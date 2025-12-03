/* SPDX-License-Identifier: GPL-2.0 */
/* XDP program to track statistics for ethernet/IPv4/GRE/MPLS/Ethernet/macsec packets */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Statistics structure per MACsec Secure Channel ID */
struct sci_stats {
	__u64 packet_count;		/* Count of packets with this SCI */
	__u64 latest_packet_num;	/* Latest macsec packet number seen */
};

/* Global statistics */
struct global_stats {
	__u64 total_packets;		/* Total packets processed */
	__u64 total_matching_packets;	/* Total packets matching the encapsulation */
	__u32 packet_counter;		/* Global packet counter for macsec packets (32-bit) */
	__u32 _pad;			/* Padding for alignment */
	__u64 redirect_xdp_ok;		/* Successful AF_XDP redirects */
	__u64 redirect_devmap_ok;	/* Successful DEVMAP redirects */
	__u64 redirect_devmap_fail;	/* Failed DEVMAP redirects (fallback to pass) */
};

/* eBPF maps */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);		/* MACsec Secure Channel ID (SCI) */
	__type(value, struct sci_stats);
} sci_stats_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct global_stats);
} global_stats_map SEC(".maps");

/* Map for redirecting packets to output interface */
struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} tx_port SEC(".maps");

/* Map for redirecting matching packets to AF_XDP socket */
struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} xsks_map SEC(".maps");

/* Ethernet header */
struct ethhdr {
	__u8 h_dest[6];
	__u8 h_source[6];
	__be16 h_proto;
};

/* IPv4 header */
struct iphdr {
	__u8 ihl:4;
	__u8 version:4;
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__be16 check;
	__be32 saddr;
	__be32 daddr;
};

/* GRE header */
struct grehdr {
	__be16 flags;
	__be16 protocol;
};

/* MPLS header */
struct mplshdr {
	__be32 label;
};

/* Pseudowire Control Word (optional, 4 bytes) */
struct pw_control_word {
	__be32 flags;
};

/* MacSec header (simplified - actual header is more complex)
 * TCI (Tag Control Information) + AN (Association Number) = 1 byte
 * SL (Short Length) = 1 byte  
 * Packet Number = 4 bytes (32-bit, but we'll read it as be32)
 * SCI (Secure Channel Identifier) = 8 bytes
 */
struct macsechdr {
	__u8 tci_an;
	__u8 sl;
	__be32 packet_number;  /* 32-bit packet number */
	__u8 secure_channel_id[8];
};

/* Helper function to check if we have enough bytes */
static __always_inline void *parse_header(void *data, void *data_end, __u32 size)
{
	if (data + size > data_end)
		return NULL;
	return data;
}

/* Helper function for DEVMAP redirect with stats tracking */
static __always_inline int do_redirect_devmap(void)
{
	__u32 zero = 0;
	struct global_stats *stats = bpf_map_lookup_elem(&global_stats_map, &zero);
	
	int ret = bpf_redirect_map(&tx_port, 0, 0);
	if (ret == XDP_REDIRECT) {
		if (stats)
			__sync_fetch_and_add(&stats->redirect_devmap_ok, 1);
		return ret;
	}
	/* Redirect failed - fall back to XDP_PASS */
	if (stats)
		__sync_fetch_and_add(&stats->redirect_devmap_fail, 1);
	return XDP_PASS;
}

/* Main XDP program */
SEC("xdp")
int xdp_macsec_stats(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	void *ptr = data;
	
	struct ethhdr *eth;
	struct iphdr *ipv4;
	struct grehdr *gre;
	struct mplshdr *mpls;
#ifdef ENABLE_PW_CONTROL_WORD
	struct pw_control_word *pw_cw;
#endif
	struct ethhdr *inner_eth;
	struct macsechdr *macsec;
	
	__u64 sci;
	__u32 zero = 0;
	struct sci_stats *sci_stats;
	struct global_stats *global_stats;
	
	/* Increment total packet counter for all packets - do this FIRST */
	/* Always try to get existing entry first */
	global_stats = bpf_map_lookup_elem(&global_stats_map, &zero);
	if (global_stats) {
		/* Entry exists, atomically increment */
		__sync_fetch_and_add(&global_stats->total_packets, 1);
	} else {
		/* Entry doesn't exist, create it with initial value */
		struct global_stats new_global_stats = {
			.total_packets = 1,
			.total_matching_packets = 0,
			.packet_counter = 0
		};
		/* Use BPF_NOEXIST to ensure we're creating, not overwriting */
		/* If it fails, try BPF_ANY (race condition - another CPU created it) */
		if (bpf_map_update_elem(&global_stats_map, &zero, &new_global_stats, BPF_NOEXIST) != 0) {
			/* Entry was created by another CPU, try to increment it */
			global_stats = bpf_map_lookup_elem(&global_stats_map, &zero);
			if (global_stats) {
				__sync_fetch_and_add(&global_stats->total_packets, 1);
			}
		}
	}
	
	/* Parse outer Ethernet header */
	eth = parse_header(ptr, data_end, sizeof(*eth));
	if (!eth)
		return do_redirect_devmap();
	
	/* Check for IPv4 */
	if (eth->h_proto != bpf_htons(0x0800))
		return do_redirect_devmap();
	
	ptr += sizeof(*eth);
	
	/* Parse IPv4 header */
	ipv4 = parse_header(ptr, data_end, sizeof(*ipv4));
	if (!ipv4)
		return do_redirect_devmap();
	
	/* Check for GRE (protocol 47) */
	if (ipv4->protocol != 47)
		return do_redirect_devmap();
	
	ptr += sizeof(*ipv4);
	
	/* Parse GRE header */
	gre = parse_header(ptr, data_end, sizeof(*gre));
	if (!gre)
		return do_redirect_devmap();
	
	/* Check for MPLS payload (0x8847) */
	if (gre->protocol != bpf_htons(0x8847)) /* MPLS over GRE */
		return do_redirect_devmap();
	
	ptr += sizeof(*gre);
	
	/* Parse MPLS header */
	mpls = parse_header(ptr, data_end, sizeof(*mpls));
	if (!mpls)
		return do_redirect_devmap();
	
	/* Skip MPLS stack (simplified - assumes single label) */
	ptr += sizeof(*mpls);
	
#ifdef ENABLE_PW_CONTROL_WORD
	/* Parse Pseudowire Control Word (4 bytes) */
	pw_cw = parse_header(ptr, data_end, sizeof(*pw_cw));
	if (!pw_cw)
		return do_redirect_devmap();
	
	/* Skip control word */
	ptr += sizeof(*pw_cw);
#endif
	
	/* Parse inner Ethernet header */
	inner_eth = parse_header(ptr, data_end, sizeof(*inner_eth));
	if (!inner_eth)
		return do_redirect_devmap();
	
	/* Check for MacSec (EtherType 0x88E5) */
	if (inner_eth->h_proto != bpf_htons(0x88E5))
		return do_redirect_devmap();
	
	ptr += sizeof(*inner_eth);
	
	/* Parse MacSec header */
	macsec = parse_header(ptr, data_end, sizeof(*macsec));
	if (!macsec)
		return do_redirect_devmap();
	
	/* Extract packet number from MacSec header (32-bit, at offset 2)
	 * Read directly as bytes to avoid structure alignment issues
	 */
	__be32 packet_number_be;
	__builtin_memcpy(&packet_number_be, (char *)macsec + 2, sizeof(packet_number_be));
	__u32 packet_number = bpf_ntohl(packet_number_be);
	
	/* Extract Secure Channel ID (SCI) from MacSec header (64-bit, at offset 6) */
	__builtin_memcpy(&sci, (char *)macsec + 6, sizeof(sci));
	
	/* Update matching packet statistics */
	global_stats = bpf_map_lookup_elem(&global_stats_map, &zero);
	if (global_stats) {
		__sync_fetch_and_add(&global_stats->total_matching_packets, 1);
		if (packet_number > global_stats->packet_counter)
			global_stats->packet_counter = packet_number;
	} else {
		/* This shouldn't happen since we initialize above, but handle it */
		struct global_stats new_global_stats = {
			.total_packets = 1,
			.total_matching_packets = 1,
			.packet_counter = packet_number
		};
		bpf_map_update_elem(&global_stats_map, &zero, &new_global_stats, BPF_ANY);
	}
	
	/* Update per-SCI statistics */
	sci_stats = bpf_map_lookup_elem(&sci_stats_map, &sci);
	if (!sci_stats) {
		/* Initialize new SCI entry */
		struct sci_stats new_stats = {
			.packet_count = 1,
			.latest_packet_num = packet_number
		};
		bpf_map_update_elem(&sci_stats_map, &sci, &new_stats, BPF_ANY);
	} else {
		__sync_fetch_and_add(&sci_stats->packet_count, 1);
		/* Store the latest packet number (direct assignment for debugging) */
		sci_stats->latest_packet_num = packet_number;
	}
	
	/* Redirect matching packets to AF_XDP socket */
	/* bpf_redirect_map returns XDP_REDIRECT on success */
	/* If AF_XDP socket not available, fall back to output interface */
	int ret = bpf_redirect_map(&xsks_map, 0, 0);
	if (ret == XDP_REDIRECT) {
		if (global_stats)
			__sync_fetch_and_add(&global_stats->redirect_xdp_ok, 1);
		return ret;
	}
	/* Fall back to output interface if AF_XDP socket not configured */
	return do_redirect_devmap();
}

/* Simple XDP program for output interface - just passes packets through */
SEC("xdp")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

