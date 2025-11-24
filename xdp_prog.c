/* SPDX-License-Identifier: GPL-2.0 */
/* XDP program to track statistics for ethernet/IPv6/GRE/MPLS/Ethernet/macsec packets */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in6.h>

/* Statistics structure per MPLS label */
struct mpls_label_stats {
	__u64 packet_count;		/* Count of packets with this MPLS label */
	__u32 latest_packet_num;	/* Latest macsec packet number seen (32-bit) */
};

/* Global statistics */
struct global_stats {
	__u64 total_packets;		/* Total packets processed */
	__u64 total_matching_packets;	/* Total packets matching the encapsulation */
	__u32 packet_counter;		/* Global packet counter for macsec packets (32-bit) */
};

/* eBPF maps */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);		/* MPLS label */
	__type(value, struct mpls_label_stats);
} mpls_stats_map SEC(".maps");

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

/* IPv6 header */
struct ipv6hdr {
	__u8 version:4;
	__u8 priority:4;
	__u8 flow_lbl[3];
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	struct in6_addr saddr;
	struct in6_addr daddr;
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

/* Main XDP program */
SEC("xdp")
int xdp_macsec_stats(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	void *ptr = data;
	
	struct ethhdr *eth;
	struct ipv6hdr *ipv6;
	struct grehdr *gre;
	struct mplshdr *mpls;
#ifdef ENABLE_PW_CONTROL_WORD
	struct pw_control_word *pw_cw;
#endif
	struct ethhdr *inner_eth;
	struct macsechdr *macsec;
	
	__u32 mpls_label;
	__u32 zero = 0;
	struct mpls_label_stats *label_stats;
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
		return bpf_redirect_map(&tx_port, 0, 0);
	
	/* Check for IPv6 */
	if (eth->h_proto != bpf_htons(0x86DD))
		return bpf_redirect_map(&tx_port, 0, 0);
	
	ptr += sizeof(*eth);
	
	/* Parse IPv6 header */
	ipv6 = parse_header(ptr, data_end, sizeof(*ipv6));
	if (!ipv6)
		return bpf_redirect_map(&tx_port, 0, 0);
	
	/* Check for GRE (protocol 47) */
	if (ipv6->nexthdr != 47)
		return bpf_redirect_map(&tx_port, 0, 0);
	
	ptr += sizeof(*ipv6);
	
	/* Parse GRE header */
	gre = parse_header(ptr, data_end, sizeof(*gre));
	if (!gre)
		return bpf_redirect_map(&tx_port, 0, 0);
	
	/* Check for MPLS payload (0x8847) */
	if (gre->protocol != bpf_htons(0x8847)) /* MPLS over GRE */
		return bpf_redirect_map(&tx_port, 0, 0);
	
	ptr += sizeof(*gre);
	
	/* Parse MPLS header */
	mpls = parse_header(ptr, data_end, sizeof(*mpls));
	if (!mpls)
		return bpf_redirect_map(&tx_port, 0, 0);
	
	/* Extract MPLS label (top 20 bits) */
	mpls_label = bpf_ntohl(mpls->label) >> 12;
	
	/* Skip MPLS stack (simplified - assumes single label) */
	ptr += sizeof(*mpls);
	
#ifdef ENABLE_PW_CONTROL_WORD
	/* Parse Pseudowire Control Word (4 bytes) */
	pw_cw = parse_header(ptr, data_end, sizeof(*pw_cw));
	if (!pw_cw)
		return bpf_redirect_map(&tx_port, 0, 0);
	
	/* Skip control word */
	ptr += sizeof(*pw_cw);
#endif
	
	/* Parse inner Ethernet header */
	inner_eth = parse_header(ptr, data_end, sizeof(*inner_eth));
	if (!inner_eth)
		return bpf_redirect_map(&tx_port, 0, 0);
	
	/* Check for MacSec (EtherType 0x88E5) */
	if (inner_eth->h_proto != bpf_htons(0x88E5))
		return bpf_redirect_map(&tx_port, 0, 0);
	
	ptr += sizeof(*inner_eth);
	
	/* Parse MacSec header */
	macsec = parse_header(ptr, data_end, sizeof(*macsec));
	if (!macsec)
		return bpf_redirect_map(&tx_port, 0, 0);
	
	/* Extract packet number from MacSec header (32-bit, at offset 2)
	 * Read directly as bytes to avoid structure alignment issues
	 */
	__be32 packet_number_be;
	__builtin_memcpy(&packet_number_be, (char *)macsec + 2, sizeof(packet_number_be));
	__u32 packet_number = bpf_ntohl(packet_number_be);
	
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
	
	/* Update per-MPLS-label statistics */
	label_stats = bpf_map_lookup_elem(&mpls_stats_map, &mpls_label);
	if (!label_stats) {
		/* Initialize new label entry */
		struct mpls_label_stats new_stats = {
			.packet_count = 1,
			.latest_packet_num = packet_number
		};
		bpf_map_update_elem(&mpls_stats_map, &mpls_label, &new_stats, BPF_ANY);
	} else {
		__sync_fetch_and_add(&label_stats->packet_count, 1);
		if (packet_number > label_stats->latest_packet_num)
			label_stats->latest_packet_num = packet_number;
	}
	
	/* Redirect matching packets to AF_XDP socket */
	/* bpf_redirect_map returns XDP_REDIRECT on success */
	/* If AF_XDP socket not available, fall back to output interface */
	int ret = bpf_redirect_map(&xsks_map, 0, 0);
	if (ret != XDP_REDIRECT) {
		/* Fall back to output interface if AF_XDP socket not configured */
		return bpf_redirect_map(&tx_port, 0, 0);
	}
	return ret;
}

/* Simple XDP program for output interface - just passes packets through */
SEC("xdp")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

