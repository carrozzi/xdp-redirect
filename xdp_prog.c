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

/* Per-interface statistics */
struct if_stats {
	__u64 rx_packets;		/* Packets received on this interface */
	__u64 rx_matching;		/* Matching packets received */
	__u64 tx_redirect_ok;		/* Successful redirects to other interface */
	__u64 tx_redirect_fail;		/* Failed redirects */
	__u64 tx_xdp_ok;		/* Successful AF_XDP redirects */
};

/* eBPF maps */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);		/* MACsec Secure Channel ID (SCI) */
	__type(value, struct sci_stats);
} sci_stats_map SEC(".maps");

/* Use PERCPU maps to avoid atomic operations and cache bouncing */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct global_stats);
} global_stats_map SEC(".maps");

/* Per-interface statistics map (key: ifindex) - PERCPU for performance */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, struct if_stats);
} if_stats_map SEC(".maps");

/* Map for redirecting packets to output interface (bidirectional)
 * Key: ingress ifindex, Value: egress ifindex
 */
struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 64);
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

/* Helper function to get or create per-interface stats */
static __always_inline struct if_stats *get_if_stats(__u32 ifindex)
{
	struct if_stats *stats = bpf_map_lookup_elem(&if_stats_map, &ifindex);
	if (!stats) {
		struct if_stats new_stats = {};
		bpf_map_update_elem(&if_stats_map, &ifindex, &new_stats, BPF_NOEXIST);
		stats = bpf_map_lookup_elem(&if_stats_map, &ifindex);
	}
	return stats;
}

/* Helper function for DEVMAP redirect with stats tracking (bidirectional) */
static __always_inline int do_redirect_devmap(struct xdp_md *ctx)
{
	__u32 zero = 0;
	__u32 ingress_ifindex = ctx->ingress_ifindex;
	struct global_stats *gstats = bpf_map_lookup_elem(&global_stats_map, &zero);
	struct if_stats *ifstats = get_if_stats(ingress_ifindex);
	
	/* Use ingress_ifindex as key to find the egress interface */
	int ret = bpf_redirect_map(&tx_port, ingress_ifindex, 0);
	if (ret == XDP_REDIRECT) {
		if (gstats)
			gstats->redirect_devmap_ok++;  /* No atomic needed for PERCPU */
		if (ifstats)
			ifstats->tx_redirect_ok++;
		return ret;
	}
	/* Redirect failed - fall back to XDP_PASS */
	if (gstats)
		gstats->redirect_devmap_fail++;
	if (ifstats)
		ifstats->tx_redirect_fail++;
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
	__u32 ingress_ifindex = ctx->ingress_ifindex;
	struct sci_stats *sci_stats;
	struct global_stats *global_stats;
	struct if_stats *if_stats;
	
	/* Get/create per-interface stats and increment rx counter */
	if_stats = get_if_stats(ingress_ifindex);
	if (if_stats)
		if_stats->rx_packets++;  /* No atomic needed for PERCPU */
	
	/* Increment total packet counter - PERCPU_ARRAY always has entry at key 0 */
	global_stats = bpf_map_lookup_elem(&global_stats_map, &zero);
	if (global_stats)
		global_stats->total_packets++;  /* No atomic needed for PERCPU */
	
	/* Parse outer Ethernet header */
	eth = parse_header(ptr, data_end, sizeof(*eth));
	if (!eth)
		return do_redirect_devmap(ctx);
	
	/* Check for IPv4 */
	if (eth->h_proto != bpf_htons(0x0800))
		return do_redirect_devmap(ctx);
	
	ptr += sizeof(*eth);
	
	/* Parse IPv4 header */
	ipv4 = parse_header(ptr, data_end, sizeof(*ipv4));
	if (!ipv4)
		return do_redirect_devmap(ctx);
	
	/* Check for GRE (protocol 47) */
	if (ipv4->protocol != 47)
		return do_redirect_devmap(ctx);
	
	ptr += sizeof(*ipv4);
	
	/* Parse GRE header */
	gre = parse_header(ptr, data_end, sizeof(*gre));
	if (!gre)
		return do_redirect_devmap(ctx);
	
	/* Check for MPLS payload (0x8847) */
	if (gre->protocol != bpf_htons(0x8847)) /* MPLS over GRE */
		return do_redirect_devmap(ctx);
	
	ptr += sizeof(*gre);
	
	/* Parse MPLS header */
	mpls = parse_header(ptr, data_end, sizeof(*mpls));
	if (!mpls)
		return do_redirect_devmap(ctx);
	
	/* Skip MPLS stack (simplified - assumes single label) */
	ptr += sizeof(*mpls);
	
#ifdef ENABLE_PW_CONTROL_WORD
	/* Parse Pseudowire Control Word (4 bytes) */
	pw_cw = parse_header(ptr, data_end, sizeof(*pw_cw));
	if (!pw_cw)
		return do_redirect_devmap(ctx);
	
	/* Skip control word */
	ptr += sizeof(*pw_cw);
#endif
	
	/* Parse inner Ethernet header */
	inner_eth = parse_header(ptr, data_end, sizeof(*inner_eth));
	if (!inner_eth)
		return do_redirect_devmap(ctx);
	
	/* Check for MacSec (EtherType 0x88E5) */
	if (inner_eth->h_proto != bpf_htons(0x88E5))
		return do_redirect_devmap(ctx);
	
	ptr += sizeof(*inner_eth);
	
	/* Parse MacSec header */
	macsec = parse_header(ptr, data_end, sizeof(*macsec));
	if (!macsec)
		return do_redirect_devmap(ctx);
	
	/* Extract packet number from MacSec header (32-bit, at offset 2)
	 * Read directly as bytes to avoid structure alignment issues
	 */
	__be32 packet_number_be;
	__builtin_memcpy(&packet_number_be, (char *)macsec + 2, sizeof(packet_number_be));
	__u32 packet_number = bpf_ntohl(packet_number_be);
	
	/* Extract Secure Channel ID (SCI) from MacSec header (64-bit, at offset 6) */
	__builtin_memcpy(&sci, (char *)macsec + 6, sizeof(sci));
	
	/* Update matching packet statistics - PERCPU, no atomics needed */
	global_stats = bpf_map_lookup_elem(&global_stats_map, &zero);
	if (global_stats) {
		global_stats->total_matching_packets++;
		if (packet_number > global_stats->packet_counter)
			global_stats->packet_counter = packet_number;
	}
	
	/* Update per-interface matching packet count */
	if (if_stats)
		if_stats->rx_matching++;
	
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
	int ret = bpf_redirect_map(&xsks_map, ctx->rx_queue_index, 0);
	if (ret == XDP_REDIRECT) {
		if (global_stats)
			global_stats->redirect_xdp_ok++;
		if (if_stats)
			if_stats->tx_xdp_ok++;
		return ret;
	}
	/* Fall back to output interface if AF_XDP socket not configured */
	return do_redirect_devmap(ctx);
}

/* Simple XDP program for output interface - just passes packets through */
SEC("xdp")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

