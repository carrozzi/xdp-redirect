/* SPDX-License-Identifier: GPL-2.0 */
/* Common structures for XDP program and user-space program */

#ifndef __XDP_PROG_H
#define __XDP_PROG_H

#include <stdint.h>

/* Statistics structure per MACsec Secure Channel ID (SCI) */
struct sci_stats {
	uint64_t packet_count;		/* Count of packets with this SCI */
	uint64_t latest_packet_num;	/* Latest macsec packet number seen */
};

/* Global statistics */
struct global_stats {
	uint64_t total_packets;		/* Total packets processed */
	uint64_t total_matching_packets;	/* Total packets matching the encapsulation */
	uint32_t packet_counter;		/* Global packet counter for macsec packets (32-bit) */
	uint32_t _pad;			/* Padding for alignment */
	uint64_t redirect_xdp_ok;	/* Successful AF_XDP redirects */
	uint64_t redirect_devmap_ok;	/* Successful DEVMAP redirects */
	uint64_t redirect_devmap_fail;	/* Failed DEVMAP redirects (fallback to pass) */
};

#endif /* __XDP_PROG_H */

