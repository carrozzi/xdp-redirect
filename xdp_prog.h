/* SPDX-License-Identifier: GPL-2.0 */
/* Common structures for XDP program and user-space program */

#ifndef __XDP_PROG_H
#define __XDP_PROG_H

#include <stdint.h>

/* Statistics structure per MPLS label */
struct mpls_label_stats {
	uint64_t packet_count;		/* Count of packets with this MPLS label */
	uint32_t latest_packet_num;	/* Latest macsec packet number seen (32-bit) */
};

/* Global statistics */
struct global_stats {
	uint64_t total_packets;		/* Total packets processed */
	uint64_t total_matching_packets;	/* Total packets matching the encapsulation */
	uint32_t packet_counter;		/* Global packet counter for macsec packets (32-bit) */
};

#endif /* __XDP_PROG_H */

