/* SPDX-License-Identifier: GPL-2.0 */
/* User-space program to read and display XDP statistics */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/resource.h>
#include <inttypes.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <linux/if_link.h>
#include <stdbool.h>
#include <net/if.h>

#include "../common/common_defines.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_params.h"
#include "xdp_prog.h"

static volatile bool exiting = false;

static void sig_int(int signo)
{
	exiting = true;
}

static int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
	struct bpf_map *map;
	int map_fd = -1;

	map = bpf_object__find_map_by_name(bpf_obj, mapname);
	if (!map) {
		fprintf(stderr, "ERR: cannot find map by name: %s\n", mapname);
		goto out;
	}

	map_fd = bpf_map__fd(map);
out:
	return map_fd;
}

static void print_stats(struct bpf_object *bpf_obj)
{
	struct global_stats global_stats;
	struct mpls_label_stats label_stats;
	__u32 zero = 0;
	__u32 mpls_label = 0;
	__u32 next_key;
	int err;
	int map_fd_global, map_fd_mpls;
	
	map_fd_global = find_map_fd(bpf_obj, "global_stats_map");
	map_fd_mpls = find_map_fd(bpf_obj, "mpls_stats_map");
	
	if (map_fd_global < 0 || map_fd_mpls < 0) {
		fprintf(stderr, "ERR: failed to find maps\n");
		return;
	}
	
	/* Get global statistics */
	err = bpf_map_lookup_elem(map_fd_global, &zero, &global_stats);
	if (err) {
		if (errno != ENOENT) {
			fprintf(stderr, "Failed to lookup global stats: %s\n", strerror(errno));
		}
		/* If map is empty, initialize with zeros */
		global_stats.total_packets = 0;
		global_stats.total_matching_packets = 0;
		global_stats.packet_counter = 0;
	}
	
	printf("\n=== Global Statistics ===\n");
	printf("Total packets: %" PRIu64 "\n", global_stats.total_packets);
	printf("Matching packets: %" PRIu64 "\n", global_stats.total_matching_packets);
	printf("Non-matching packets: %" PRIu64 "\n", 
	       global_stats.total_packets - global_stats.total_matching_packets);
	printf("Latest packet number: %" PRIu32 "\n", global_stats.packet_counter);
	
	/* Iterate through all MPLS labels */
	printf("\n=== Per-MPLS-Label Statistics ===\n");
	printf("%-15s %-20s %-25s\n", "MPLS Label", "Packet Count", "Latest Packet Number");
	printf("%-15s %-20s %-25s\n", "-----------", "------------", "---------------------");
	
	/* Start iteration from NULL (first key) */
	next_key = 0;
	while (bpf_map_get_next_key(map_fd_mpls, 
				     mpls_label ? &mpls_label : NULL, 
				     &next_key) == 0) {
		mpls_label = next_key;
		
		err = bpf_map_lookup_elem(map_fd_mpls, &mpls_label, &label_stats);
		if (err) {
			fprintf(stderr, "Failed to lookup MPLS label %u: %s\n",
				mpls_label, strerror(errno));
			continue;
		}
		
		printf("%-15u %-20" PRIu64 " %-25" PRIu32 "\n",
		       mpls_label,
		       label_stats.packet_count,
		       label_stats.latest_packet_num);
	}
	
	printf("\n");
	fflush(stdout);
}

int main(int argc, char **argv)
{
	struct xdp_program *program = NULL;
	struct xdp_program *output_program = NULL;
	struct bpf_object *bpf_obj;
	struct config cfg = {
		.ifindex = -1,
		.do_unload = false,
		.attach_mode = XDP_MODE_NATIVE,
	};
	enum xdp_attach_mode output_attach_mode = XDP_MODE_NATIVE;
	int err = 0;
	int interval = 2; /* Default 2 seconds */
	char errmsg[1024];
	
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <input_ifname> <output_ifname> [interval_seconds]\n", argv[0]);
		fprintf(stderr, "Example: %s eth0 eth1 2\n", argv[0]);
		return EXIT_FAIL_OPTION;
	}
	
	if (argc >= 4) {
		interval = atoi(argv[3]);
		if (interval <= 0) {
			fprintf(stderr, "Invalid interval: %s\n", argv[3]);
			return EXIT_FAIL_OPTION;
		}
	}
	
	/* Set input interface name */
	strncpy(cfg.ifname_buf, argv[1], IF_NAMESIZE - 1);
	cfg.ifname = cfg.ifname_buf;
	cfg.ifindex = if_nametoindex(cfg.ifname);
	if (cfg.ifindex == 0) {
		fprintf(stderr, "Failed to get interface index for %s: %s\n",
			cfg.ifname, strerror(errno));
		return EXIT_FAIL_OPTION;
	}
	
	/* Get output interface index */
	unsigned int output_ifindex = if_nametoindex(argv[2]);
	if (output_ifindex == 0) {
		fprintf(stderr, "Failed to get interface index for output interface %s: %s\n",
			argv[2], strerror(errno));
		return EXIT_FAIL_OPTION;
	}
	
	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, "xdp_prog.o", sizeof(cfg.filename));
	strncpy(cfg.progname, "xdp_macsec_stats", sizeof(cfg.progname));
	
	/* Load and attach BPF program */
	program = load_bpf_and_xdp_attach(&cfg);
	if (!program) {
		fprintf(stderr, "ERR: Failed to load and attach BPF program\n");
		return EXIT_FAIL_BPF;
	}
	
	/* Get bpf_object from program */
	bpf_obj = xdp_program__bpf_obj(program);
	if (!bpf_obj) {
		fprintf(stderr, "ERR: Failed to get bpf_object\n");
		err = EXIT_FAIL_BPF;
		goto cleanup;
	}
	
	/* Attach a simple XDP_PASS program to output interface (required for redirect) */
	/* Load it directly so we can handle errors gracefully */
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts2);
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts2, 0);
	
	xdp_opts2.open_filename = "xdp_prog.o";
	xdp_opts2.prog_name = "xdp_pass_func";
	xdp_opts2.opts = &opts2;
	
	output_program = xdp_program__create(&xdp_opts2);
	err = libxdp_get_error(output_program);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERR: Failed to load XDP program 'xdp_pass_func': %s\n", errmsg);
		err = EXIT_FAIL_BPF;
		goto cleanup;
	}
	
	/* Try native mode first, fall back to SKB mode if not supported */
	err = xdp_program__attach(output_program, output_ifindex, XDP_MODE_NATIVE, 0);
	if (err) {
		/* If native mode fails, try SKB mode */
		output_attach_mode = XDP_MODE_SKB;
		err = xdp_program__attach(output_program, output_ifindex, output_attach_mode, 0);
		if (err) {
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "ERR: Failed to attach XDP program to output interface %s "
				"(tried both native and SKB modes): %s\n", argv[2], errmsg);
			xdp_program__close(output_program);
			output_program = NULL;
			err = EXIT_FAIL_BPF;
			goto cleanup;
		}
		printf("Attached XDP program to output interface %s in SKB mode\n", argv[2]);
	} else {
		printf("Attached XDP program to output interface %s in native mode\n", argv[2]);
	}
	
	/* Initialize global stats map to ensure it exists */
	int map_fd_global = find_map_fd(bpf_obj, "global_stats_map");
	if (map_fd_global >= 0) {
		__u32 zero = 0;
		struct global_stats init_stats = {0};
		/* Try to initialize - ignore error if already exists */
		bpf_map_update_elem(map_fd_global, &zero, &init_stats, BPF_NOEXIST);
	}
	
	/* Configure redirect map with output interface */
	int map_fd_tx = find_map_fd(bpf_obj, "tx_port");
	if (map_fd_tx < 0) {
		fprintf(stderr, "ERR: Failed to find tx_port map\n");
		err = EXIT_FAIL_BPF;
		goto cleanup;
	}
	
	int key = 0;
	err = bpf_map_update_elem(map_fd_tx, &key, &output_ifindex, BPF_ANY);
	if (err) {
		fprintf(stderr, "ERR: Failed to update tx_port map: %s\n", strerror(errno));
		err = EXIT_FAIL_BPF;
		goto cleanup;
	}
	
	/* Verify the map was set correctly */
	unsigned int verify_ifindex = 0;
	err = bpf_map_lookup_elem(map_fd_tx, &key, &verify_ifindex);
	if (err || verify_ifindex != output_ifindex) {
		fprintf(stderr, "ERR: Failed to verify tx_port map (got ifindex %u, expected %u)\n",
			verify_ifindex, output_ifindex);
		err = EXIT_FAIL_BPF;
		goto cleanup;
	}
	
	printf("Configured redirect: %s (ifindex %d) -> %s (ifindex %u)\n",
	       cfg.ifname, cfg.ifindex, argv[2], output_ifindex);
	printf("Verified tx_port map: key=0 -> ifindex=%u\n", verify_ifindex);
	printf("XDP program attached to input interface %s (ifindex %d)\n", 
	       cfg.ifname, cfg.ifindex);
	
	printf("\nNOTE: Make sure there is traffic on %s for counters to increment.\n", cfg.ifname);
	printf("      You can test with: ping6 or send test packets to the interface.\n");
	printf("Press Ctrl+C to stop\n\n");
	
	/* Set up signal handler */
	signal(SIGINT, sig_int);
	signal(SIGTERM, sig_int);
	
	/* Main loop - print statistics periodically */
	while (!exiting) {
		sleep(interval);
		if (!exiting) {
			print_stats(bpf_obj);
		}
	}
	
	printf("\nDetaching XDP program...\n");
	
cleanup:
	if (output_program) {
		int detach_err = xdp_program__detach(output_program, output_ifindex, output_attach_mode, 0);
		if (detach_err) {
			libxdp_strerror(detach_err, errmsg, sizeof(errmsg));
			fprintf(stderr, "Error detaching output XDP program: %s\n", errmsg);
		}
		xdp_program__close(output_program);
	}
	if (program) {
		int detach_err = xdp_program__detach(program, cfg.ifindex, cfg.attach_mode, 0);
		if (detach_err) {
			libxdp_strerror(detach_err, errmsg, sizeof(errmsg));
			fprintf(stderr, "Error detaching input XDP program: %s\n", errmsg);
		}
		xdp_program__close(program);
	}
	
	return err == 0 ? EXIT_OK : EXIT_FAIL;
}
