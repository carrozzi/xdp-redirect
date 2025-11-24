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
#include <xdp/xsk.h>
#include <linux/if_link.h>
#include <stdbool.h>
#include <net/if.h>
#include <pthread.h>
#include <poll.h>
#include <sys/mman.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "../common/common_defines.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_params.h"
#include "xdp_prog.h"

static volatile bool exiting = false;

/* AF_XDP socket configuration */
#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

struct xsk_umem_info {
	struct xsk_ring_prod fq;
	struct xsk_ring_cons cq;
	struct xsk_umem *umem;
	void *buffer;
};

struct xsk_socket_info {
	struct xsk_ring_cons rx;
	struct xsk_ring_prod tx;
	struct xsk_umem_info *umem;
	struct xsk_socket *xsk;
	uint64_t umem_frame_addr[NUM_FRAMES];
	uint32_t umem_frame_free;
};

static struct xsk_socket_info *xsk_info = NULL;
static pthread_t xsk_thread;
static char *output_ifname = NULL;

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

/* AF_XDP helper functions */
static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
	if (xsk->umem_frame_free == 0)
		return INVALID_UMEM_FRAME;

	return xsk->umem_frame_addr[--xsk->umem_frame_free];
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t addr)
{
	xsk->umem_frame_addr[xsk->umem_frame_free++] = addr;
}

static int send_packet_to_interface(const void *data, size_t len, const char *ifname)
{
	struct sockaddr_ll saddr;
	struct ifreq ifr;
	int sock;
	int ret;

	/* Create raw socket */
	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0) {
		fprintf(stderr, "ERR: Failed to create raw socket: %s\n", strerror(errno));
		return -1;
	}

	/* Get interface index */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	ret = ioctl(sock, SIOCGIFINDEX, &ifr);
	if (ret < 0) {
		fprintf(stderr, "ERR: Failed to get interface index for %s: %s\n",
			ifname, strerror(errno));
		close(sock);
		return -1;
	}

	/* Setup destination address */
	memset(&saddr, 0, sizeof(saddr));
	saddr.sll_family = AF_PACKET;
	saddr.sll_protocol = htons(ETH_P_ALL);
	saddr.sll_ifindex = ifr.ifr_ifindex;
	saddr.sll_halen = ETH_ALEN;

	/* Send packet */
	ret = sendto(sock, data, len, 0, (struct sockaddr *)&saddr, sizeof(saddr));
	close(sock);

	if (ret < 0) {
		fprintf(stderr, "ERR: Failed to send packet: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

static void *xsk_packet_reader(void *arg)
{
	struct xsk_socket_info *xsk = (struct xsk_socket_info *)arg;
	struct pollfd fds[1];
	unsigned int rcvd;
	uint32_t idx_rx = 0, idx_fq = 0;
	int ret;

	memset(fds, 0, sizeof(fds));
	fds[0].fd = xsk_socket__fd(xsk->xsk);
	fds[0].events = POLLIN;

	while (!exiting) {
		ret = poll(fds, 1, 100); /* 100ms timeout */
		if (ret <= 0)
			continue;

		/* Receive packets */
		rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
		if (!rcvd) {
			/* No packets, refill fill queue if needed */
			uint32_t free_frames = xsk->umem_frame_free;
			if (free_frames > 0) {
				ret = xsk_ring_prod__reserve(&xsk->umem->fq, free_frames, &idx_fq);
				if (ret == free_frames) {
					for (uint32_t i = 0; i < free_frames; i++)
						*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
							xsk_alloc_umem_frame(xsk);
					xsk_ring_prod__submit(&xsk->umem->fq, free_frames);
				}
			}
			continue;
		}

		/* Process received packets */
		for (unsigned int i = 0; i < rcvd; i++) {
			uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
			uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;
			uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

			/* Send packet to output interface */
			if (output_ifname) {
				if (send_packet_to_interface(pkt, len, output_ifname) == 0) {
					/* Packet sent successfully */
				} else {
					fprintf(stderr, "WARNING: Failed to send packet of %u bytes\n", len);
				}
			}

			/* Free the frame back to the umem */
			xsk_free_umem_frame(xsk, addr);
		}

		xsk_ring_cons__release(&xsk->rx, rcvd);

		/* Refill fill queue */
		uint32_t free_frames = xsk->umem_frame_free;
		if (free_frames > 0) {
			ret = xsk_ring_prod__reserve(&xsk->umem->fq, free_frames, &idx_fq);
			if (ret == free_frames) {
				for (uint32_t i = 0; i < free_frames; i++)
					*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
						xsk_alloc_umem_frame(xsk);
				xsk_ring_prod__submit(&xsk->umem->fq, free_frames);
			}
		}
	}

	return NULL;
}

static int setup_af_xdp_socket(const char *ifname, int ifindex, struct bpf_object *bpf_obj, const char *out_ifname)
{
	struct xsk_umem_info *umem;
	struct xsk_umem_config umem_cfg = {
		.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.frame_size = FRAME_SIZE,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
		.flags = 0,
	};
	struct xsk_socket_config xsk_cfg = {
		.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
		.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
		.libbpf_flags = 0,
		.xdp_flags = 0,
		.bind_flags = XDP_USE_NEED_WAKEUP,
	};
	void *umem_buffer;
	int ret;
	int map_fd_xsks;

	/* Allocate umem buffer */
	umem_buffer = mmap(NULL, NUM_FRAMES * FRAME_SIZE, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (umem_buffer == MAP_FAILED) {
		fprintf(stderr, "ERR: Failed to allocate umem buffer: %s\n", strerror(errno));
		return -1;
	}

	/* Create umem */
	umem = calloc(1, sizeof(*umem));
	if (!umem) {
		munmap(umem_buffer, NUM_FRAMES * FRAME_SIZE);
		return -1;
	}

	ret = xsk_umem__create(&umem->umem, umem_buffer, NUM_FRAMES * FRAME_SIZE,
			       &umem->fq, &umem->cq, &umem_cfg);
	if (ret) {
		fprintf(stderr, "ERR: Failed to create umem: %s\n", strerror(-ret));
		free(umem);
		munmap(umem_buffer, NUM_FRAMES * FRAME_SIZE);
		return -1;
	}
	umem->buffer = umem_buffer;

	/* Create socket info */
	xsk_info = calloc(1, sizeof(*xsk_info));
	if (!xsk_info) {
		xsk_umem__delete(umem->umem);
		free(umem);
		munmap(umem_buffer, NUM_FRAMES * FRAME_SIZE);
		return -1;
	}
	xsk_info->umem = umem;

	/* Initialize umem frame addresses */
	for (int i = 0; i < NUM_FRAMES; i++)
		xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;
	xsk_info->umem_frame_free = NUM_FRAMES;

	/* Create AF_XDP socket */
	ret = xsk_socket__create(&xsk_info->xsk, ifname, 0, umem->umem,
				 &xsk_info->rx, &xsk_info->tx, &xsk_cfg);
	if (ret) {
		fprintf(stderr, "ERR: Failed to create AF_XDP socket: %s\n", strerror(-ret));
		xsk_umem__delete(umem->umem);
		free(xsk_info);
		free(umem);
		munmap(umem_buffer, NUM_FRAMES * FRAME_SIZE);
		return -1;
	}

	/* Get xsks_map file descriptor */
	map_fd_xsks = find_map_fd(bpf_obj, "xsks_map");
	if (map_fd_xsks < 0) {
		fprintf(stderr, "ERR: Failed to find xsks_map\n");
		xsk_socket__delete(xsk_info->xsk);
		xsk_umem__delete(umem->umem);
		free(xsk_info);
		free(umem);
		munmap(umem_buffer, NUM_FRAMES * FRAME_SIZE);
		return -1;
	}

	/* Add socket to xsks_map */
	ret = xsk_socket__update_xskmap(xsk_info->xsk, map_fd_xsks);
	if (ret) {
		fprintf(stderr, "ERR: Failed to update xsks_map: %s\n", strerror(-ret));
		xsk_socket__delete(xsk_info->xsk);
		xsk_umem__delete(umem->umem);
		free(xsk_info);
		free(umem);
		munmap(umem_buffer, NUM_FRAMES * FRAME_SIZE);
		return -1;
	}

	/* Fill the fill queue */
	uint32_t idx_fq;
	ret = xsk_ring_prod__reserve(&umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS, &idx_fq);
	if (ret == XSK_RING_PROD__DEFAULT_NUM_DESCS) {
		for (int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
			*xsk_ring_prod__fill_addr(&umem->fq, idx_fq++) =
				xsk_alloc_umem_frame(xsk_info);
		xsk_ring_prod__submit(&umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS);
	}

	printf("AF_XDP socket created and added to xsks_map\n");

	return 0;
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
	
	/* Setup AF_XDP socket for matching packets */
	output_ifname = argv[2]; /* Store output interface name for packet reader */
	if (setup_af_xdp_socket(cfg.ifname, cfg.ifindex, bpf_obj, argv[2]) < 0) {
		fprintf(stderr, "WARNING: Failed to setup AF_XDP socket, matching packets will go to output interface\n");
	} else {
		/* Start packet reader thread */
		if (pthread_create(&xsk_thread, NULL, xsk_packet_reader, xsk_info) != 0) {
			fprintf(stderr, "ERR: Failed to create AF_XDP reader thread: %s\n", strerror(errno));
			/* Cleanup will handle xsk_info */
		} else {
			printf("AF_XDP packet reader thread started\n");
		}
	}
	
	printf("\nNOTE: Make sure there is traffic on %s for counters to increment.\n", cfg.ifname);
	printf("      Matching packets will be sent to %s via AF_XDP socket.\n", argv[2]);
	printf("      Non-matching packets will be redirected to %s.\n", argv[2]);
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
	/* Wait for AF_XDP thread to finish */
	if (xsk_info && xsk_info->xsk) {
		/* Only join if thread was created (socket exists) */
		pthread_join(xsk_thread, NULL);
		if (xsk_info->xsk) {
			xsk_socket__delete(xsk_info->xsk);
		}
		if (xsk_info->umem && xsk_info->umem->umem) {
			xsk_umem__delete(xsk_info->umem->umem);
			if (xsk_info->umem->buffer) {
				munmap(xsk_info->umem->buffer, NUM_FRAMES * FRAME_SIZE);
			}
			free(xsk_info->umem);
		}
		free(xsk_info);
	}
	
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
