/* SPDX-License-Identifier: GPL-2.0 */
/* User-space program to load XDP program and display statistics */
/* Uses libbpf directly (no libxdp dispatcher) to avoid duplicate map instances */

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
#include <xdp/xsk.h>

#include "xdp_prog.h"

/* Exit codes */
#define EXIT_OK          0
#define EXIT_FAIL        1
#define EXIT_FAIL_OPTION 2
#define EXIT_FAIL_BPF    3

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
static int output_raw_sock = -1;
static struct sockaddr_ll output_saddr;

/* Global state for cleanup */
static struct bpf_object *bpf_obj = NULL;
static int input_ifindex = -1;
static int output_ifindex = -1;
static __u32 input_xdp_flags = 0;
static __u32 output_xdp_flags = 0;
static int output_prog_fd = -1;

static void sig_int(int signo)
{
	exiting = true;
}

static int find_map_fd(struct bpf_object *obj, const char *mapname)
{
	struct bpf_map *map;
	int map_fd = -1;

	map = bpf_object__find_map_by_name(obj, mapname);
	if (!map) {
		fprintf(stderr, "ERR: cannot find map by name: %s\n", mapname);
		goto out;
	}

	map_fd = bpf_map__fd(map);
out:
	return map_fd;
}

static void print_stats(struct bpf_object *obj)
{
	struct global_stats global_stats;
	struct sci_stats sci_stats_entry;
	__u32 zero = 0;
	__u64 sci = 0;
	__u64 next_key;
	int err;
	int map_fd_global, map_fd_sci;
	
	map_fd_global = find_map_fd(obj, "global_stats_map");
	map_fd_sci = find_map_fd(obj, "sci_stats_map");
	
	if (map_fd_global < 0 || map_fd_sci < 0) {
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
	printf("Total packets: %" PRIu64 "\n", (uint64_t)global_stats.total_packets);
	printf("Matching packets: %" PRIu64 "\n", (uint64_t)global_stats.total_matching_packets);
	printf("Non-matching packets: %" PRIu64 "\n", 
	       (uint64_t)(global_stats.total_packets - global_stats.total_matching_packets));
	printf("Latest packet number: %" PRIu32 "\n", global_stats.packet_counter);
	printf("\n=== Redirect Statistics ===\n");
	printf("AF_XDP redirects (matching): %" PRIu64 "\n", (uint64_t)global_stats.redirect_xdp_ok);
	printf("DEVMAP redirects (success):  %" PRIu64 "\n", (uint64_t)global_stats.redirect_devmap_ok);
	printf("DEVMAP redirects (failed):   %" PRIu64 "\n", (uint64_t)global_stats.redirect_devmap_fail);
	
	/* Iterate through all SCIs */
	printf("\n=== Per-SCI Statistics ===\n");
	printf("%-20s %-20s %-25s\n", "SCI", "Packet Count", "Latest Packet Number");
	printf("%-20s %-20s %-25s\n", "-------------------", "------------", "---------------------");
	
	/* Start iteration from NULL (first key) */
	next_key = 0;
	while (bpf_map_get_next_key(map_fd_sci, 
				     sci ? &sci : NULL, 
				     &next_key) == 0) {
		sci = next_key;
		
		err = bpf_map_lookup_elem(map_fd_sci, &sci, &sci_stats_entry);
		if (err) {
			fprintf(stderr, "Failed to lookup SCI 0x%016" PRIx64 ": %s\n",
				(uint64_t)__builtin_bswap64(sci), strerror(errno));
			continue;
		}
		
		printf("0x%016" PRIx64 " %-20" PRIu64 " %-25" PRIu64 "\n",
		       (uint64_t)__builtin_bswap64(sci),
		       (uint64_t)sci_stats_entry.packet_count,
		       (uint64_t)sci_stats_entry.latest_packet_num);
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

/* Initialize persistent raw socket for output */
static int init_output_socket(const char *ifname)
{
	struct ifreq ifr;
	int ret;

	/* Create raw socket */
	output_raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (output_raw_sock < 0) {
		fprintf(stderr, "ERR: Failed to create output raw socket: %s\n", strerror(errno));
		return -1;
	}

	/* Get interface index */
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	ret = ioctl(output_raw_sock, SIOCGIFINDEX, &ifr);
	if (ret < 0) {
		fprintf(stderr, "ERR: Failed to get interface index for %s: %s\n", ifname, strerror(errno));
		close(output_raw_sock);
		output_raw_sock = -1;
		return -1;
	}

	/* Setup destination address (reused for all sends) */
	memset(&output_saddr, 0, sizeof(output_saddr));
	output_saddr.sll_family = AF_PACKET;
	output_saddr.sll_protocol = htons(ETH_P_ALL);
	output_saddr.sll_ifindex = ifr.ifr_ifindex;
	output_saddr.sll_halen = ETH_ALEN;

	printf("Initialized persistent raw socket for output interface %s\n", ifname);
	return 0;
}

static int send_packet_to_interface(const void *data, size_t len)
{
	if (output_raw_sock < 0)
		return -1;

	int ret = sendto(output_raw_sock, data, len, 0, 
			 (struct sockaddr *)&output_saddr, sizeof(output_saddr));
	return (ret < 0) ? -1 : 0;
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
				if (ret == (int)free_frames) {
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
			send_packet_to_interface(pkt, len);

			/* Free the frame back to the umem */
			xsk_free_umem_frame(xsk, addr);
		}

		xsk_ring_cons__release(&xsk->rx, rcvd);

		/* Refill fill queue */
		uint32_t free_frames = xsk->umem_frame_free;
		if (free_frames > 0) {
			ret = xsk_ring_prod__reserve(&xsk->umem->fq, free_frames, &idx_fq);
			if (ret == (int)free_frames) {
				for (uint32_t i = 0; i < free_frames; i++)
					*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
						xsk_alloc_umem_frame(xsk);
				xsk_ring_prod__submit(&xsk->umem->fq, free_frames);
			}
		}
	}

	return NULL;
}

static int setup_af_xdp_socket(const char *ifname, int ifindex, struct bpf_object *obj)
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
		.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD, /* Don't load another XDP prog */
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
		xsk_info = NULL;
		return -1;
	}

	/* Get xsks_map file descriptor */
	map_fd_xsks = find_map_fd(obj, "xsks_map");
	if (map_fd_xsks < 0) {
		fprintf(stderr, "ERR: Failed to find xsks_map\n");
		xsk_socket__delete(xsk_info->xsk);
		xsk_umem__delete(umem->umem);
		free(xsk_info);
		free(umem);
		munmap(umem_buffer, NUM_FRAMES * FRAME_SIZE);
		xsk_info = NULL;
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
		xsk_info = NULL;
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

/* Load BPF object file and get program FD */
static struct bpf_object *load_bpf_object(const char *filename, const char *prog_name, int *prog_fd)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	int err;

	/* Open BPF object file */
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERR: Failed to open BPF object file %s: %s\n",
			filename, strerror(errno));
		return NULL;
	}

	/* Load BPF object into kernel */
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "ERR: Failed to load BPF object: %s\n", strerror(-err));
		bpf_object__close(obj);
		return NULL;
	}

	/* Find the program by name */
	prog = bpf_object__find_program_by_name(obj, prog_name);
	if (!prog) {
		fprintf(stderr, "ERR: Failed to find program '%s' in object\n", prog_name);
		bpf_object__close(obj);
		return NULL;
	}

	*prog_fd = bpf_program__fd(prog);
	if (*prog_fd < 0) {
		fprintf(stderr, "ERR: Failed to get program FD: %s\n", strerror(errno));
		bpf_object__close(obj);
		return NULL;
	}

	return obj;
}

/* Attach XDP program to interface using libbpf */
static int attach_xdp(int ifindex, int prog_fd, __u32 *flags_out)
{
	int err;

	/* Try native mode first */
	err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_DRV_MODE, NULL);
	if (err == 0) {
		*flags_out = XDP_FLAGS_DRV_MODE;
		return 0;
	}

	/* Fall back to SKB mode */
	err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
	if (err == 0) {
		*flags_out = XDP_FLAGS_SKB_MODE;
		return 0;
	}

	fprintf(stderr, "ERR: Failed to attach XDP program: %s\n", strerror(-err));
	return err;
}

/* Detach XDP program from interface */
static int detach_xdp(int ifindex, __u32 flags)
{
	return bpf_xdp_detach(ifindex, flags, NULL);
}

int main(int argc, char **argv)
{
	int err = 0;
	int interval = 2; /* Default 2 seconds */
	int prog_fd = -1;
	char *input_ifname;
	struct bpf_object *output_obj = NULL;
	
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
	
	input_ifname = argv[1];
	output_ifname = argv[2];
	
	/* Get interface indices */
	input_ifindex = if_nametoindex(input_ifname);
	if (input_ifindex == 0) {
		fprintf(stderr, "Failed to get interface index for %s: %s\n",
			input_ifname, strerror(errno));
		return EXIT_FAIL_OPTION;
	}
	
	output_ifindex = if_nametoindex(output_ifname);
	if (output_ifindex == 0) {
		fprintf(stderr, "Failed to get interface index for output interface %s: %s\n",
			output_ifname, strerror(errno));
		return EXIT_FAIL_OPTION;
	}
	
	/* Load and attach pass program to output interface FIRST to determine mode */
	printf("Loading XDP pass program for output interface %s...\n", output_ifname);
	output_obj = load_bpf_object("xdp_prog.o", "xdp_pass_func", &output_prog_fd);
	if (!output_obj) {
		fprintf(stderr, "WARNING: Failed to load output XDP program, redirect may not work\n");
	} else {
		err = attach_xdp(output_ifindex, output_prog_fd, &output_xdp_flags);
		if (err) {
			fprintf(stderr, "WARNING: Failed to attach XDP program to %s\n", output_ifname);
			bpf_object__close(output_obj);
			output_obj = NULL;
		} else {
			printf("Attached XDP pass program to %s in %s mode\n", output_ifname,
			       (output_xdp_flags & XDP_FLAGS_DRV_MODE) ? "native" : "SKB");
		}
	}
	
	/* Load main XDP program */
	printf("Loading XDP program for input interface %s...\n", input_ifname);
	bpf_obj = load_bpf_object("xdp_prog.o", "xdp_macsec_stats", &prog_fd);
	if (!bpf_obj) {
		return EXIT_FAIL_BPF;
	}
	
	/* Attach input interface in SAME mode as output for DEVMAP redirect to work */
	if (output_obj && (output_xdp_flags & XDP_FLAGS_SKB_MODE)) {
		/* Output is in SKB mode, force input to SKB mode too */
		printf("Forcing input interface to SKB mode to match output interface\n");
		err = bpf_xdp_attach(input_ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
		if (err == 0) {
			input_xdp_flags = XDP_FLAGS_SKB_MODE;
		} else {
			fprintf(stderr, "ERR: Failed to attach XDP program in SKB mode: %s\n", strerror(-err));
			bpf_object__close(bpf_obj);
			return EXIT_FAIL_BPF;
		}
	} else {
		/* Try native first, fall back to SKB */
		err = attach_xdp(input_ifindex, prog_fd, &input_xdp_flags);
		if (err) {
			fprintf(stderr, "ERR: Failed to attach XDP program to %s\n", input_ifname);
			bpf_object__close(bpf_obj);
			return EXIT_FAIL_BPF;
		}
	}
	printf("Attached XDP program to %s in %s mode\n", input_ifname,
	       (input_xdp_flags & XDP_FLAGS_DRV_MODE) ? "native" : "SKB");
	
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
	if (err || verify_ifindex != (unsigned int)output_ifindex) {
		fprintf(stderr, "ERR: Failed to verify tx_port map (got ifindex %u, expected %d)\n",
			verify_ifindex, output_ifindex);
		err = EXIT_FAIL_BPF;
		goto cleanup;
	}
	
	printf("Configured redirect: %s (ifindex %d) -> %s (ifindex %d)\n",
	       input_ifname, input_ifindex, output_ifname, output_ifindex);
	
	/* Enable promiscuous mode on input interface */
	struct ifreq ifr;
	int sock_promisc = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock_promisc >= 0) {
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, input_ifname, IFNAMSIZ - 1);
		if (ioctl(sock_promisc, SIOCGIFFLAGS, &ifr) == 0) {
			ifr.ifr_flags |= IFF_PROMISC;
			if (ioctl(sock_promisc, SIOCSIFFLAGS, &ifr) == 0) {
				printf("Enabled promiscuous mode on %s\n", input_ifname);
			}
		}
		close(sock_promisc);
	}
	
	/* Initialize persistent raw socket for output */
	if (init_output_socket(output_ifname) < 0) {
		fprintf(stderr, "ERR: Failed to initialize output socket\n");
		err = EXIT_FAIL;
		goto cleanup;
	}
	
	/* Setup AF_XDP socket for matching packets */
	if (setup_af_xdp_socket(input_ifname, input_ifindex, bpf_obj) < 0) {
		fprintf(stderr, "WARNING: Failed to setup AF_XDP socket, matching packets will use DEVMAP redirect\n");
	} else {
		/* Start packet reader thread */
		if (pthread_create(&xsk_thread, NULL, xsk_packet_reader, xsk_info) != 0) {
			fprintf(stderr, "ERR: Failed to create AF_XDP reader thread: %s\n", strerror(errno));
		} else {
			printf("AF_XDP packet reader thread started\n");
		}
	}
	
	printf("\nNOTE: Make sure there is traffic on %s for counters to increment.\n", input_ifname);
	printf("      Matching packets will be sent to %s via AF_XDP socket.\n", output_ifname);
	printf("      Non-matching packets will be redirected to %s via DEVMAP.\n", output_ifname);
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
	
	printf("\nDetaching XDP programs...\n");
	err = 0; /* Reset error for cleanup */
	
cleanup:
	/* Wait for AF_XDP thread to finish */
	if (xsk_info && xsk_info->xsk) {
		pthread_join(xsk_thread, NULL);
		xsk_socket__delete(xsk_info->xsk);
		if (xsk_info->umem) {
			xsk_umem__delete(xsk_info->umem->umem);
			if (xsk_info->umem->buffer) {
				munmap(xsk_info->umem->buffer, NUM_FRAMES * FRAME_SIZE);
			}
			free(xsk_info->umem);
		}
		free(xsk_info);
	}
	
	/* Close output raw socket */
	if (output_raw_sock >= 0) {
		close(output_raw_sock);
	}
	
	/* Detach output XDP program */
	if (output_obj) {
		int detach_err = detach_xdp(output_ifindex, output_xdp_flags);
		if (detach_err) {
			fprintf(stderr, "Error detaching output XDP program: %s\n", strerror(-detach_err));
		}
		bpf_object__close(output_obj);
	}
	
	/* Detach input XDP program */
	if (bpf_obj) {
		int detach_err = detach_xdp(input_ifindex, input_xdp_flags);
		if (detach_err) {
			fprintf(stderr, "Error detaching input XDP program: %s\n", strerror(-detach_err));
		}
		bpf_object__close(bpf_obj);
	}
	
	return err == 0 ? EXIT_OK : EXIT_FAIL;
}
