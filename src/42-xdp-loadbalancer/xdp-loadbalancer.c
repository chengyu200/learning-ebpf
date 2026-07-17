// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 42-xdp-loadbalancer: user-space loader. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdp-loadbalancer.h"
#include "xdp-loadbalancer.skel.h"

static char *g_ifname = "vethbpf0";
static volatile sig_atomic_t exiting;

static void sig_handler(int sig) { exiting = 1; }
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG) return 0;
	return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
	struct xdp_loadbalancer_bpf *skel;
	int ifindex, err, prog_fd, i;

	if (argc > 1) g_ifname = argv[1];
	ifindex = if_nametoindex(g_ifname);
	if (!ifindex) { fprintf(stderr, "if %s not found\n", g_ifname); return 1; }

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = xdp_loadbalancer_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "open/load failed\n"); return 1; }

	/* Populate backends from argv[2..] as "IP" (MAC left zero; peer uses L3). */
	for (i = 2; i < argc && i - 2 < MAX_BACKENDS; i++) {
		struct backend be = {};
		if (inet_pton(AF_INET, argv[i], &be.addr) != 1) {
			fprintf(stderr, "bad backend ip: %s\n", argv[i]);
			continue;
		}
		__u32 key = i - 2;
		bpf_map__update_elem(skel->maps.backends, &key, sizeof(key),
				     &be, sizeof(be), BPF_ANY);
		printf("backend[%u] = %s\n", key, argv[i]);
	}

	prog_fd = bpf_program__fd(skel->progs.xdp_lb);
	err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
	if (err) { fprintf(stderr, "xdp attach: %s\n", strerror(-err)); goto cleanup; }

	printf("xdp-loadbalancer on %s... Ctrl-C\n", g_ifname);
	while (!exiting) sleep(1);
	bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);

cleanup:
	xdp_loadbalancer_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
