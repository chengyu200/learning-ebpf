// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 41-xdp-tcpdump: user-space loader. */
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
#include "xdp-tcpdump.h"
#include "xdp-tcpdump.skel.h"

static char *g_ifname = "vethbpf0";
static volatile sig_atomic_t exiting;

static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	char s[INET_ADDRSTRLEN], d[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &e->saddr, s, sizeof(s));
	inet_ntop(AF_INET, &e->daddr, d, sizeof(d));
	printf("%s:%d -> %s:%d  proto=%d len=%u\n",
	       s, e->sport, d, e->dport, e->proto, e->pkt_len);
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct xdp_tcpdump_bpf *skel;
	int ifindex, err, prog_fd;

	if (argc > 1) g_ifname = argv[1];
	ifindex = if_nametoindex(g_ifname);
	if (!ifindex) { fprintf(stderr, "if %s not found\n", g_ifname); return 1; }

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = xdp_tcpdump_bpf__open_and_load();
	if (!skel) { fprintf(stderr, "open/load failed\n"); return 1; }

	prog_fd = bpf_program__fd(skel->progs.xdp_tcpdump);
	err = bpf_xdp_attach(ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
	if (err) { fprintf(stderr, "xdp attach: %s\n", strerror(-err)); goto cleanup; }

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) { err = -1; goto cleanup; }

	printf("xdp-tcpdump on %s... Ctrl-C\n", g_ifname);
	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) { fprintf(stderr, "poll err: %d\n", err); break; }
	}
	bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);

cleanup:
	ring_buffer__free(rb);
	xdp_tcpdump_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
