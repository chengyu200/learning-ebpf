// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
/* 23-http: user-space loader.  Opens a raw packet socket bound to an
 * interface, attaches the socket filter, and prints parsed events.
 */
#include <argp.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <bpf/libbpf.h>
#include "http.h"
#include "http.skel.h"

static struct env {
	char ifname[IF_NAMESIZE];
	bool verbose;
} env = { .ifname = "lo", .verbose = false };

const char *argp_program_version = "http 0.1";
const char argp_program_doc[] =
"Capture TCP/IPv4 packets (incl. HTTP request line) via a socket filter.\n\n"
"USAGE: ./http [--if IFNAME] [-v]\n";

static const struct argp_option opts[] = {
	{ "if", 'i', "IFNAME", 0, "Interface to bind (default lo)" },
	{ "verbose", 'v', NULL, 0, "Verbose libbpf debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'i': strncpy(env.ifname, arg, sizeof(env.ifname) - 1); break;
	case 'v': env.verbose = true; break;
	default: return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = { .options = opts, .parser = parse_arg, .doc = argp_program_doc };

static volatile sig_atomic_t exiting;
static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static int open_raw_sock(const char *name)
{
	struct sockaddr_ll sll;
	int sock;

	sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
	if (sock < 0) {
		fprintf(stderr, "Failed to create raw socket\n");
		return -1;
	}
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex(name);
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		fprintf(stderr, "Failed to bind to %s: %s\n", name, strerror(errno));
		close(sock);
		return -1;
	}
	return sock;
}

static void ltoa(uint32_t addr, char *dst)
{
	snprintf(dst, 16, "%u.%u.%u.%u", (addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
		 (addr >> 8) & 0xFF, (addr & 0xFF));
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct so_event *e = data;
	char ifname[IF_NAMESIZE];
	char sstr[16] = {}, dstr[16] = {};

	if (e->pkt_type != PACKET_HOST)
		return 0;

	ltoa(ntohl(e->src_addr), sstr);
	ltoa(ntohl(e->dst_addr), dstr);

	if (!if_indextoname(e->ifindex, ifname))
		strncpy(ifname, "?", sizeof(ifname));

	if (e->ip_proto != 6)
		return 0;

	printf("%-7s %s:%d -> %s:%d  proto=%d payload(%u): ",
	       ifname, sstr, ntohs(e->port16[0]), dstr, ntohs(e->port16[1]), e->ip_proto, e->payload_length);
	if (e->payload_length > 0) {
		fwrite(e->payload, 1, e->payload_length < MAX_BUF_SIZE ? e->payload_length : MAX_BUF_SIZE, stdout);
	}
	printf("\n");
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct http_bpf *skel;
	int sock = -1, err;

	argp_parse(&argp, argc, argv, 0, NULL, NULL);
	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = http_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	sock = open_raw_sock(env.ifname);
	if (sock < 0) {
		err = -errno;
		goto cleanup;
	}

	{
		int prog_fd = bpf_program__fd(skel->progs.socket_handler);
		err = setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd));
	}
	if (err) {
		fprintf(stderr, "SO_ATTACH_BPF failed: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	printf("Listening on %s... Ctrl-C to stop.\n", env.ifname);
	printf("%-7s %-22s %s\n", "IF", "SRC -> DST", "PAYLOAD");

	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) { err = 0; break; }
		if (err < 0) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	if (sock >= 0) close(sock);
	http_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
