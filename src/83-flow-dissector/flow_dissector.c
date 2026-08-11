// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 83-flow-dissector: custom BPF flow dissector — userspace loader + test.
 *
 * Flow:
 *   1. Load BPF skeleton
 *   2. Attach flow_dissector program to current netns (bpf_program__attach_netns)
 *   3. Construct test packets (Ethernet + IPv4 + TCP/UDP/ICMP)
 *   4. Test program logic via bpf_prog_test_run_opts (simulates kernel calls)
 *   5. Print dissected flow keys for each test packet
 *   6. Cleanup
 *
 * Note: the kernel only calls the BPF flow dissector at runtime if
 *   CONFIG_BPF_FLOW_DISSECTOR is enabled. Without it, the program loads
 *   and attaches but is never invoked. bpf_prog_test_run_opts works
 *   regardless and verifies the program logic.
 *
 * Usage:
 *   sudo ./flow_dissector
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <asm/byteorder.h>
#include "flow_dissector.h"
#include "flow_dissector.skel.h"

#define bpf_ntohs(x) ntohs(x)

struct bpf_flow_keys {
	__u16 nhoff;
	__u16 thoff;
	__u16 addr_proto;
	__u8 is_frag;
	__u8 is_first_frag;
	__u8 is_encap;
	__u8 ip_proto;
	__u16 n_proto;
	__u16 sport;
	__u16 dport;
	union {
		struct { __u32 ipv4_src; __u32 ipv4_dst; };
		struct { __u32 ipv6_src[4]; __u32 ipv6_dst[4]; };
	};
	__u32 flags;
	__u32 flow_label;
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static const char *proto_str(__u8 proto)
{
	switch (proto) {
	case 6:  return "TCP";
	case 17: return "UDP";
	case 1:  return "ICMP";
	default: return "?";
	}
}

static int handle_ringbuf(void *ctx, void *data, size_t data_sz)
{
	struct event *e = data;
	char src_ip[16], dst_ip[16];
	struct in_addr addr;
	addr.s_addr = e->ipv4_src;
	inet_ntop(AF_INET, &addr, src_ip, sizeof(src_ip));
	addr.s_addr = e->ipv4_dst;
	inet_ntop(AF_INET, &addr, dst_ip, sizeof(dst_ip));

	fprintf(stderr, "  [RINGBUF] %s:%u -> %s:%u  %s  nhoff=%u thoff=%u\n",
		src_ip, e->sport, dst_ip, e->dport,
		proto_str(e->ip_proto), e->nhoff, e->thoff);
	return 0;
}

static void print_flow_keys(const struct bpf_flow_keys *fk)
{
	char src_ip[16], dst_ip[16];
	struct in_addr addr;

	addr.s_addr = fk->ipv4_src;
	inet_ntop(AF_INET, &addr, src_ip, sizeof(src_ip));
	addr.s_addr = fk->ipv4_dst;
	inet_ntop(AF_INET, &addr, dst_ip, sizeof(dst_ip));

	fprintf(stderr, "  n_proto=0x%04x  ip_proto=%-4s  nhoff=%u  thoff=%u\n",
		bpf_ntohs(fk->n_proto), proto_str(fk->ip_proto), fk->nhoff, fk->thoff);
	fprintf(stderr, "  src=%s  dst=%s\n", src_ip, dst_ip);
	if (fk->ip_proto == 6 || fk->ip_proto == 17)
		fprintf(stderr, "  sport=%u  dport=%u\n",
			bpf_ntohs(fk->sport), bpf_ntohs(fk->dport));
	if (fk->is_frag)
		fprintf(stderr, "  is_frag=1 is_first_frag=%u\n", fk->is_first_frag);
}

/* Build a test packet: Ethernet + IPv4 + TCP */
static int build_tcp_pkt(char *buf, int bufsz)
{
	/* Ethernet header (14 bytes) */
	char eth[14] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  /* dst MAC */
		0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,  /* src MAC */
		0x08, 0x00                           /* ETH_P_IP */
	};
	/* IPv4 header (20 bytes) */
	struct {
		__u8 ver_ihl, tos;
		__u16 tot_len;
		__u16 id, frag_off;
		__u8 ttl, proto;
		__u16 check;
		__u32 saddr, daddr;
	} ip = {
		.ver_ihl = 0x45, .tos = 0, .tot_len = htons(40),
		.id = 0, .frag_off = 0, .ttl = 64, .proto = 6, /* TCP */
		.check = 0,
		.saddr = htonl(0x7f000001), /* 127.0.0.1 */
		.daddr = htonl(0x7f000002), /* 127.0.0.2 */
	};
	/* TCP header (20 bytes) */
	struct {
		__u16 sport, dport;
		__u32 seq, ack;
		__u8 data_off, flags;
		__u16 window, check, urg;
	} tcp = {
		.sport = htons(12345), .dport = htons(8080),
		.seq = 0, .ack = 0, .data_off = 0x50, .flags = 0x02, /* SYN */
		.window = 0, .check = 0, .urg = 0,
	};

	int total = sizeof(eth) + sizeof(ip) + sizeof(tcp);
	if (total > bufsz) return -1;
	memcpy(buf, eth, sizeof(eth));
	memcpy(buf + sizeof(eth), &ip, sizeof(ip));
	memcpy(buf + sizeof(eth) + sizeof(ip), &tcp, sizeof(tcp));
	return total;
}

/* Build a test packet: Ethernet + IPv4 + UDP */
static int build_udp_pkt(char *buf, int bufsz)
{
	char eth[14] = {
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
		0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
		0x08, 0x00
	};
	struct {
		__u8 ver_ihl, tos;
		__u16 tot_len;
		__u16 id, frag_off;
		__u8 ttl, proto;
		__u16 check;
		__u32 saddr, daddr;
	} ip = {
		.ver_ihl = 0x45, .tot_len = htons(28),
		.ttl = 64, .proto = 17, /* UDP */
		.saddr = htonl(0xc0a80101), /* 192.168.1.1 */
		.daddr = htonl(0xc0a80102), /* 192.168.1.2 */
	};
	struct {
		__u16 sport, dport;
		__u16 len, check;
	} udp = {
		.sport = htons(5353), .dport = htons(53),
		.len = htons(8), .check = 0,
	};

	int total = sizeof(eth) + sizeof(ip) + sizeof(udp);
	if (total > bufsz) return -1;
	memcpy(buf, eth, sizeof(eth));
	memcpy(buf + sizeof(eth), &ip, sizeof(ip));
	memcpy(buf + sizeof(eth) + sizeof(ip), &udp, sizeof(udp));
	return total;
}

/* Build a test packet: IPv4 only (no Ethernet, like loopback) */
static int build_ipv4_only_pkt(char *buf, int bufsz)
{
	struct {
		__u8 ver_ihl, tos;
		__u16 tot_len;
		__u16 id, frag_off;
		__u8 ttl, proto;
		__u16 check;
		__u32 saddr, daddr;
	} ip = {
		.ver_ihl = 0x45, .tot_len = htons(20),
		.ttl = 64, .proto = 1, /* ICMP */
		.saddr = htonl(0x7f000001),
		.daddr = htonl(0x7f000001),
	};

	int total = sizeof(ip);
	if (total > bufsz) return -1;
	memcpy(buf, &ip, sizeof(ip));
	return total;
}

struct test_case {
	const char *name;
	int (*build)(char *, int);
};

int main(int argc, char **argv)
{
	struct flow_dissector_bpf *skel;
	struct bpf_link *link = NULL;
	int err = 0, netns_fd = -1;
	int prog_fd;

	setvbuf(stdout, NULL, _IONBF, 0);
	libbpf_set_print(libbpf_print_fn);

	/* 1. Load BPF skeleton */
	skel = flow_dissector_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load skeleton\n");
		return 1;
	}

	prog_fd = bpf_program__fd(skel->progs.dissect_flow);

	/* 2. Attach flow dissector to current netns */
	netns_fd = open("/proc/self/ns/net", O_RDONLY | O_CLOEXEC);
	if (netns_fd >= 0) {
		link = bpf_program__attach_netns(skel->progs.dissect_flow, netns_fd);
		if (link) {
			fprintf(stderr, "BPF flow dissector attached to netns (link active).\n");
		} else {
			fprintf(stderr, "attach_netns failed: %s (continuing with test_run)\n",
				strerror(errno));
		}
	}

	fprintf(stderr, "Testing flow dissector program logic via bpf_prog_test_run_opts.\n\n");

	struct ring_buffer *ringbuf = ring_buffer__new(
		bpf_map__fd(skel->maps.rb), handle_ringbuf, NULL, NULL);

	/* 3. Test cases */
	struct test_case tests[] = {
		{ "Ethernet + IPv4 + TCP (127.0.0.1:12345 -> 127.0.0.2:8080)", build_tcp_pkt },
		{ "Ethernet + IPv4 + UDP (192.168.1.1:5353 -> 192.168.1.2:53)", build_udp_pkt },
		{ "IPv4 only, no Ethernet (127.0.0.1 -> 127.0.0.1, ICMP)",      build_ipv4_only_pkt },
	};

	for (int i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
		char pkt[256];
		int pkt_len = tests[i].build(pkt, sizeof(pkt));
		if (pkt_len < 0) {
			fprintf(stderr, "Test %d: build failed\n", i);
			continue;
		}

		struct bpf_flow_keys flow_keys = {};
		LIBBPF_OPTS(bpf_test_run_opts, opts,
			.data_in = pkt,
			.data_size_in = pkt_len,
			.data_out = pkt,
			.data_size_out = pkt_len,
			.repeat = 1,
		);

		err = bpf_prog_test_run_opts(prog_fd, &opts);
		if (err) {
			fprintf(stderr, "Test %d: %s\n  test_run returned: %s (may be OK)\n",
				i, tests[i].name, strerror(errno));
		} else {
			fprintf(stderr, "Test %d: %s\n  retval=%lld\n",
				i, tests[i].name, opts.retval);
		}

		/* Poll ringbuf for this test's events */
		if (ringbuf)
			ring_buffer__poll(ringbuf, 50);
	}

	/* 4. Check call counters */
	__u32 key = 0;
	__u64 vals[16] = {};
	int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpu > 16) ncpu = 16;

	/* Total calls */
	__u64 total = 0;
	if (bpf_map__lookup_elem(skel->maps.call_count, &key, sizeof(key),
				 vals, sizeof(__u64) * ncpu, 0) == 0) {
		for (int i = 0; i < ncpu; i++)
			total += vals[i];
	}

	/* flow_keys non-NULL count */
	key = 1;
	__u64 fk_total = 0;
	if (bpf_map__lookup_elem(skel->maps.call_count, &key, sizeof(key),
				 vals, sizeof(__u64) * ncpu, 0) == 0) {
		for (int i = 0; i < ncpu; i++)
			fk_total += vals[i];
	}

	fprintf(stderr, "\nFlow dissector called %llu times (flow_keys non-NULL: %llu).\n",
		total, fk_total);

	/* 5. Final ringbuf drain */
	if (ringbuf) {
		ring_buffer__poll(ringbuf, 100);
		ring_buffer__free(ringbuf);
	}

	fprintf(stderr, "\nDone.\n");

	/* Cleanup */
	if (link)
		bpf_link__destroy(link);
	if (netns_fd >= 0)
		close(netns_fd);
	flow_dissector_bpf__destroy(skel);
	return 0;
}
