// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 78-tcx-chain: TCX chaining demonstration - userspace loader.
 *
 * Flow:
 *   1. Ensure veth pair exists (setup-veth.sh)
 *   2. Open skeleton, set chain_action (TCX_NEXT or TCX_PASS)
 *   3. Load and attach two tcx/ingress programs to vethbpf0 (FIFO order)
 *   4. Periodically print per-CPU packet counts for both programs
 *   5. Ctrl-C to exit, auto detach
 *
 * Usage:
 *   sudo ./tcx_chain              # TCX_NEXT mode (chain continues)
 *   sudo ./tcx_chain --pass       # TCX_PASS mode (chain stops at prog_a)
 *   sudo ./tcx_chain vethbpf0 2   # custom interface and interval
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcx_chain.h"
#include "tcx_chain.skel.h"

static char *g_ifname = "vethbpf0";
static int g_interval = 2;
static int g_pass_mode = 0;
static volatile sig_atomic_t exiting;

static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static void print_stats(struct tcx_chain_bpf *skel, int ncpu)
{
	__u64 pkts[2] = {};
	__u64 *vals;

	vals = calloc(ncpu, sizeof(__u64));
	if (!vals)
		return;

	for (int i = 0; i < 2; i++) {
		__u32 key = i;
		memset(vals, 0, ncpu * sizeof(__u64));
		if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.pkt_count), &key, vals) == 0)
			for (int c = 0; c < ncpu; c++)
				pkts[i] += vals[c];
	}

	free(vals);

	printf("%-12s %10s\n", "Program", "Packets");
	printf("%-12s %10s\n", "--------", "-------");
	printf("%-12s %10llu\n", "prog_a", pkts[0]);
	printf("%-12s %10llu\n", "prog_b", pkts[1]);
	printf("\n");
}

int main(int argc, char **argv)
{
	struct tcx_chain_bpf *skel;
	struct bpf_link *links[2] = {};
	int err = 0, ifindex, ncpu;

	int arg_idx = 0;
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--pass") == 0) {
			g_pass_mode = 1;
		} else if (argv[i][0] != '-') {
			if (arg_idx == 0)
				g_ifname = argv[i];
			else if (arg_idx == 1)
				g_interval = atoi(argv[i]);
			arg_idx++;
		}
	}

	ifindex = if_nametoindex(g_ifname);
	if (!ifindex) {
		fprintf(stderr, "interface %s not found. Run: sudo ./scripts/setup-veth.sh create\n", g_ifname);
		return 1;
	}
	ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpu < 1) ncpu = 1;

	setvbuf(stdout, NULL, _IONBF, 0);
	libbpf_set_print(libbpf_print_fn);

	struct sigaction sa = {};
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	skel = tcx_chain_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open skeleton\n");
		return 1;
	}

	/* Set chain_action before load.
	 * TCX_NEXT (-1): chain continues, prog_b also sees packets.
	 * TCX_PASS  (0): chain stops at prog_a, prog_b never runs.
	 */
	skel->data->chain_action = g_pass_mode ? TCX_PASS : TCX_NEXT;

	err = tcx_chain_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load skeleton: %d\n", err);
		goto cleanup;
	}

	/* Attach prog_a first, then prog_b.
	 * With empty opts, programs are appended to the chain in FIFO order.
	 * Chain order: [prog_a -> prog_b]
	 */
	struct bpf_program *progs[2] = {
		skel->progs.prog_a,
		skel->progs.prog_b,
	};

	for (int i = 0; i < 2; i++) {
		LIBBPF_OPTS(bpf_tcx_opts, opts);
		links[i] = bpf_program__attach_tcx(progs[i], ifindex, &opts);
		if (!links[i]) {
			fprintf(stderr, "attach prog_%c failed: %s\n", 'a' + i, strerror(errno));
			err = -errno;
			goto cleanup;
		}
	}

	printf("TCX chain attached to %s (2 programs: prog_a -> prog_b).\n", g_ifname);
	printf("Mode: %s (chain %s)\n",
		g_pass_mode ? "TCX_PASS" : "TCX_NEXT",
		g_pass_mode ? "stops at prog_a" : "continues to prog_b");
	printf("Generate traffic: sudo ip netns exec bpfns ping 192.168.99.1\n\n");

	while (!exiting) {
		sleep(g_interval);
		print_stats(skel, ncpu);
	}

cleanup:
	for (int i = 0; i < 2; i++)
		if (links[i])
			bpf_link__destroy(links[i]);
	tcx_chain_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
