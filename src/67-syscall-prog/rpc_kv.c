// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 67-syscall-prog: 用户态 — 交互式 BPF RPC 键值存储 CLI。
 *
 * 通过 bpf_prog_test_run_opts 触发 BPF syscall 程序，
 * 用户态传入 rpc_req，BPF 程序返回 retval。
 *
 * 命令：
 *   put <key> <value>   存入键值对
 *   get <key>           查询键值
 *   del <key>           删除键
 *   stats               显示操作统计
 *   quit                退出
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "rpc_kv.h"
#include "rpc_kv.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

/* 执行一次 BPF RPC 调用 */
static int bpf_rpc_call(int prog_fd, __u32 op, __u32 key, __u64 value, int *retval)
{
	struct rpc_req req = {
		.op = op,
		.key = key,
		.value = value,
	};
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .ctx_in = &req,
		    .ctx_size_in = sizeof(req));

	int err = bpf_prog_test_run_opts(prog_fd, &opts);
	if (err) {
		fprintf(stderr, "  BPF_PROG_RUN failed: %s\n", strerror(errno));
		return err;
	}
	*retval = (int)opts.retval;
	return 0;
}

/* 读取并打印 percpu stats */
static void print_stats(struct rpc_kv_bpf *skel)
{
	int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpu < 1)
		ncpu = 1;

	printf("\n  --- Operation Stats ---\n");
	const char *names[] = {"PUT", "LOOKUP", "DELETE"};
	__u64 *vals = calloc(ncpu, sizeof(__u64));

	for (int s = 0; s < STATS_COUNT; s++) {
		__u32 key = s;
		if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					&key, vals) != 0) {
			printf("  %-8s (error)\n", names[s]);
			continue;
		}
		__u64 total = 0;
		for (int c = 0; c < ncpu; c++)
			total += vals[c];
		printf("  %-8s %llu", names[s], total);
		if (ncpu > 1) {
			printf("  (");
			for (int c = 0; c < ncpu && c < 4; c++)
				printf("CPU%d=%llu%s", c, vals[c],
				       c < ncpu - 1 && c < 3 ? " " : "");
			if (ncpu > 4)
				printf(" ...");
			printf(")");
		}
		printf("\n");
	}
	free(vals);
}

int main(int argc, char **argv)
{
	struct rpc_kv_bpf *skel;
	int err = 0, prog_fd;
	char line[256];

	setvbuf(stdout, NULL, _IONBF, 0);
	libbpf_set_print(libbpf_print_fn);

	skel = rpc_kv_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "failed to open/load skeleton\n");
		return 1;
	}

	/* syscall 程序不需要 attach — 加载即可用 */
	prog_fd = bpf_program__fd(skel->progs.handle_rpc);
	if (prog_fd < 0) {
		fprintf(stderr, "failed to get prog fd\n");
		err = 1;
		goto cleanup;
	}

	printf("BPF syscall RPC KV store loaded.\n");
	printf("  prog_fd=%d  store(map_fd=%d)  stats(map_fd=%d)\n\n",
	       prog_fd,
	       bpf_map__fd(skel->maps.store),
	       bpf_map__fd(skel->maps.stats));
	printf("Commands: put <key> <value> | get <key> | del <key> | stats | quit\n\n");

	while (1) {
		printf("> ");
		if (!fgets(line, sizeof(line), stdin))
			break;

		/* 去除换行 */
		line[strcspn(line, "\n")] = '\0';
		if (line[0] == '\0')
			continue;

		char cmd[16];
		__u32 key;
		__u64 value;
		int retval;

		if (sscanf(line, "put %u %llu", &key, &value) == 2) {
			if (bpf_rpc_call(prog_fd, OP_PUT, key, value, &retval) == 0)
				printf("  PUT key=%u value=%llu -> OK (%d)\n",
				       key, value, retval);
		} else if (sscanf(line, "get %u", &key) == 1) {
			if (bpf_rpc_call(prog_fd, OP_LOOKUP, key, 0, &retval) == 0) {
				if (retval >= 0)
					printf("  LOOKUP key=%u -> value=%d\n",
					       key, retval);
				else
					printf("  LOOKUP key=%u -> NOT FOUND (%d)\n",
					       key, retval);
			}
		} else if (sscanf(line, "del %u", &key) == 1) {
			if (bpf_rpc_call(prog_fd, OP_DELETE, key, 0, &retval) == 0)
				printf("  DELETE key=%u -> %s (%d)\n",
				       key, retval == 0 ? "OK" : "NOT FOUND",
				       retval);
		} else if (strcmp(line, "stats") == 0) {
			print_stats(skel);
		} else if (strcmp(line, "quit") == 0 || strcmp(line, "exit") == 0) {
			break;
		} else if (strcmp(line, "help") == 0) {
			printf("  put <key> <value>   - store key-value\n");
			printf("  get <key>           - lookup key\n");
			printf("  del <key>           - delete key\n");
			printf("  stats               - show operation stats\n");
			printf("  quit                - exit\n");
		} else {
			printf("  Unknown command. Type 'help'.\n");
		}
	}

	printf("\n  Cleanup. Goodbye.\n");

cleanup:
	rpc_kv_bpf__destroy(skel);
	return err;
}
