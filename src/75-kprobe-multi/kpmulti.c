// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 75-kprobe-multi: 用户态 — skeleton attach + ringbuf + kallsyms 解析 + 统计。
 *
 * 启动时加载 /proc/kallsyms 到内存（IP→函数名映射），
 * ringbuf 事件中的 ip 字段通过映射解析为函数名。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "kpmulti.h"
#include "kpmulti.skel.h"

#define MAX_SYMS 100000
#define MAX_FUNC_STATS 64

static volatile sig_atomic_t exiting;

static void sig_handler(int sig)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

/* kallsyms 条目 */
struct ksym {
	__u64 addr;
	char name[64];
};

static struct ksym *ksyms;
static int ksym_count;

/* 加载 /proc/kallsyms */
static int load_ksyms(void)
{
	FILE *f;
	char line[256];
	char type;
	__u64 addr;
	char name[64];

	ksyms = calloc(MAX_SYMS, sizeof(struct ksym));
	if (!ksyms)
		return -ENOMEM;

	f = fopen("/proc/kallsyms", "r");
	if (!f) {
		fprintf(stderr, "open /proc/kallsyms: %s\n", strerror(errno));
		return -errno;
	}

	ksym_count = 0;
	while (fgets(line, sizeof(line), f) && ksym_count < MAX_SYMS) {
		if (sscanf(line, "%llx %c %63s", (unsigned long long *)&addr,
			   &type, name) != 3)
			continue;
		/* 只保留函数符号（T/t） */
		if (type != 'T' && type != 't')
			continue;
		ksyms[ksym_count].addr = addr;
		strncpy(ksyms[ksym_count].name, name, 63);
		ksyms[ksym_count].name[63] = '\0';
		ksym_count++;
	}
	fclose(f);
	printf("Loaded %d kernel symbols\n", ksym_count);
	return 0;
}

/* IP → 函数名（线性搜索，demo 够用） */
static const char *lookup_sym(__u64 ip)
{
	int i;

	for (i = 0; i < ksym_count; i++) {
		if (ksyms[i].addr == ip)
			return ksyms[i].name;
		if (ksyms[i].addr > ip && i > 0)
			return ksyms[i - 1].name;
	}
	return "(unknown)";
}

/* 函数调用统计 */
struct func_stat {
	char name[64];
	__u64 entry_cnt;
	__u64 return_cnt;
	__u64 latency_sum;
	__u64 latency_cnt;
};

static struct func_stat stats[MAX_FUNC_STATS];
static int stat_count;

static struct func_stat *find_or_add_stat(const char *name)
{
	for (int i = 0; i < stat_count; i++) {
		if (strcmp(stats[i].name, name) == 0)
			return &stats[i];
	}
	if (stat_count >= MAX_FUNC_STATS)
		return NULL;
	strncpy(stats[stat_count].name, name, 63);
	stats[stat_count].name[63] = '\0';
	return &stats[stat_count++];
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct event *e = data;
	const char *func;
	(void)ctx;

	func = lookup_sym(e->ip);
	struct func_stat *st = find_or_add_stat(func);

	switch (e->type) {
	case EVENT_ENTRY:
		if (st) st->entry_cnt++;
		printf("[ENTRY]   pid=%-6d comm=%-12s func=%s\n",
		       e->pid, e->comm, func);
		break;
	case EVENT_RETURN:
		if (st) st->return_cnt++;
		printf("[RETURN]  pid=%-6d comm=%-12s func=%s\n",
		       e->pid, e->comm, func);
		break;
	case EVENT_LATENCY:
		if (st) {
			st->latency_sum += e->latency_ns;
			st->latency_cnt++;
		}
		printf("[LATENCY] pid=%-6d comm=%-12s func=%-20s latency=%llu ns\n",
		       e->pid, e->comm, func, e->latency_ns);
		break;
	default:
		printf("[????]    pid=%-6d type=%d\n", e->pid, e->type);
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct kpmulti_bpf *skel;
	int err = 0;

	setvbuf(stdout, NULL, _IONBF, 0);
	libbpf_set_print(libbpf_print_fn);

	struct sigaction sa = {};
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	/* 加载 kallsyms */
	err = load_ksyms();
	if (err) {
		fprintf(stderr, "failed to load kallsyms\n");
		return 1;
	}

	skel = kpmulti_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open skeleton\n");
		err = 1;
		goto cleanup;
	}

	/* 设置自身 PID 过滤（避免反馈循环）— 必须在 load 之前设置 */
	skel->rodata->self_pid = getpid();

	/* 可选：--pid <N> 只追踪指定进程 */
	if (argc > 1) {
		skel->rodata->target_pid = atoi(argv[1]);
	}

	err = kpmulti_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load skeleton: %s\n", strerror(-err));
		goto cleanup;
	}

	err = kpmulti_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "attach failed: %s\n", strerror(errno));
		goto cleanup;
	}

	printf("kprobe.multi: tracing vfs_* (entry + return + session).\n");
	if (skel->rodata->target_pid)
		printf("  Filtering: only pid=%d\n", skel->rodata->target_pid);
	printf("Test: cat /etc/passwd  |  rm /tmp/test  |  echo > /tmp/x\n");
	printf("Ctrl-C to stop.\n\n");

	struct ring_buffer *rb;
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ring_buffer__new failed\n");
		err = 1;
		goto cleanup;
	}

	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err < 0 && errno != EINTR) {
			fprintf(stderr, "ring_buffer__poll: %s\n", strerror(errno));
			break;
		}
		err = 0;
	}

	/* 汇总统计 */
	printf("\n=== Summary ===\n");
	printf("%-30s %8s %8s %12s\n", "Function", "Entry", "Return", "Avg Latency");
	printf("%-30s %8s %8s %12s\n", "----------", "-----", "------", "-----------");
	for (int i = 0; i < stat_count; i++) {
		printf("%-30s %8llu %8llu ",
		       stats[i].name, stats[i].entry_cnt, stats[i].return_cnt);
		if (stats[i].latency_cnt > 0)
			printf("%12llu ns\n", stats[i].latency_sum / stats[i].latency_cnt);
		else
			printf("%12s\n", "-");
	}

	ring_buffer__free(rb);

cleanup:
	free(ksyms);
	if (skel)
		kpmulti_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
