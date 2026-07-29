// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 54-httpstat: 用户态 — AF_PACKET attach BPF + ringbuf 轮询 + 聚合统计。
 *
 * 功能：
 *   1. 创建 AF_PACKET raw socket，attach BPF socket filter
 *   2. 轮询 ringbuf 接收 http_event
 *   3. 聚合统计：方法分布、状态码分布、URL 路径 Top N、源 IP Top N、字节数
 *   4. 每 5 秒或 Ctrl-C 时打印统计报告
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "httpstat.h"
#include "httpstat.skel.h"

#define MAX_PATHS 1024
#define MAX_IPS   256
#define TOP_N     10
#define REPORT_INTERVAL 20

static volatile sig_atomic_t exiting;
static volatile sig_atomic_t report_flag;

static void sig_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM)
		exiting = 1;
	else if (sig == SIGALRM)
		report_flag = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static int open_raw_sock(const char *name)
{
	struct sockaddr_ll sll;
	int sock;

	sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
		      htons(0x0003 /* ETH_P_ALL */));
	if (sock < 0) {
		fprintf(stderr, "socket(PF_PACKET): %s\n", strerror(errno));
		return -1;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex(name);
	if (!sll.sll_ifindex) {
		fprintf(stderr, "if_nametoindex(%s): %s\n", name, strerror(errno));
		close(sock);
		return -1;
	}
	sll.sll_protocol = htons(0x0003);
	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		fprintf(stderr, "bind: %s\n", strerror(errno));
		close(sock);
		return -1;
	}
	return sock;
}

/* ── 聚合数据结构 ── */

struct path_entry {
	char path[MAX_PATH_LEN];
	__u64 count;
};

struct ip_entry {
	__u32 ip;
	__u64 count;
};

static __u64 method_counts[HTTP_METHOD_COUNT];
static __u64 status_counts[600];
static __u64 req_bytes, resp_bytes;
static __u64 total_requests, total_responses;

static struct path_entry paths[MAX_PATHS];
static int num_paths = 0;

static struct ip_entry ips[MAX_IPS];
static int num_ips = 0;

static struct ip_entry d_ips[MAX_IPS];
static int num_d_ips = 0;

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	struct http_event *e = data;
	(void)ctx;

	char src_str[INET_ADDRSTRLEN], dst_str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &e->saddr, src_str, sizeof(src_str));
	inet_ntop(AF_INET, &e->daddr, dst_str, sizeof(dst_str));

	if (e->type == HTTP_REQUEST) {
		total_requests++;
		if (e->method < HTTP_METHOD_COUNT)
			method_counts[e->method]++;
		req_bytes += e->payload_len;

		/* 实时打印请求 */
		char path_str[MAX_PATH_LEN + 1];
		__u32 plen = e->path_len;
		if (plen > MAX_PATH_LEN)
			plen = MAX_PATH_LEN;
		memcpy(path_str, e->path, plen);
		path_str[plen] = '\0';

		printf("[REQ] %s:%d -> %s:%d  %s %s  (%u bytes)\n",
		       src_str, e->sport, dst_str, e->dport,
		       (e->method < HTTP_METHOD_COUNT) ? http_method_names[e->method] : "?",
		       path_str, e->payload_len);

		/* 路径计数 */
		if (e->path_len > 0 && e->path_len <= MAX_PATH_LEN) {
			int found = -1;
			for (int i = 0; i < num_paths; i++) {
				if (strncmp(paths[i].path, e->path, e->path_len) == 0
				    && paths[i].path[e->path_len] == '\0') {
					found = i;
					break;
				}
			}
			if (found >= 0) {
				paths[found].count++;
			} else if (num_paths < MAX_PATHS) {
				memcpy(paths[num_paths].path, e->path, e->path_len);
				paths[num_paths].path[e->path_len] = '\0';
				paths[num_paths].count = 1;
				num_paths++;
			}
		}

		/* 源 IP 计数 */
		{
			int found = -1;
			for (int i = 0; i < num_ips; i++) {
				if (ips[i].ip == e->saddr) {
					found = i;
					break;
				}
			}
			if (found >= 0) {
				ips[found].count++;
			} else if (num_ips < MAX_IPS) {
				ips[num_ips].ip = e->saddr;
				ips[num_ips].count = 1;
				num_ips++;
			}
		}

		/* 目的 IP 计数 */
		{
			int found = -1;
			for (int i = 0; i < num_d_ips; i++) {
				if (d_ips[i].ip == e->daddr) {
					found = i;
					break;
				}
			}
			if (found >= 0) {
				d_ips[found].count++;
			} else if (num_d_ips < MAX_IPS) {
				d_ips[num_d_ips].ip = e->daddr;
				d_ips[num_d_ips].count = 1;
				num_d_ips++;
			}
		}
	} else if (e->type == HTTP_RESPONSE) {
		total_responses++;
		if (e->status > 0 && e->status < 600)
			status_counts[e->status]++;
		resp_bytes += e->payload_len;

		/* 实时打印响应 */
		printf("[RSP] %s:%d -> %s:%d  HTTP/%u  (%u bytes)\n",
		       src_str, e->sport, dst_str, e->dport,
		       e->status, e->payload_len);
	}

	return 0;
}

static int cmp_path_entry(const void *a, const void *b)
{
	const struct path_entry *pa = a, *pb = b;
	if (pb->count > pa->count)
		return 1;
	if (pb->count < pa->count)
		return -1;
	return 0;
}

static int cmp_ip_entry(const void *a, const void *b)
{
	const struct ip_entry *pa = a, *pb = b;
	if (pb->count > pa->count)
		return 1;
	if (pb->count < pa->count)
		return -1;
	return 0;
}

static void print_report(void)
{
	printf("\n");
	printf("========================================\n");
	printf("     HTTP Traffic Statistics Report\n");
	printf("========================================\n");

	/* 方法分布 */
	printf("\n--- Method Distribution ---\n");
	for (int i = 0; i < HTTP_METHOD_COUNT; i++) {
		if (method_counts[i] > 0)
			printf("  %-8s %llu\n", http_method_names[i], method_counts[i]);
	}

	/* 状态码分布 */
	printf("\n--- Status Code Distribution ---\n");
	for (int i = 100; i < 600; i++) {
		if (status_counts[i] > 0)
			printf("  %d\t\t %llu\n", i, status_counts[i]);
	}

	/* 总计 */
	printf("\n--- Total ---\n");
	printf("  Requests:  %llu (%llu bytes)\n", total_requests, req_bytes);
	printf("  Responses: %llu (%llu bytes)\n", total_responses, resp_bytes);

	/* Top N 路径 */
	if (num_paths > 0) {
		qsort(paths, num_paths, sizeof(struct path_entry), cmp_path_entry);
		printf("\n--- Top %d Paths ---\n",
		       num_paths < TOP_N ? num_paths : TOP_N);
		int n = num_paths < TOP_N ? num_paths : TOP_N;
		for (int i = 0; i < n; i++)
			printf("  %-3d %-40s %llu\n", i + 1, paths[i].path, paths[i].count);
	}

	/* Top N 源 IP */
	if (num_ips > 0) {
		qsort(ips, num_ips, sizeof(struct ip_entry), cmp_ip_entry);
		printf("\n--- Top %d Source IPs ---\n",
		       num_ips < TOP_N ? num_ips : TOP_N);
		int n = num_ips < TOP_N ? num_ips : TOP_N;
		for (int i = 0; i < n; i++) {
			char str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &ips[i].ip, str, sizeof(str));
			printf("  %-3d %-20s %llu\n", i + 1, str, ips[i].count);
		}
	}

	/* Top N 目的 IP */
	if (num_d_ips > 0) {
		qsort(d_ips, num_d_ips, sizeof(struct ip_entry), cmp_ip_entry);
		printf("\n--- Top %d Destination IPs ---\n",
		       num_d_ips < TOP_N ? num_d_ips : TOP_N);
		int n = num_d_ips < TOP_N ? num_d_ips : TOP_N;
		for (int i = 0; i < n; i++) {
			char str[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &d_ips[i].ip, str, sizeof(str));
			printf("  %-3d %-20s %llu\n", i + 1, str, d_ips[i].count);
		}
	}

	printf("\n");
	fflush(stdout);
}

int main(int argc, char **argv)
{
	struct httpstat_bpf *skel;
	struct ring_buffer *rb = NULL;
	int sock = -1, err;
	const char *ifname = "lo";

	if (argc > 1)
		ifname = argv[1];

	setvbuf(stdout, NULL, _IONBF, 0);
	libbpf_set_print(libbpf_print_fn);

	struct sigaction sa = {};
	sa.sa_handler = sig_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGALRM, &sa, NULL);

	/* 定时报告 */
	alarm(REPORT_INTERVAL);

	skel = httpstat_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open/load skeleton\n");
		return 1;
	}

	sock = open_raw_sock(ifname);
	if (sock < 0) {
		err = 1;
		goto cleanup;
	}

	int prog_fd = bpf_program__fd(skel->progs.socket_handler);
	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0) {
		fprintf(stderr, "SO_ATTACH_BPF: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ring_buffer__new failed\n");
		err = 1;
		goto cleanup;
	}

	printf("httpstat: capturing HTTP on %s (Ctrl-C to stop, report every %ds)\n",
	       ifname, REPORT_INTERVAL);

	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err < 0 && errno != EINTR) {
			fprintf(stderr, "ring_buffer__poll: %s\n", strerror(errno));
			break;
		}

		if (report_flag) {
			report_flag = 0;
			print_report();
			alarm(REPORT_INTERVAL);
		}
	}

	print_report();

cleanup:
	if (rb)
		ring_buffer__free(rb);
	if (sock >= 0)
		close(sock);
	httpstat_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
