// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
/*
 * 23-http: 用户态加载器
 *
 * 本程序创建一个 raw packet socket（AF_PACKET），绑定到指定网卡，
 * 将 BPF socket filter 程序通过 SO_ATTACH_BPF 挂载到该 socket，
 * 然后轮询 ring buffer 接收并打印内核态捕获的 TCP/HTTP 事件。
 *
 * 教学概念：
 * - AF_PACKET raw socket：抓取链路层所有包
 * - SO_ATTACH_BPF：将 BPF 程序挂到 socket 上做过滤
 * - ring_buffer__poll：从 ring buffer 读取内核态事件
 *
 * 编译：make -C src/23-http
 * 运行：sudo ./src/23-http/http -i lo
 *       另开终端：curl http://127.0.0.1:8080/
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

/* ── 命令行参数 ── */
static struct env {
	char ifname[IF_NAMESIZE];  /* 绑定的网卡名，默认 "lo"（回环） */
	bool verbose;              /* 是否打印 libbpf 调试日志 */
} env = { .ifname = "lo", .verbose = false };

const char *argp_program_version = "http 0.1";
const char argp_program_doc[] =
"Capture TCP/IPv4 packets (incl. HTTP request line) via a socket filter.\n\n"
"USAGE: ./http [--if IFNAME] [-v]\n";

static const struct argp_option opts[] = {
	{ "if",      'i', "IFNAME", 0, "Interface to bind (default lo)" },
	{ "verbose", 'v', NULL,     0, "Verbose libbpf debug output" },
	{},
};

/*
 * 命令行参数解析回调。
 * argp 会对每个选项和位置参数调用此函数。
 */
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'i': strncpy(env.ifname, arg, sizeof(env.ifname) - 1); break;
	case 'v': env.verbose = true; break;
	case ARGP_KEY_ARG:
		/* 位置参数（如 ./http lo）也作为网卡名 */
		if (state->arg_num == 0)
			strncpy(env.ifname, arg, sizeof(env.ifname) - 1);
		else
			argp_usage(state);
		break;
	default: return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = { .options = opts, .parser = parse_arg,
				  .args_doc = "[IFNAME]",
				  .doc = argp_program_doc };

/* ── 信号处理 ── */
static volatile sig_atomic_t exiting;
static void sig_handler(int sig) { exiting = 1; }

/*
 * libbpf 日志回调：控制 libbpf 的输出级别。
 * DEBUG 级别只在 --verbose 时打印，避免正常使用时刷屏。
 */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

/*
 * 创建 raw packet socket 并绑定到指定网卡。
 *
 * PF_PACKET + SOCK_RAW：工作在链路层，抓取包含以太网头的完整帧。
 * ETH_P_ALL：捕获所有协议类型的包。
 *
 * @name  网卡名（如 "lo", "eth0"）
 * @return 成功返回 socket fd，失败返回 -1
 */
static int open_raw_sock(const char *name)
{
	struct sockaddr_ll sll;
	int sock;

	/* 创建 raw socket
	 * SOCK_NONBLOCK: 非阻塞模式（配合 ring_buffer__poll 使用）
	 * SOCK_CLOEXEC:  exec 时自动关闭 fd */
	sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
		      htons(ETH_P_ALL));
	if (sock < 0) {
		fprintf(stderr, "Failed to create raw socket\n");
		return -1;
	}

	/* 绑定到指定网卡：只有该网卡的包才会被捕获 */
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex(name);  /* 网卡名 → 索引号 */
	sll.sll_protocol = htons(ETH_P_ALL);     /* 捕获所有协议 */
	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		fprintf(stderr, "Failed to bind to %s: %s\n", name, strerror(errno));
		close(sock);
		return -1;
	}
	return sock;
}

/*
 * 将 32 位整数格式的 IPv4 地址转为点分十进制字符串。
 * 例如：0x0100007F → "127.0.0.1"
 */
static void ltoa(uint32_t addr, char *dst)
{
	snprintf(dst, 16, "%u.%u.%u.%u",
		 (addr >> 24) & 0xFF,  /* 最高字节 */
		 (addr >> 16) & 0xFF,
		 (addr >> 8)  & 0xFF,
		 (addr)       & 0xFF);  /* 最低字节 */
}

/*
 * ring buffer 事件回调：每收到一个事件调用一次。
 * 解析事件中的地址、端口、payload 并打印。
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct so_event *e = data;
	char ifname[IF_NAMESIZE];
	char sstr[16] = {}, dstr[16] = {};

	/* 只显示发给本机的包（PACKET_HOST=0）
	 * PACKET_OUTGOING(4) 是本机发出的包，也可根据需要保留 */
	if (e->pkt_type != PACKET_HOST)
		return 0;

	/* IP 地址从网络字节序转主机字节序后转为字符串 */
	ltoa(ntohl(e->src_addr), sstr);
	ltoa(ntohl(e->dst_addr), dstr);

	/* 网卡索引转网卡名 */
	if (!if_indextoname(e->ifindex, ifname))
		strncpy(ifname, "?", sizeof(ifname));

	/* 只显示 TCP 包 */
	if (e->ip_proto != 6)
		return 0;

	/* 打印：网卡 源IP:端口 → 目的IP:端口  payload 内容 */
	printf("%-7s %s:%d -> %s:%d  proto=%d payload(%u): ",
	       ifname, sstr, ntohs(e->port16[0]), dstr, ntohs(e->port16[1]),
	       e->ip_proto, e->payload_length);

	/* 打印 payload（HTTP 请求行/响应头等） */
	if (e->payload_length > 0) {
		fwrite(e->payload, 1,
		       e->payload_length < MAX_BUF_SIZE ? e->payload_length : MAX_BUF_SIZE,
		       stdout);
	}
	printf("\n");
	return 0;
}

/*
 * 主函数：加载 BPF 程序 → 创建 raw socket → 挂载 filter → 轮询事件
 */
int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct http_bpf *skel;
	int sock = -1, err;

	/* 解析命令行参数 */
	argp_parse(&argp, argc, argv, 0, NULL, NULL);

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* ── 第 1 步：加载 BPF 骨架 ──
	 * open_and_load = open + load + map_create 一步到位
	 * 骨架中包含编译好的 socket_handler 程序和 ring buffer map */
	skel = http_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* ── 第 2 步：创建 raw socket 并绑定到网卡 ── */
	sock = open_raw_sock(env.ifname);
	if (sock < 0) {
		err = -errno;
		goto cleanup;
	}

	/* ── 第 3 步：将 BPF 程序挂载到 socket ──
	 * SO_ATTACH_BPF：把 BPF 程序的 fd 附加到 socket，
	 * 之后每个经过该 socket 的包都会触发 BPF 程序执行。
	 * 注意：这里传的是 prog_fd（程序文件描述符），不是 link */
	{
		int prog_fd = bpf_program__fd(skel->progs.socket_handler);
		err = setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF,
				 &prog_fd, sizeof(prog_fd));
	}
	if (err) {
		fprintf(stderr, "SO_ATTACH_BPF failed: %s\n", strerror(errno));
		err = -errno;
		goto cleanup;
	}

	/* ── 第 4 步：创建 ring buffer 并注册回调 ──
	 * ring buffer 是内核与用户态之间的共享内存环形缓冲区，
	 * 内核态 bpf_ringbuf_submit 的事件会在此被读取并调用 handle_event */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* ── 第 5 步：主循环 ── 轮询 ring buffer，100ms 超时 */
	printf("Listening on %s... Ctrl-C to stop.\n", env.ifname);
	printf("%-7s %-22s %s\n", "IF", "SRC -> DST", "PAYLOAD");

	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		if (err == -EINTR) { err = 0; break; }  /* Ctrl-C */
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
