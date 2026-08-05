// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * 67-fmod-ret: 用户态加载器。
 *
 * 加载 fmod_ret BPF 程序，设置目标 PID 和错误码，
 * 在 read() 系统调用上注入错误。
 *
 * 用法：
 *   sudo ./fmod-ret --pid <PID> [--errno <ERRNO>]
 *
 * 示例：
 *   sudo ./fmod-ret --pid $(pgrep bash) --errno -12   # 注入 -ENOMEM
 *   sudo ./fmod-ret --pid $(pgrep bash) --errno -1     # 注入 -EPERM
 *   sudo ./fmod-ret --pid 0 --errno -12                 # 所有进程（危险！）
 *
 * 测试：
 *   # 在被注入的 bash 中：
 *   cat /etc/hostname
 *   # → cat: read error: Cannot allocate memory
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <argp.h>
#include <bpf/libbpf.h>
#include "fmod-ret.h"
#include "fmod-ret.skel.h"

static struct env {
	pid_t pid;       /* 目标进程 PID（必须指定，-1 = 未设置） */
	int errno_val;   /* 注入的错误码（默认 -12 = ENOMEM） */
	bool verbose;
} env = { .pid = -1, .errno_val = -12, .verbose = false };

const char *argp_program_version = "fmod-ret 0.1";
const char argp_program_doc[] =
"Inject errors into read() via BPF_MODIFY_RETURN.\n\n"
"USAGE: ./fmod-ret --pid <PID> [--errno <ERRNO>] [-v]\n"
"  --pid is required. 0 = all processes (dangerous!)\n"
"  --errno: -12=ENOMEM, -1=EPERM, -13=EACCES, -5=EIO, etc.\n";

static const struct argp_option opts[] = {
	{ "pid",    'p', "PID",    0, "Target process PID (required, 0 = all)" },
	{ "errno",  'e', "ERRNO",  0, "Error code to inject (default: -12 = -ENOMEM)" },
	{ "verbose",'v', NULL,     0, "Verbose libbpf debug output" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'p': env.pid = atoi(arg); break;
	case 'e': env.errno_val = atoi(arg); break;
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

static const char *errno_name(int err)
{
	switch (err) {
	case -1:  return "EPERM";
	case -2:  return "ENOENT";
	case -5:  return "EIO";
	case -12: return "ENOMEM";
	case -13: return "EACCES";
	case -22: return "EINVAL";
	case -38: return "ENOSYS";
	default:  return "?";
	}
}

int main(int argc, char **argv)
{
	struct fmod_ret_bpf *skel;
	int err = 0;

	argp_parse(&argp, argc, argv, 0, NULL, NULL);

	/* --pid 是必填参数 */
	if (env.pid < 0) {
		fprintf(stderr, "Error: --pid is required.\n");
		fprintf(stderr, "Usage: %s --pid <PID> [--errno <ERRNO>] [-v]\n", argv[0]);
		fprintf(stderr, "  --pid 0 means all processes (dangerous!)\n");
		return 1;
	}

	setvbuf(stdout, NULL, _IONBF, 0);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	libbpf_set_print(libbpf_print_fn);

	skel = fmod_ret_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* 设置注入参数 */
	skel->rodata->target_pid = env.pid;
	skel->rodata->inject_errno = env.errno_val;

	err = fmod_ret_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
		goto cleanup;
	}

	err = fmod_ret_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach: %d\n", err);
		goto cleanup;
	}

	printf("═══════════════════════════════════════════════════════\n");
	printf("  BPF_MODIFY_RETURN error injection\n");
	printf("═══════════════════════════════════════════════════════\n");
	printf("  Target:  %s", env.pid ? "" : "ALL processes");
	if (env.pid)
		printf("PID %d", env.pid);
	printf("\n");
	printf("  Inject:  %d (%s) into read()\n", env.errno_val, errno_name(env.errno_val));
	printf("═══════════════════════════════════════════════════════\n");
	printf("\n");
	printf("Test in %s terminal:\n", env.pid ? "the target process's" : "another");
	printf("  cat /etc/hostname\n");
	printf("  → should get: %s\n\n", strerror(-env.errno_val));
	printf("Press Ctrl-C to stop.\n\n");

	while (!exiting)
		sleep(1);

cleanup:
	fmod_ret_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}
