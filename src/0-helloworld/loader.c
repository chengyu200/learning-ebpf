#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <fcntl.h>



/* Copy whatever the kernel wrote to the trace pipe to stdout. */
static void read_trace_pipe(void)
{
	char buf[4096];
	int fd;
	ssize_t n;

	fd = open("/sys/kernel/tracing/trace_pipe", O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		return;

	while ((n = read(fd, buf, sizeof(buf))) > 0)
		fwrite(buf, 1, n, stdout);
	close(fd);
}

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int prog_fd;
    int err;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <bpf_object.o>\n", argv[0]);
        return 1;
    }

    // 打开BPF对象文件
    obj = bpf_object__open(argv[1]);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object: %s\n", argv[1]);
        return 1;
    }

    // 加载BPF对象到内核
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    // 获取第一个BPF程序
    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        fprintf(stderr, "No BPF program found in object\n");
        goto cleanup;
    }

    // 自动attach程序（适用于带有SEC()宏定义的程序）
    link = bpf_program__attach(prog);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "Failed to attach BPF program\n");
        goto cleanup;
    }

    prog_fd = bpf_program__fd(prog);
    printf("BPF program loaded successfully!\n");
    printf("Program FD: %d\n", prog_fd);
    printf("Press Ctrl+C to exit...\n");

    // 保持程序运行，否则detach后eBPF程序会被卸载
    while (1) {
	read_trace_pipe();
	sleep(1);
    }

cleanup:
    bpf_object__close(obj);
    return err;
}

