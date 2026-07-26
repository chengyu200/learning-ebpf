#!/bin/bash
# 53-transparent-proxy-v2: 一键演示脚本
#
# 流程：
#   1. 编译 sidecar + server + external-server
#   2. 建 veth 对（vethbpf0 ↔ bpfns:192.168.99.2）
#   3. 启动 sidecar（root，自建 cgroup + 加载 BPF + listen :15006）
#   4. 启动 external-server 在 bpfns 内（:9090）
#   5. 启动 server（:8080），把 PID 传给 sidecar
#   6. curl 测试：入流量（/hello）+ 出流量（/outbound）
#   7. 清理
#
# Usage: sudo ./src/53-transparent-proxy-v2/run-demo.sh
set -u

TOP_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
EXE="$TOP_DIR/src/53-transparent-proxy-v2"
SCRIPTS="$TOP_DIR/scripts"

cleanup() {
	echo ""
	echo "==> 7. 清理"
	for pid in $(cat /sys/fs/cgroup/ebpf-proxy-demo/cgroup.procs 2>/dev/null); do
		echo $pid > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
	done
	[ -n "$SERVER_PID" ] && kill -9 "$SERVER_PID" 2>/dev/null || true
	[ -n "$SIDECAR_PID" ] && kill -9 "$SIDECAR_PID" 2>/dev/null || true
	[ -n "$EXT_PID" ] && kill -9 "$EXT_PID" 2>/dev/null || true
	sleep 1
	rmdir /sys/fs/cgroup/ebpf-proxy-demo 2>/dev/null || true
	# 不自动删除 veth（用户可能重复运行）
}
trap cleanup EXIT

echo "==> 1. 编译"
make -C "$EXE" 2>&1 | sed 's/^/    /'

echo "==> 2. 建 veth 对"
"$SCRIPTS/setup-veth.sh" create 2>&1 | sed 's/^/    /'
sleep 0.5

echo "==> 3. 启动 external-server（bpfns 内 :9090）"
ip netns exec bpfns "$EXE/external-server" &
EXT_PID=$!
sleep 0.5

echo "==> 4. 启动 server（:8080）"
"$EXE/server" &
SERVER_PID=$!
sleep 0.5

echo "==> 5. 启动 sidecar（cgroup + BPF + listen :15006）"
echo "    server_pid=$SERVER_PID"
"$EXE/sidecar" "$SERVER_PID" &
SIDECAR_PID=$!
sleep 1.5

if [ ! -d /sys/fs/cgroup/ebpf-proxy-demo ]; then
	echo "ERROR: sidecar 未成功创建 cgroup"
	exit 1
fi

echo "==> 6. 测试"
echo ""
echo "--- Test A: 入流量 curl http://127.0.0.1:8080/hello ---"
( echo $$ > /sys/fs/cgroup/ebpf-proxy-demo/cgroup.procs
  curl -sS --max-time 5 http://127.0.0.1:8080/hello
)
echo ""

echo ""
echo "--- Test B: 出流量 curl http://127.0.0.1:8080/outbound ---"
echo "    (server 内部 connect 192.168.99.2:9090 应被劫持到 sidecar)"
( echo $$ > /sys/fs/cgroup/ebpf-proxy-demo/cgroup.procs
  curl -sS --max-time 10 http://127.0.0.1:8080/outbound
)
echo ""

echo ""
echo "==> 演示完成，按 Ctrl-C 退出"
wait
