#!/bin/bash
# 53-transparent-proxy-v4: 一键演示脚本
#
# v4 关键改进：端口一致（server 监听 0.0.0.0:8080，与用户访问端口相同）。
#   防回环由 sk_lookup 中的 PID 排除实现。
#
# 流程：
#   1. 编译
#   2. 建 veth 对（vethbpf0 ↔ bpfns:192.168.99.2）
#   3. 启动 external-server 在 bpfns 内
#   4. 启动 server（0.0.0.0:8080），把 PID 传给 sidecar
#   5. 启动 sidecar（cgroup + BPF + listen :15006）
#   6. curl 测试（无需 echo $$ > cgroup.procs！）
#   7. 清理
#
# Usage: sudo ./src/53-transparent-proxy-v4/run-demo.sh
set -u

TOP_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
EXE="$TOP_DIR/src/53-transparent-proxy-v4"
SCRIPTS="$TOP_DIR/scripts"

SIDECAR_PID=""
SERVER_PID=""
EXT_PID=""

cleanup() {
	echo ""
	echo "==> 7. 清理"
	for pid in $(cat /sys/fs/cgroup/ebpf-proxy-demo/cgroup.procs 2>/dev/null); do
		echo $pid > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
	done
	[ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
	[ -n "$SIDECAR_PID" ] && kill "$SIDECAR_PID" 2>/dev/null || true
	[ -n "$EXT_PID" ] && kill "$EXT_PID" 2>/dev/null || true
	sleep 1
	rmdir /sys/fs/cgroup/ebpf-proxy-demo 2>/dev/null || true
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

echo "==> 4. 启动 server（:9000）"
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

echo ""
echo "==> 6. 测试（client 无需加入 cgroup！）"
echo ""
echo "--- Test A: 入流量 curl 127.0.0.1:8080/hello（sk_lookup 拦截） ---"
curl -sS --max-time 5 http://127.0.0.1:8080/hello
echo ""

echo ""
echo "--- Test B: 入流量 curl 127.0.0.1:8080/another（再次验证） ---"
curl -sS --max-time 5 http://127.0.0.1:8080/another
echo ""

echo ""
echo "--- Test C: 出流量 curl 127.0.0.1:8080/outbound（server 出连接被劫持） ---"
curl -sS --max-time 10 http://127.0.0.1:8080/outbound
echo ""

echo ""
echo "==> 演示完成，按 Ctrl-C 退出"
wait
