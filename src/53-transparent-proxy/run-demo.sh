#!/bin/bash
# 53-transparent-proxy: 一键演示脚本
#
# 流程：
#   1. 编译 sidecar + server
#   2. 启动 sidecar（root，自建 cgroup + 加载 BPF + listen :15006）
#   3. 将当前 shell 移入 cgroup（使其 connect() 被 BPF 拦截）
#   4. 后台启动 server（:8080）
#   5. curl http://127.0.0.1:8080/hello 触发劫持
#   6. 退出时清理：kill 进程 + 移出 cgroup + rmdir cgroup
#
# Usage: sudo ./src/53-transparent-proxy/run-demo.sh
set -e

TOP_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
EXE_DIR="$TOP_DIR/src/53-transparent-proxy"

echo "==> 1. 编译"
make -C "$EXE_DIR" 2>&1 | sed 's/^/    /'

SIDECAR_PID=""
SERVER_PID=""

cleanup() {
	echo ""
	echo "==> 6. 清理"
	# 先把 shell 移出 cgroup
	if [ -w /sys/fs/cgroup/cgroup.procs ]; then
		echo $$ > /sys/fs/cgroup/cgroup.procs 2>/dev/null || true
	fi
	[ -n "$SERVER_PID" ] && kill -9 "$SERVER_PID" 2>/dev/null || true
	[ -n "$SIDECAR_PID" ] && kill -9 "$SIDECAR_PID" 2>/dev/null || true
	sleep 0.5
	# sidecar 退出时会 rmdir cgroup，这里兜底
	rmdir /sys/fs/cgroup/ebpf-proxy-demo 2>/dev/null || true
	echo "    done"
}
trap cleanup EXIT

echo "==> 2. 启动 sidecar（cgroup + BPF + listen :15006）"
"$EXE_DIR/sidecar" &
SIDECAR_PID=$!
sleep 1

if [ ! -d /sys/fs/cgroup/ebpf-proxy-demo ]; then
	echo "ERROR: sidecar 未成功创建 cgroup"
	exit 1
fi

echo "==> 3. 将当前 shell (PID=$$) 移入 cgroup"
echo $$ > /sys/fs/cgroup/ebpf-proxy-demo/cgroup.procs
echo "    当前 cgroup: $(cat /proc/self/cgroup | grep -o 'ebpf-proxy-demo')"

echo "==> 4. 启动 server（:8080）"
"$EXE_DIR/server" &
SERVER_PID=$!
sleep 0.5

echo "==> 5. 测试 curl http://127.0.0.1:8080/hello"
echo "    （预期：sidecar 日志显示劫持，curl 收到 server 响应）"
echo ""
sleep 0.5
curl -sS http://127.0.0.1:8080/hello || true
echo ""

echo ""
echo "==> 再测一次（不同 path）"
curl -sS http://127.0.0.1:8080/transparent-proxy/test || true
echo ""

echo ""
echo "==> 验证：宿主其他进程（不在 cgroup）直连 server 不被劫持"
echo "    （以下用 ip netns exec 在默认 ns 跑，但 PID 不在 cgroup 内）"
# 注意：curl 由本脚本启动会继承 cgroup 成员身份，这里用 -- 另起一个
# 真正的「非 cgroup」测试需另开终端。此处仅演示。
echo "    若需严格验证，请另开终端 curl 127.0.0.1:8080"

echo ""
echo "==> 演示完成，按 Ctrl-C 退出（将自动清理）"
wait
