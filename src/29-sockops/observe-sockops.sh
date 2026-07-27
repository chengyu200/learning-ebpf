#!/usr/bin/env bash
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# observe-sockops.sh — 验证 29-sockops 的 sockmap 短路是否生效
#
# 三步验证:
#   1. 不挂 BPF:tcpdump 应抓到 HTTP 明文(基线)
#   2. 挂 BPF:tcpdump 应抓不到 HTTP 明文;trace_pipe 应出现 'sk_msg redir: ret=1'
#   3. bpftool 应只看到 1 个 sockhash(map 正确复用,而非 2 个)
#
# 用法: sudo ./src/29-sockops/observe-sockops.sh [port]   (默认 8080)

set -uo pipefail

PORT=${1:-8080}
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
APP="$(dirname "$0")/bpf_contrack"
TMP=$(mktemp -d)

cleanup() {
	[ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null || true
	[ -n "${BPF_PID:-}" ] && kill "$BPF_PID" 2>/dev/null || true
	rm -rf "$TMP"
}
trap cleanup EXIT

[ "$EUID" -eq 0 ] || { echo "需要 root,请用 sudo 运行"; exit 1; }
command -v tcpdump >/dev/null || { echo "需要 tcpdump"; exit 1; }
command -v bpftool >/dev/null || { echo "需要 bpftool"; exit 1; }

echo "================ 29-sockops 短路验证 (port=$PORT) ================"

echo "[1] 构建 bpf_contrack"
make -C "$REPO/src/29-sockops" -s || { echo "构建失败"; exit 1; }
[ -x "$APP" ] || { echo "二进制不存在: $APP"; exit 1; }

echo "[2] 启动本地 HTTP server (127.0.0.1:$PORT)"
python3 -m http.server "$PORT" >/dev/null 2>&1 &
SRV_PID=$!
sleep 1

# 跑一次 curl + tcpdump 抓包,返回包含 "HTTP/1" 的行数(≈数据包数)
run_curl_with_capture() {
	local pcap="$TMP/$1.pcap"
	timeout 6 tcpdump -i lo -A -nn -s 0 "tcp port $PORT" 2>/dev/null > "$pcap" &
	local tcpd=$!
	sleep 0.5
	curl -s "http://127.0.0.1:$PORT/" -o /dev/null 2>/dev/null || true
	wait "$tcpd" 2>/dev/null || true
	local n
	n=$(grep -c "HTTP/1" "$pcap" 2>/dev/null || true)
	echo "${n:-0}"
}

echo "[3] 基线(不挂 BPF)"
baseline=$(run_curl_with_capture baseline)
echo "    HTTP 明文行数: $baseline"

echo "[4] 挂载 BPF,重新抓包"
"$APP" >"$TMP/bpf.log" 2>&1 &
BPF_PID=$!
sleep 1.5

short=$(run_curl_with_capture short)
sleep 2  # 等 loader 读一轮 trace_pipe
echo "    HTTP 明文行数: $short"

echo "    trace_pipe 日志(bpf_printk):"
grep ">>>" "$TMP/bpf.log" 2>/dev/null | head -12 | sed 's/^/      /' || true

echo "[5] bpftool 检查 sockhash"
nmaps=$(bpftool map show 2>/dev/null | grep -c "sockhash" || true)
echo "    sockhash 数量: $nmaps (应为 1;若为 2 则 map 复用失败)"

echo "================ 结论 ================"
if [ "${baseline:-0}" -gt 0 ] && [ "${short:-0}" -eq 0 ]; then
	echo "PASS  短路生效:挂 BPF 后 HTTP 明文从 lo 消失"
elif [ "${baseline:-0}" -gt 0 ] && [ "${short:-0}" -gt 0 ]; then
	echo "FAIL  短路未生效:挂 BPF 后 lo 上仍有明文"
	echo "      检查 trace 是否有 'sk_msg redir: ret=1'(ret=0 表示 redirect 未命中)"
else
	echo "UNDECIDABLE  baseline=$baseline short=$short"
	echo "      可能 curl 失败或端口 $PORT 被占用"
fi
