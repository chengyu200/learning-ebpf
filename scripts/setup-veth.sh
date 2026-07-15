#!/bin/bash
# Create a veth pair for safely testing the tc (20) and xdp (21) examples.
#
# vethbpf0 stays in the default netns; vethbpf1 moves into netns "bpfns". This
# guarantees real packet flow between the two ends (a same-host pair with two
# IPs can be defeated by the local routing table on some hosts).
#
# Usage: sudo ./scripts/setup-veth.sh [create|delete]
set -e

VETH0="${VETH0:-vethbpf0}"
VETH1="${VETH1:-vethbpf1}"
NS="${NS:-bpfns}"
CIDR="${CIDR:-192.168.99}"

cmd="${1:-create}"

case "$cmd" in
create)
	# Clean up any previous instance first.
	ip netns del "$NS" 2>/dev/null || true
	ip link del "$VETH0" 2>/dev/null || true

	ip link add "$VETH0" type veth peer name "$VETH1"
	ip link set "$VETH0" up
	ip addr add "$CIDR.1/24" dev "$VETH0" 2>/dev/null || true

	ip netns add "$NS"
	ip link set "$VETH1" netns "$NS"
	ip netns exec "$NS" ip link set lo up
	ip netns exec "$NS" ip link set "$VETH1" up
	ip netns exec "$NS" ip addr add "$CIDR.2/24" dev "$VETH1"

	echo "created: $VETH0 (default ns, $CIDR.1) <-> $VETH1 (netns $NS, $CIDR.2)"
	echo "test with: sudo ip netns exec $NS ping $CIDR.1"
	;;
delete)
	ip netns del "$NS" 2>/dev/null || true
	ip link del "$VETH0" 2>/dev/null || true
	echo "deleted: $VETH0 / $VETH1 (netns $NS)"
	;;
*)
	echo "usage: $0 [create|delete]" >&2
	exit 1
	;;
esac
