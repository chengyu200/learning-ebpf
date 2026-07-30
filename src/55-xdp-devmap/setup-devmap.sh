#!/bin/bash
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#
# setup-devmap.sh: create/delete the network topology for 55-xdp-devmap.
#
# Creates two veth pairs across three namespaces:
#
#   Netns "ext" (external client)     Default ns (router + XDP)      Netns "int" (internal server)
#   vethext1 10.0.1.2  ←─pair─→  vethext0 10.0.1.1                  vethint1 10.0.2.2
#                                                                     ←─pair─→  vethint0 10.0.2.1
#
# Route in "ext": 10.0.2.0/24 via 10.0.1.1
#
# Usage: sudo ./setup-devmap.sh [create|delete]
set -e

VEXT0="vethext0"
VEXT1="vethext1"
VINT0="vethint0"
VINT1="vethint1"
NS_EXT="ext"
NS_INT="int"

cmd="${1:-create}"

case "$cmd" in
create)
    # Clean up any previous instance
    ip netns del "$NS_EXT" 2>/dev/null || true
    ip netns del "$NS_INT" 2>/dev/null || true
    ip link del "$VEXT0" 2>/dev/null || true
    ip link del "$VINT0" 2>/dev/null || true

    # External pair: vethext0 (default ns) ↔ vethext1 (netns ext)
    ip link add "$VEXT0" type veth peer name "$VEXT1"
    ip link set "$VEXT0" up
    ip addr add 10.0.1.1/24 dev "$VEXT0" 2>/dev/null || true

    ip netns add "$NS_EXT"
    ip link set "$VEXT1" netns "$NS_EXT"
    ip netns exec "$NS_EXT" ip link set lo up
    ip netns exec "$NS_EXT" ip link set "$VEXT1" up
    ip netns exec "$NS_EXT" ip addr add 10.0.1.2/24 dev "$VEXT1"
    # Route: internal subnet via router
    ip netns exec "$NS_EXT" ip route add 10.0.2.0/24 via 10.0.1.1 dev "$VEXT1"

    # Internal pair: vethint0 (default ns) ↔ vethint1 (netns int)
    ip link add "$VINT0" type veth peer name "$VINT1"
    ip link set "$VINT0" up
    ip addr add 10.0.2.1/24 dev "$VINT0" 2>/dev/null || true

    ip netns add "$NS_INT"
    ip link set "$VINT1" netns "$NS_INT"
    ip netns exec "$NS_INT" ip link set lo up
    ip netns exec "$NS_INT" ip link set "$VINT1" up
    ip netns exec "$NS_INT" ip addr add 10.0.2.2/24 dev "$VINT1"
    # Route: return path to external subnet via router
    ip netns exec "$NS_INT" ip route add 10.0.1.0/24 via 10.0.2.1 dev "$VINT1"

    # Enable IP forwarding in default ns (router)
    sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1 || true

    echo "created:"
    echo "  $VEXT0 (default ns, 10.0.1.1) ↔ $VEXT1 ($NS_EXT, 10.0.1.2)"
    echo "  $VINT0 (default ns, 10.0.2.1) ↔ $VINT1 ($NS_INT, 10.0.2.2)"
    echo "  route in $NS_EXT: 10.0.2.0/24 via 10.0.1.1"
    echo ""
    echo "test:"
    echo "  ip netns exec $NS_EXT ping 10.0.2.2"
    echo "  ip netns exec $NS_INT tcpdump -i $VINT1 -n"
    ;;

delete)
    ip netns del "$NS_EXT" 2>/dev/null || true
    ip netns del "$NS_INT" 2>/dev/null || true
    ip link del "$VEXT0" 2>/dev/null || true
    ip link del "$VINT0" 2>/dev/null || true
    echo "deleted: $VEXT0/$VEXT1, $VINT0/$VINT1, netns $NS_EXT/$NS_INT"
    ;;

*)
    echo "usage: $0 [create|delete]" >&2
    exit 1
    ;;
esac
