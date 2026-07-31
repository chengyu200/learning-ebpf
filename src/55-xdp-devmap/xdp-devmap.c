// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 55-xdp-devmap: user-space loader.
 *
 * Creates the network topology (via setup-devmap.sh), loads the BPF
 * object, populates DEVMAP entries with {ifindex, prog_fd}, attaches
 * the main XDP program to the external NIC, and prints stats on exit.
 *
 * Usage: sudo ./xdp-devmap [-m] [-i ext_if] [-o int_if]
 *   -m            mirror mode (default: forward mode)
 *   -i <ext_if>   external NIC (default: vethext0)
 *   -o <int_if>   internal NIC (default: vethint0)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if_link.h>
#include <linux/sockios.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "xdp-devmap.h"
#include "xdp-devmap.skel.h"

static volatile sig_atomic_t exiting;
static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

/* Get MAC address of a network interface */
/* Get MAC address of the peer of a veth pair.
 * For our topology, vethint0↔vethint1 where vethint1 is in netns "int".
 * We read it via /sys/class/net in the peer's netns. */
static int get_peer_mac_cross_ns(const char *peer_ifname, const char *peer_ns,
                                 __u8 mac[6])
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "ip netns exec %s cat /sys/class/net/%s/address 2>/dev/null",
             peer_ns, peer_ifname);
    FILE *p = popen(cmd, "r");
    if (!p)
        return -1;
    unsigned int m[6];
    int n = fscanf(p, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
    pclose(p);
    if (n != 6)
        return -1;
    for (int i = 0; i < 6; i++)
        mac[i] = (__u8)m[i];
    return 0;
}

static int get_if_mac(const char *ifname, __u8 mac[6])
{
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

static void print_stats(struct xdp_devmap_bpf *skel)
{
    __u32 keys[2] = { STAT_FORWARD, STAT_MIRROR };
    const char *labels[2] = { "forwarded", "mirrored" };

    for (int i = 0; i < 2; i++) {
        int map_fd = bpf_map__fd(skel->maps.stats_map);
        int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        if (ncpu < 1) ncpu = 1;

        struct stats *vals = calloc(ncpu, sizeof(struct stats));
        if (!vals) continue;

        if (bpf_map_lookup_elem(map_fd, &keys[i], vals) == 0) {
            __u64 total_pkts = 0, total_bytes = 0;
            for (int c = 0; c < ncpu; c++) {
                total_pkts += vals[c].pkts;
                total_bytes += vals[c].bytes;
            }
            if (total_pkts > 0)
                printf("  %-10s: %llu pkts, %llu bytes\n",
                       labels[i],
                       (unsigned long long)total_pkts,
                       (unsigned long long)total_bytes);
        }
        free(vals);
    }
}

int main(int argc, char **argv)
{
    struct xdp_devmap_bpf *skel;
    const char *ext_if = "vethext0";
    const char *int_if = "vethint0";
    bool mirror = false;
    int opt, err, ext_ifindex, int_ifindex;

    while ((opt = getopt(argc, argv, "mi:o:")) != -1) {
        switch (opt) {
        case 'm': mirror = true; break;
        case 'i': ext_if = optarg; break;
        case 'o': int_if = optarg; break;
        default:
            fprintf(stderr, "Usage: %s [-m] [-i ext_if] [-o int_if]\n", argv[0]);
            return 1;
        }
    }

    ext_ifindex = if_nametoindex(ext_if);
    int_ifindex = if_nametoindex(int_if);
    if (!ext_ifindex || !int_ifindex) {
        fprintf(stderr, "interface not found (ext=%s int=%s)\n", ext_if, int_if);
        fprintf(stderr, "run setup-devmap.sh create first\n");
        return 1;
    }

    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* ── 1. Load BPF skeleton ── */
    skel = xdp_devmap_bpf__open();
    if (!skel) {
        fprintf(stderr, "open skeleton failed\n");
        return 1;
    }

    /* Set rodata config */
    skel->rodata->mirror_mode = mirror;
    if (!mirror) {
        /* Forward mode: target 10.0.2.0/24 (network byte order) */
        struct in_addr net;
        inet_pton(AF_INET, "10.0.2.0", &net);
        skel->rodata->target_prefix = net.s_addr;
        skel->rodata->target_mask   = htonl(0xFFFFFF00); /* /24 */
    }

    err = xdp_devmap_bpf__load(skel);
    if (err) {
        fprintf(stderr, "load skeleton failed: %s\n", strerror(-err));
        goto cleanup;
    }

    /* ── 2. Fill MAC config map ──
     * src_mac = internal NIC MAC (egress source)
     * dst_mac = peer of internal NIC (internal service MAC) */
    {
        __u8 src_mac[6], dst_mac[6];
        if (get_if_mac(int_if, src_mac) < 0) {
            fprintf(stderr, "get MAC of %s failed\n", int_if);
            goto cleanup;
        }
        /* Read peer MAC from netns "int" (vethint1's real MAC) */
        if (get_peer_mac_cross_ns("vethint1", "int", dst_mac) < 0) {
            fprintf(stderr, "warning: could not read vethint1 MAC, using broadcast\n");
            memset(dst_mac, 0xff, 6);
        }

        __u32 zero = 0;
        struct mac_config mc;
        memcpy(mc.src_mac, src_mac, 6);
        memcpy(mc.dst_mac, dst_mac, 6);
        bpf_map_update_elem(bpf_map__fd(skel->maps.mac_map),
                            &zero, &mc, BPF_ANY);
        printf("[config] %s src_mac=%02x:%02x:%02x:%02x:%02x:%02x\n", int_if,
               src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
    }

    /* ── 3. Fill DEVMAP entries with {ifindex, prog_fd} ── */
    {
        int egress_fd = bpf_program__fd(skel->progs.xdp_egress);
        if (egress_fd < 0) {
            fprintf(stderr, "get xdp_egress fd failed\n");
            goto cleanup;
        }

        struct bpf_devmap_val val = {
            .ifindex = int_ifindex,
            .bpf_prog.fd = egress_fd,
        };
        __u32 key = 0;

        if (bpf_map_update_elem(bpf_map__fd(skel->maps.forward_map),
                                &key, &val, BPF_ANY) < 0) {
            fprintf(stderr, "forward_map update: %s\n", strerror(errno));
            goto cleanup;
        }
        if (bpf_map_update_elem(bpf_map__fd(skel->maps.mirror_map),
                                &key, &val, BPF_ANY) < 0) {
            fprintf(stderr, "mirror_map update: %s\n", strerror(errno));
            goto cleanup;
        }
        printf("[config] DEVMAP[0] → ifindex=%d (%s) + egress prog fd=%d\n",
               int_ifindex, int_if, egress_fd);
    }

    /* ── 4. Attach main XDP program to external NIC ── */
    {
        int prog_fd = bpf_program__fd(skel->progs.xdp_ingress);
        err = bpf_xdp_attach(ext_ifindex, prog_fd, XDP_FLAGS_SKB_MODE, NULL);
        if (err) {
            fprintf(stderr, "xdp attach to %s: %s\n", ext_if, strerror(-err));
            goto cleanup;
        }
    }

    printf("\n%s mode on %s → %s. Ctrl-C to stop.\n",
           mirror ? "MIRROR" : "FORWARD", ext_if, int_if);
    if (mirror) {
        printf("All IPv4 pkts on %s will be broadcast to %s\n", ext_if, int_if);
    } else {
        printf("Pkts to 10.0.2.0/24 on %s will be forwarded to %s\n", ext_if, int_if);
    }
    printf("Test: ip netns exec ext ping 10.0.2.2\n");
    printf("      ip netns exec int tcpdump -i vethint1 -n\n\n");

    while (!exiting)
        sleep(1);

    /* ── 5. Print stats ── */
    printf("\n=== Stats ===\n");
    print_stats(skel);

    /* ── 6. Detach XDP ── */
    bpf_xdp_detach(ext_ifindex, XDP_FLAGS_SKB_MODE, NULL);
    printf("XDP detached from %s\n", ext_if);

cleanup:
    xdp_devmap_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
