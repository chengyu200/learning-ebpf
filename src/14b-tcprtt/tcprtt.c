// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* 14b-tcprtt: user-space loader and histogram printer.
 *
 * Loads the BPF program, polls the hists hash map at intervals (or on
 * Ctrl-C), and prints a log2 histogram of TCP smoothed RTT.
 */
#include <argp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tcprtt.h"
#include "tcprtt.skel.h"

static struct env {
    int interval;
    int duration;
    bool timestamp;
    bool milliseconds;
    __u16 lport;
    __u16 rport;
    __u32 laddr;
    __u32 raddr;
    bool filter_lport;
    bool filter_rport;
    bool filter_laddr;
    bool filter_raddr;
    bool byladdr;
    bool byraddr;
    bool extension;
    bool ipv4;
    bool ipv6;
    bool verbose;
} env;

const char *argp_program_version = "tcprtt 0.1";
const char argp_program_doc[] =
"Summarize TCP smoothed RTT as a log2 histogram.\n"
"\n"
"USAGE: ./tcprtt [-i INTERVAL] [-m] [-T] [-p LPORT] [-P RPORT] "
"[-b] [-B] [-e] [-4|-6]\n"
"\n"
"EXAMPLES:\n"
"    ./tcprtt                  # trace until Ctrl-C\n"
"    ./tcprtt -i 1 -d 10      # 1s intervals, 10 times\n"
"    ./tcprtt -m -T            # milliseconds + timestamps\n"
"    ./tcprtt -p 80            # filter local port 80\n"
"    ./tcprtt -B              # histogram by remote address\n"
"    ./tcprtt -e              # show average RTT\n";

static const struct argp_option opts[] = {
    { "interval",   'i', "SEC",  0, "Summary interval, seconds" },
    { "duration",   'd', "SEC",  0, "Total duration, seconds (default 99999)" },
    { "timestamp",  'T', NULL,   0, "Include timestamp on output" },
    { "milliseconds",'m', NULL, 0, "Millisecond histogram (default: microseconds)" },
    { "lport",      'p', "PORT", 0, "Filter local port" },
    { "rport",      'P', "PORT", 0, "Filter remote port" },
    { "laddr",      'a', "ADDR", 0, "Filter local address" },
    { "raddr",      'A', "ADDR", 0, "Filter remote address" },
    { "byladdr",    'b', NULL,   0, "Histogram by local address" },
    { "byraddr",    'B', NULL,   0, "Histogram by remote address" },
    { "extension",  'e', NULL,   0, "Show average RTT" },
    { "ipv4",       '4', NULL,   0, "Trace IPv4 only" },
    { "ipv6",       '6', NULL,   0, "Trace IPv6 only" },
    { "verbose",    'v', NULL,   0, "Verbose libbpf debug" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'i':
        env.interval = atoi(arg);
        break;
    case 'd':
        env.duration = atoi(arg);
        break;
    case 'T':
        env.timestamp = true;
        break;
    case 'm':
        env.milliseconds = true;
        break;
    case 'p':
        env.lport = atoi(arg);
        env.filter_lport = true;
        break;
    case 'P':
        env.rport = atoi(arg);
        env.filter_rport = true;
        break;
    case 'a': {
        struct in_addr a;
        if (!inet_pton(AF_INET, arg, &a)) {
            fprintf(stderr, "bad local address: %s\n", arg);
            return ARGP_ERR_UNKNOWN;
        }
        env.laddr = a.s_addr;   /* network byte order */
        env.filter_laddr = true;
        break;
    }
    case 'A': {
        struct in_addr a;
        if (!inet_pton(AF_INET, arg, &a)) {
            fprintf(stderr, "bad remote address: %s\n", arg);
            return ARGP_ERR_UNKNOWN;
        }
        env.raddr = a.s_addr;
        env.filter_raddr = true;
        break;
    }
    case 'b':
        env.byladdr = true;
        break;
    case 'B':
        env.byraddr = true;
        break;
    case 'e':
        env.extension = true;
        break;
    case '4':
        env.ipv4 = true;
        break;
    case '6':
        env.ipv6 = true;
        break;
    case 'v':
        env.verbose = true;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

static volatile sig_atomic_t exiting;
static void sig_handler(int sig) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt, va_list args)
{
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, fmt, args);
}

/* ── Histogram printing ── */

static void print_hist_section(struct hist *h, const char *unit, const char *sec_label)
{
    __u64 max_val = 0;
    int max_slot = -1;
    int i, j;

    for (i = 0; i < MAX_SLOTS; i++) {
        if (h->slots[i] > max_val)
            max_val = h->slots[i];
        if (h->slots[i] > 0)
            max_slot = i;
    }

    if (max_slot < 0) {
        printf("%-22s : no samples\n", sec_label);
        return;
    }

    if (env.extension && h->cnt > 0)
        printf("%-22s [AVG %llu %s]\n", sec_label,
               (unsigned long long)(h->latency / h->cnt), unit);
    else
        printf("%s\n", sec_label);

    printf("%12s %-12s : %-8s |%-s\n", "", unit, "count", "distribution");

    for (i = 0; i <= max_slot; i++) {
        __u64 lo, hi;
        int stars;
        double pct;

        if (i == 0) {
            lo = 0;
            hi = 1;
        } else {
            lo = 1ULL << i;
            hi = (1ULL << (i + 1)) - 1;
        }

        pct = max_val ? (100.0 * h->slots[i] / max_val) : 0.0;
        printf("%12llu -> %-8llu : %-8llu |",
               (unsigned long long)lo, (unsigned long long)hi,
               (unsigned long long)h->slots[i]);
        stars = (int)(pct / 2.5);
        for (j = 0; j < stars && j < 40; j++)
            printf("*");
        printf("\n");
    }
}

static void print_and_clear_hist(struct tcprtt_bpf *skel)
{
    __u64 *keys = NULL;
    struct hist *hists = NULL;
    int map_fd, count = 0, i;
    __u64 next_key;
    __u64 cur_key;
    char addrstr[INET_ADDRSTRLEN];
    const char *unit = env.milliseconds ? "msecs" : "usecs";

    map_fd = bpf_map__fd(skel->maps.hists);

    /* Iterate all keys in the hash map */
    /* First pass: count entries. Use NULL to get the very first key. */
    __u64 *prev_key = NULL;
    for (;;) {
        int ret = bpf_map_get_next_key(map_fd, prev_key, &next_key);
        if (ret)
            break;
        prev_key = &cur_key;
        cur_key = next_key;
        count++;
    }

    if (count == 0) {
        printf("\nNo samples collected.\n");
        return;
    }

    keys = calloc(count, sizeof(__u64));
    hists = calloc(count, sizeof(struct hist));
    if (!keys || !hists) {
        fprintf(stderr, "out of memory\n");
        free(keys);
        free(hists);
        return;
    }

    /* Second pass: collect all keys and values */
    prev_key = NULL;
    i = 0;
    for (;;) {
        int ret = bpf_map_get_next_key(map_fd, prev_key, &next_key);
        if (ret)
            break;
        prev_key = &cur_key;
        cur_key = next_key;
        keys[i] = next_key;
        bpf_map_lookup_elem(map_fd, &next_key, &hists[i]);
        i++;
    }
    count = i;

    if (env.timestamp) {
        time_t t = time(NULL);
        struct tm *tm = localtime(&t);
        char ts[32];
        strftime(ts, sizeof(ts), "%H:%M:%S", tm);
        printf("\n%-8s\n", ts);
    } else {
        printf("\n");
    }

    for (i = 0; i < count; i++) {
        char sec_label[64];
        if (env.byladdr || env.byraddr) {
            struct in_addr a = { .s_addr = (__be32)keys[i] };
            inet_ntop(AF_INET, &a, addrstr, sizeof(addrstr));
            snprintf(sec_label, sizeof(sec_label), "Address = %s", addrstr);
        } else {
            snprintf(sec_label, sizeof(sec_label), "All Addresses");
        }
        print_hist_section(&hists[i], unit, sec_label);
    }

    /* Clear the map for next interval */
    for (i = 0; i < count; i++)
        bpf_map_delete_elem(map_fd, &keys[i]);

    free(keys);
    free(hists);
}

int main(int argc, char **argv)
{
    struct tcprtt_bpf *skel;
    int err;

    env.duration = 99999;
    argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (!env.interval)
        env.interval = env.duration;

    libbpf_set_print(libbpf_print_fn);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = tcprtt_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Set rodata filters */
    skel->rodata->targ_ms        = env.milliseconds;
    skel->rodata->targ_laddr_hist = env.byladdr;
    skel->rodata->targ_raddr_hist = env.byraddr;
    skel->rodata->targ_show_ext  = env.extension;
    if (env.filter_lport)
        skel->rodata->targ_sport = env.lport;
    if (env.filter_rport)
        skel->rodata->targ_dport = env.rport;
    if (env.filter_laddr)
        skel->rodata->targ_saddr = env.laddr;
    if (env.filter_raddr)
        skel->rodata->targ_daddr = env.raddr;
    if (env.ipv4)
        skel->rodata->targ_family = AF_INET;
    else if (env.ipv6)
        skel->rodata->targ_family = AF_INET6;

    err = tcprtt_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }
    err = tcprtt_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Tracing TCP RTT... Hit Ctrl-C to end.\n");

    int seconds = 0;
    while (!exiting) {
        sleep(env.interval);
        if (env.timestamp || env.interval < env.duration) {
            print_and_clear_hist(skel);
        }
        seconds += env.interval;
        if (seconds >= env.duration)
            break;
    }

    /* Final print (if not already printed in the loop) */
    if (exiting || seconds >= env.duration)
        print_and_clear_hist(skel);

cleanup:
    tcprtt_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
