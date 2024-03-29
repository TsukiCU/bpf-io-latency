#include "iolatency.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

char _license[] SEC("license") = "GPL";
#define MAX_ENTRIES 10000

struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, struct request *);
 __type(value, u64);
} start SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct hist);
} hists SEC(".maps");

static struct hist start_hist;

/* Trace Point: block_rq_insert
 * This trace point is triggered when a block I/O request is INSERTED into the request queue.

 * Trace Point: block_rq_issue
 * This trace point occurs when a block I/O request is issued to the device driver for processing.

 * Trace Point: block_rq_complete
 * This trace point is hit upon the COMPLETION of a block I/O request.
 */

SEC("raw_tracepoint/block_rq_insert")
int BPF_PROG(bpf_prog_io_insert, struct request *rq) {
    u64 ts;

    ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &rq, &ts, BPF_ANY);
    return 0;
}

SEC("raw_tracepoint/block_rq_issue")
int BPF_PROG(bpf_prog_io_issue, struct request *rq) {
    u64 ts;

    ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&start, &rq, &ts, BPF_ANY);
    return 0;
}

SEC("raw_tracepoint/block_rq_complete")
int BPF_PROG(bpf_prog_io_complete, struct request *rq) {
    u64 *t_start;
    u64 latency;
    u64 slot;
    u32 dum = 0;
    struct hist *io_hist;

    t_start = bpf_map_lookup_elem(&start, &rq);
    if (!t_start)
        return 0;

    latency = bpf_ktime_get_ns() - *t_start;
    bpf_map_delete_elem(&start, &rq);
    latency /= 1000U;  // to usecs

    slot = log2l(latency);
    if (slot >= MAX_SLOTS)
        slot = MAX_SLOTS - 1;

    io_hist = bpf_map_lookup_elem(&hists, &dum);
    if (!io_hist) {
        bpf_map_update_elem(&hists, &dum, &start_hist, BPF_ANY);
        io_hist = bpf_map_lookup_elem(&hists, &dum);
        if (!io_hist) return 0;
    }

    __sync_fetch_and_add(&io_hist->slots[slot], 1);

    return 0;
}