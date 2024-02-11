#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "iolatency.h"

#define MAX_ENTRIES 10240

char LICENSE[] SEC("license") = "GPL";

/// @sample{"interval":5000,"type":"log2_hist"}
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct hist);
}hists SEC(".maps");

SEC("tracepoint/block/block_rq_insert")
int bpf_prog_io_insert(struct trace_event_raw_block_rq *ctx)
{
    bpf_printk("ahhhhh, %s, %llu\n", ctx->comm, ctx->sector);
}

SEC("tracepoint/block/block_rq_complete")
int bpf_prog_io_complete(struct trace_event_raw_block_rq_completion *ctx)
{
    bpf_printk("puhhhhhh, %llu\n", ctx->sector);
}

