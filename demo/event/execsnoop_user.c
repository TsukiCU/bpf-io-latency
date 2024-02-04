#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include "execsnoop.h"

int prog_fd;
volatile bool exiting = false;

void sig_handler(int sig)
{
    exiting = true;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    /* sample_cb function called on each received data record. */
    struct event *event = data;
    printf("Event received from BPF program:\n");
    printf("PID: %d, PPID: %d, UID: %d, Command: %s\n",
           event->pid, event->ppid, event->uid, event->comm);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
    /* lost_cb function called when record loss has occurred. */
    fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main()
{
    struct perf_buffer *pb = NULL;
    struct perf_buffer_opts pb_opts = {};

    struct bpf_link *link = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;
	int ret, err;

    signal(SIGINT, sig_handler);

    obj = bpf_object__open_file("execsnoop.bpf.o", NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 0;
	}
    bpf_object__load(obj);

    prog = bpf_object__find_program_by_name(obj, "tracepoint__syscalls__sys_enter_execve");
	if (!prog) {
		printf("finding a prog in obj file failed\n");
		goto cleanup;
	}

    /* load BPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
		fprintf(stderr, "ERROR: finding a map in obj file failed\n");
		goto cleanup;
	}

    link = bpf_program__attach_tracepoint(prog, "raw_syscalls", "sys_enter");
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: bpf_program__attach failed\n");
		link = NULL;
		goto cleanup;
	}

    pb = perf_buffer__new(prog_fd, 32, handle_event, handle_lost_events, NULL, NULL);
    ret = libbpf_get_error(pb);
	if (ret) {
		printf("failed to setup perf_buffer: %d\n", ret);
		return 1;
	}

    printf("Now successfully started! Hit Ctrl-C to exit.\n");
    while (!exiting) {
        err = perf_buffer__poll(pb, 100); // Timeout of 100 ms
        if (err < 0 && errno != EINTR) {
            fprintf(stderr, "ERROR: perf_buffer__poll failed\n");
            goto cleanup;
        }
    }

cleanup:
    /* No need to check if its null.*/
    perf_buffer__free(pb);
    bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}