#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "iolatency.h"

#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

static void print_stars(unsigned int val, unsigned int val_max, int width) {
	int num_stars, num_spaces, i;
	bool need_plus;

	num_stars = min(val, val_max) * width / val_max;
	num_spaces = width - num_stars;
	need_plus = val > val_max;

	for (i = 0; i < num_stars; i++)
		printf("*");
	for (i = 0; i < num_spaces; i++)
		printf(" ");
	if (need_plus)
		printf("+");
}

void draw_hist(unsigned int *vals, int vals_size) {
	int stars_max = 40, idx_max = -1;
    int stars, width;
	__u32 val_max = 0;
	__u64 low, high;

	// Find max value and last non-zero index
    for (int i=0; i < vals_size; i++) {
        if (vals[i] > 0) idx_max = i;
        if (vals[i] > val_max) val_max = vals[i];
    }

    // If no data to plot
	if (idx_max < 0) return;

	printf("%*s%-*s : count    distribution\n", idx_max <= 32 ? 5 : 15, "",
		idx_max <= 32 ? 19 : 29, "usecs");

	stars = idx_max<=32 ? stars_max : stars_max/2;
	for (int i=0; i<=idx_max; i++) {
		low = (1ULL << (i + 1)) >> 1;
		high = (1ULL << (i + 1)) - 1;
		if (low == high)
			low -= 1;
		width = idx_max <= 32 ? 10 : 20;
		printf("%*lld -> %-*lld : %-8d |", width, low, width, high, vals[i]);
		print_stars(vals[i], val_max, stars);
		printf("|\n");
	}
}

int main(int argc, char **argv) {
    int prog_fd, map_fd;
    int interval;
    __u32 key = 0;
    char *bpf_progs[3] = {"bpf_prog_io_insert", "bpf_prog_io_issue", "bpf_prog_io_complete"};
    struct hist start_hist = {0};
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *bpf_links[3];
    struct hist hist;  // Hist shown in user space

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interval>\n", argv[0]);
        return 1;
    }

    interval = atoi(argv[1]);  // Interval between printing hists.

    obj = bpf_object__open_file("iolatency.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Cannot open bpf object file!\n");
        return 0;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Cannot load the bpf object!\n");
        goto cleanup;
    }

    struct bpf_map *histmap;
    histmap = bpf_object__find_map_by_name(obj, "hists");
    if (libbpf_get_error(histmap)) {
        fprintf(stderr, "Cannot find the bpf map!\n");
        goto cleanup;
    }

    map_fd = bpf_map__fd(histmap);
    if (bpf_map_update_elem(map_fd, &key, &start_hist, BPF_ANY) < 0) {
        fprintf(stderr, "bpf_map_update_elem");
        goto cleanup;
    }

    // Attach bpf programs to kernel
    for (int i=0; i<3; i++) {
        prog = bpf_object__find_program_by_name(obj, bpf_progs[i]);
        if (libbpf_get_error(prog)) {
            fprintf(stderr, "Cannot find bpf program!\n");
            goto cleanup;
        }
        prog_fd = bpf_program__fd(prog);
        if (prog_fd < 0) {
            fprintf(stderr, "Cannot get prog_fd!\n");
            goto cleanup;
        }
        bpf_links[i] = bpf_program__attach(prog);
        if (libbpf_get_error(bpf_links[i])) {
            fprintf(stderr, "Cannot attach bpf program!\n");
            bpf_links[i] = NULL;
            goto cleanup;
        }
    }

    // While loop to print status to user space
    while (1) {
        sleep(interval);

        if (bpf_map_lookup_elem(map_fd, &key, &hist) < 0) {
            fprintf(stderr, "bpf_map_lookup_elem failed!\n");
            goto cleanup;
        }
        if (bpf_map_update_elem(map_fd, &key, &start_hist, BPF_ANY) < 0) {
            fprintf(stderr, "bpf_map_update_elem failed!\n");
            goto cleanup;
        }
        draw_hist(hist.slots, MAX_SLOTS);
        printf("\n");
    }

cleanup:
    for (int i=0; i<3; i++) {
        if (bpf_links[i]) bpf_link__destroy(bpf_links[i]);
    }
    if (obj)
        bpf_object__close(obj);
    return 0;
}
