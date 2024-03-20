#ifndef _IOLATENCY_H_
#define _IOLATENCY_H_

#define MAX_SLOTS 20

// don't need this in user space.
#ifdef __BPF__

#include "vmlinux.h"
static u64 log2(u32 v)
{
	u32 shift, r;

	r = (v > 0xFFFF) << 4; v >>= r;
	shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
	shift = (v > 0xF) << 2; v >>= shift; r |= shift;
	shift = (v > 0x3) << 1; v >>= shift; r |= shift;
	r |= (v >> 1);

	return r;
}

static u64 log2l(u64 v)
{
	u32 hi = v >> 32;

	if (hi)
		return log2(hi) + 32;
	else
		return log2(v);
}

#endif

struct hist {
    __u32 slots[MAX_SLOTS];
};

#endif /* _IOLATENCY_H_ */