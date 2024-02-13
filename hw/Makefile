CLANG := clang

BPF_CFLAGS := -O2 -target bpf -g -c

USERSPACE_CFLAGS :=
USERSPACE_LDFLAGS := -lbpf

BPF_SRC := iolatency.bpf.c
BPF_OBJ := $(BPF_SRC:.c=.o)

USERSPACE_SRC := iolatency.c
USERSPACE_BIN := iolatency

all: $(BPF_OBJ) $(USERSPACE_BIN)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(BPF_CFLAGS) $< -o $@
$(USERSPACE_BIN): $(USERSPACE_SRC)
	$(CLANG) $(USERSPACE_CFLAGS) $< -o $@ $(USERSPACE_LDFLAGS)

clean:
	rm -f $(BPF_OBJ) $(USERSPACE_BIN)

.PHONY: all clean
