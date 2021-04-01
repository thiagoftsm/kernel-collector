OUTPUT := .output
CLANG ?= clang
BPFTOOL ?= bpftool
LLVM_STRIP ?= llvm-strip

INCLUDES := -Ikernel/ -Ibpf/ -I../libbpf/include/uapi -I../includes/
CFLAGS := -g -Wall

CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
			 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ARCH := $(shell uname -m | sed 's/x86_64/x86/')

all: binaries

sync.bpf.o: sync.bpf.c
sync.skel.h: sync.bpf.o
sync_file_range.bpf.o: sync_file_range.bpf.c
sync_file_range.skel.h: sync_file_range.bpf.o
syncfs.bpf.o: syncfs.bpf.c
syncfs.skel.h: syncfs.bpf.o
fdatasync.bpf.o: fdatasync.bpf.c
fdatasync.skel.h: fdatasync.bpf.o
fsync.bpf.o: fsync.bpf.c
fsync.skel.h: fsync.bpf.o
msync.bpf.o: msync.bpf.c
msync.skel.h: msync.bpf.o

clean:
	rm -rf *.a bpf/ pkgconfig/ *.o *.h

%.bpf.o: %.bpf.c
	$(call msg,BPF,$@)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@ # strip useless DWARF info

%.skel.h: %.bpf.o 
	$(BPFTOOL) gen skeleton $< > $@

binaries: sync.skel.h fdatasync.skel.h sync_file_range.skel.h syncfs.skel.h fdatasync.skel.h msync.skel.h

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:


