OUTPUT := .output
CLANG ?= clang
BPFTOOL ?= bpftool
LLVM_STRIP ?= llvm-strip

INCLUDES := -Ikernel/ -Ibpf/ -I../libbpf/include/uapi
CFLAGS := -g -Wall

CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
			 | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ARCH := $(shell uname -m | sed 's/x86_64/x86/')

all: binaries

sync.bpf.o: sync.bpf.c
sync.skel.h: sync.bpf.o

clean:
	#rm -rf *.a bpf/ pkgconfig/ *.o
	rm -rf *.o *.h

%.bpf.o: %.bpf.c
	$(call msg,BPF,$@)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $(filter %.c,$^) -o $@
	$(LLVM_STRIP) -g $@ # strip useless DWARF info

%.skel.h: %.bpf.o 
	$(BPFTOOL) gen skeleton $< > $@

binaries: sync.skel.h


# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:


