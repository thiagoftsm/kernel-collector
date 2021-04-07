CLANG ?= clang
BPFTOOL ?= bpftool
LLVM_STRIP ?= llvm-strip

INCLUDES := -Ikernel/ -Ibpf/ -I../libbpf/include/uapi
CFLAGS := -g -Wall

ARCH := $(shell uname -m | sed 's/x86_64/x86/')

APPS = cachestat \
       dc \
       fdatasync \
       fsync \
       msync \
       process \
       sync \
       sync_file_range \
       syncfs \
       #

all: $(APPS)

clean:
	rm -rf *.a bpf/ pkgconfig/ *.o *.h

%.bpf.o: %.bpf.c
	$(call msg,BPF,$@)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) -c $(filter %.c,$^) -o $@
	#$(LLVM_STRIP) -g $@ # strip useless DWARF info

%.skel.h: %.bpf.o 
	$(BPFTOOL) gen skeleton $< > $@

$(APPS): %: %.skel.h

