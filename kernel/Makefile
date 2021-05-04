CLANG = clang
LLC = llc
KERNELSOURCE = /usr/src/linux
ARCH = x86

EXTRA_CFLAGS += -fno-stack-protector

LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include/generated
LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include/generated/uapi
LINUXINCLUDE += -I$(KERNELSOURCE)/include
LINUXINCLUDE += -I$(KERNELSOURCE)/fs/

LINUXINCLUDE += -I$(KERNELSOURCE)/include/generated/uapi
LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include
LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include/uapi
LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include/generated
LINUXINCLUDE += -I$(KERNELSOURCE)/arch/$(ARCH)/include/generated/uapi
LINUXINCLUDE += -I$(KERNELSOURCE)/include
LINUXINCLUDE += -I$(KERNELSOURCE)/include/uapi
LINUXINCLUDE += -include $(KERNELSOURCE)/include/linux/kconfig.h
LINUXINCLUDE += -I../includes

CLANG_VERSION := $(shell clang --version | grep -o -E 'clang version [0-9]+\.[0-9]+\.[0-9]' | cut -f 3 -d ' ')
LLVM_INCLUDES = $(shell [ -d /usr/lib/clang ] && echo "-I/usr/lib/clang/$(CLANG_VERSION)/include" || echo "-I/usr/lib64/clang/$(CLANG_VERSION)/include")
LLVM_INCLUDES += -I/opt/rh/llvm-toolset-7.0/root/usr/lib64/clang/$(CLANG_VERSION)/include

#KERNEL_VERSION="$(shell basename $(realpath /usr/src/linux) | cut -f 2 -d '-')"
KERNEL_VERSION="$(shell cat /usr/src/linux/include/config/kernel.release)"

VER_MAJOR=$(shell echo $(KERNEL_VERSION) | cut -d. -f1)
VER_MINOR=$(shell echo $(KERNEL_VERSION) | cut -d. -f2)
VER_PATCH=$(shell echo $(KERNEL_VERSION) | cut -d. -f3)

CURRENT_KERNEL=$(shell echo $(VER_MAJOR)\*65536 + $(VER_MINOR)\*256 + $(VER_PATCH) |bc)

NETDATA_APPS= btrfs \
	      dc \
	      ext4 \
	      cachestat \
	      fdatasync \
	      fsync \
	      io_latency_tp \
	      md \
	      msync \
	      network_viewer \
	      nfs \
	      process \
	      sync \
	      syncfs \
	      sync_file_range \
	      swap \
	      xfs \
	      #

all: $(NETDATA_APPS)
#clang --target bpf
#The .eh_frame is generated because the C code is compiled first with native architecture like
#  clang -O2 -g -S -emit-llvm file.c  <==== native x86_64 arch
#  llc -march=bpf file.ll

#Compile with x64 arch will produce .eh_frame which tries to facilitate stack unwinding.
#If you compile all the way with bpf  ..., you should not see .eh_frame.

%_kern.o: %_kern.c
	$(CLANG) $(EXTRA_CFLAGS) -S -nostdinc $(LINUXINCLUDE) $(LLVM_INCLUDES) \
		-D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
	    	-Wno-compare-distinct-pointer-types \
	    	-Wno-gnu-variable-sized-type-not-at-end \
	    	-Wno-tautological-compare \
		-DNETDATASEL=0 \
		-D__BPF_TRACING__ \
		-include ../includes/netdata_asm_goto.h \
		-O2 -emit-llvm -c $<
	$(LLC) -march=bpf -filetype=obj -o r$@ $(<:.c=.ll)
	$(CLANG) $(EXTRA_CFLAGS) -S -nostdinc $(LINUXINCLUDE) $(LLVM_INCLUDES) \
		-D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
	    	-Wno-compare-distinct-pointer-types \
	    	-Wno-gnu-variable-sized-type-not-at-end \
	    	-Wno-tautological-compare \
		-DNETDATASEL=1 \
		-D__BPF_TRACING__ \
		-include ../includes/netdata_asm_goto.h \
		-O2 -emit-llvm -c $<
	$(LLC) -march=bpf -filetype=obj -o d$@ $(<:.c=.ll)
	$(CLANG) $(EXTRA_CFLAGS) -S -nostdinc $(LINUXINCLUDE) $(LLVM_INCLUDES) \
		-D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
	    	-Wno-compare-distinct-pointer-types \
	    	-Wno-gnu-variable-sized-type-not-at-end \
	    	-Wno-tautological-compare \
		-DNETDATASEL=2 \
		-D__BPF_TRACING__ \
		-include ../includes/netdata_asm_goto.h \
		-O2 -emit-llvm -c $<
	$(LLC) -march=bpf -filetype=obj -o p$@ $(<:.c=.ll)

$(NETDATA_APPS): %: %_kern.o

clean:
	rm *.o *.ll
