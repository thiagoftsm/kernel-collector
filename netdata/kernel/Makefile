CLANG = clang
LLC = llc

NETDATA_APPS= sync \
	      #

all: $(NETDATA_APPS)

%_kern.o: %_kern.c
	$(CLANG) $(EXTRA_CFLAGS) -I../../btf/bpf/ -I../../btf/kernel/ -g -S -O2 -target bpf -DNOTBTF -D__KERNEL__ -c $<
	$(LLC) -march=bpf -filetype=obj -o $@ $(<:.c=.ll)

$(NETDATA_APPS): %: %_kern.o

clean:
	rm *.o *.ll
