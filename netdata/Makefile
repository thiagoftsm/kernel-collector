CLANG ?= clang
CFLAGS := -g -O2 -Wall -I../btf/ -L../btf -pthread

all: $(binaries)

libs:
	cd kernel/ && $(MAKE) && cp /*.o ..

binaries:
	$(CC) $(CFLAGS) ebpf.c -lelf -lz -lbpf -o ebpf.plugin

clean:
	#cd kernel/ && $(MAKE) clean
	rm ebpf.plugin
