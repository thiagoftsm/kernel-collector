CLANG ?= clang
CFLAGS := -g -O2 -Wall -I../btf/ -L../btf -pthread

all:
	$(CC) $(CFLAGS) ebpf.c -lelf -lz -lbpf -o ebpf.plugin


clean:
	rm ebpf.plugin
