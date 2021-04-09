// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_TP_LATENCY_H_
#define _NETDATA_TP_LATENCY_H_ 1

#include <linux/sched.h>

#define NETDATA_LATENCY_MAX_BINS 21L
#define NETDATA_LATENCY_MAX_BINS_POS 20L
#define NETDATA_LATENCY_MAX_HD 256L
#define NETDATA_LATENCY_HISTOGRAM_LENGTH  (NETDATA_LATENCY_MAX_BINS * NETDATA_LATENCY_MAX_HD)

// /sys/kernel/debug/tracing/events/block/block_rq_issue/
struct netdata_block_rq_issue {
    u64 pad;                    // This is not used with eBPF
    dev_t dev;                  // offset:8;       size:4; signed:0;
    sector_t sector;            // offset:16;      size:8; signed:0;
    unsigned int nr_sector;     // offset:24;      size:4; signed:0;
    unsigned int bytes;         // offset:28;      size:4; signed:0;
    char rwbs[8];               // offset:32;      size:8; signed:1;
    char comm[16];              // offset:40;      size:16;        signed:1;
    int data_loc_name;          // offset:56;      size:4; signed:1; (https://github.com/iovisor/bpftrace/issues/385)
};

// /sys/kernel/debug/tracing/events/block/block_rq_complete
// https://elixir.bootlin.com/linux/latest/source/include/trace/events/block.h
struct netdata_block_rq_complete {
    u64 pad;                    // This is not used with eBPF
    dev_t dev;                  // offset:8;       size:4; signed:0;
    sector_t sector;            // offset:16;      size:8; signed:0;
    unsigned int nr_sector;     // offset:24;      size:4; signed:0;
    int error;                  // offset:28;      size:4; signed:1;
    char rwbs[8];               // offset:32;      size:8; signed:1;
    int data_loc_name;          // offset:40;      size:4; signed:1; ()https://lists.linuxfoundation.org/pipermail/iovisor-dev/2017-February/000627.html
};

typedef struct netdata_disk_key {
    dev_t dev;
    sector_t sector;
    u8 partition;
} netdata_disk_key_t;

typedef struct netdata_disk_value {
    u64 timestamp;
    unsigned int bytes;
} netdata_disk_value_t;

typedef struct netdata_bootsector {
    u64 start_sector;
    u64 end_sector;
    u64 timestamp;
    u64 changed_sector;
    u64 size;
} netdata_bootsector_t;


typedef struct block_key {
    __u32 bin;
    u32 dev;
    u32 partition;
} block_key_t;

#endif /* _NETDATA_CACHE_H_ */
