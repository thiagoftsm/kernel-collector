#define KBUILD_MODNAME "latency_netdata"
#include <linux/bpf.h>
#include <linux/ptrace.h>

#include "bpf_helpers.h"
#include "netdata_ebpf.h"

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
} netdata_disk_key_t;

typedef struct netdata_disk_value {
    u64 timestamp;
    unsigned int bytes;
} netdata_disk_value_t;

/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

//CPU
struct bpf_map_def SEC("maps") tbl_cpu_stats = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_LATENCY_MAX_BINS
};

//Hardware
struct bpf_map_def SEC("maps") tbl_disk_stats = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(block_key_t),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_LATENCY_HISTOGRAM_LENGTH
};

//Global
struct bpf_map_def SEC("maps")  tbl_latency_pid_stats = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct netdata_latency_pid_stat),
    .max_entries = 100000
};

struct bpf_map_def SEC("maps") tbl_latency_tot = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_LATENCY_COUNTER
};


// Temporary use only
struct bpf_map_def SEC("maps") tmp_cpu_stats = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u64),
    .max_entries = 512
};

struct bpf_map_def SEC("maps") tmp_disk_stats = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    //.key_size = sizeof(__u64),
    .key_size = sizeof(netdata_disk_key_t),
    .value_size = sizeof(netdata_disk_value_t),
    .max_entries = 8192
};

/************************************************************************************
 *     
 *                                 COMMON SECTION
 *     
 ***********************************************************************************/

/**
 * The motive we are using log2 to plot instead the raw value is well explained
 * inside this paper https://www.fsl.cs.stonybrook.edu/docs/osprof-osdi2006/osprof.pdf
 */
static unsigned int log2(unsigned int v)
{
    unsigned int r;
    unsigned int shift;

    r = (v > 0xFFFF) << 4; v >>= r;
    shift = (v > 0xFF) << 3; v >>= shift; r |= shift;
    shift = (v > 0xF) << 2; v >>= shift; r |= shift;
    shift = (v > 0x3) << 1; v >>= shift; r |= shift;
    r |= (v >> 1);

    return r;
}

static unsigned int log2l(__u64 v)
{
    unsigned int hi = v >> 32;
    if (hi)
        return log2(hi) + 32;
    else
        return log2(v);
}

/**
 *  We are limitating to 32 bins to be sure that 
 *  our dashboard will plot.
 *
 *  The algorithm was based in the link
 *  http://www.brendangregg.com/blog/2015-05-15/ebpf-one-small-step.html
 */
static inline __u32 select_idx(__u64 val)
{
    __u32 rlog;

    val /= 1024;
    rlog = log2l(val);

    if (rlog > NETDATA_LATENCY_MAX_BINS_POS)
        rlog = NETDATA_LATENCY_MAX_BINS_POS;

    return rlog;
}

static void netdata_update_u64(__u64 *res, __u64 value)
{
    if (!value)
        return;

    __sync_fetch_and_add(res, value);
    if ( (0xFFFFFFFFFFFFFFFF - *res) <= value) {
        *res = value;
    }
}

static void netdata_update_global(__u64 key)
{
    __u64 *res;
    __u64 value = 1;
    res = bpf_map_lookup_elem(&tbl_latency_tot, &key);
    if (res) {
        netdata_update_u64(res, value) ;
    } else
        bpf_map_update_elem(&tbl_latency_tot, &key, &value, BPF_NOEXIST);
}



static inline void netdata_update_pid(__u64 pid_tgid, __u32 hist_idx, __u32 offset)
{
    struct netdata_latency_pid_stat *fill, data ={ };

    __u32 pid = (__u32)(pid_tgid >> 32);
    fill = bpf_map_lookup_elem(&tbl_latency_pid_stats, &pid);
    if (!fill) {
        fill = &data;
    } 

    switch (hist_idx) {
        case NETDATA_KEY_CALLS_BLOCK_RQ_ISSUE: {
                netdata_update_u64(&fill->blk_start_request_call, 1);
                break;
            }
                                               /*
        case NETDATA_KEY_CALLS_BLOCK_MQ_START_REQUEST: {
                netdata_update_u64(&fill->blk_mq_start_request_call, 1);
                break;
            }
            */
        case NETDATA_KEY_CALLS_BLOCK_RQ_COMPLETE: {
                netdata_update_u64(&fill->io_done, 1);
                break;
            }
        case NETDATA_KEY_TRY_TO_WAKE_UP: {
                netdata_update_u64(&fill->try_to_wake_up_call, 1);
                break;
            }
    }

    /*
    __u32 update_idx = hist_idx + offset;
    if (update_idx < NETDATA_LENGTH_HIST)
        netdata_update_u64(&fill->histogram[update_idx], 1);
        */

    if (fill == &data)
        bpf_map_update_elem(&tbl_latency_pid_stats, &pid, fill, BPF_ANY);
}

/************************************************************************************
 *     
 *                                 END COMMON SECTION
 *     
 ***********************************************************************************/

/************************************************************************************
 *     
 *                               SCHEDULE SECTION
 *     
 ***********************************************************************************/

/*
static void netdata_trace_enqueue(u32 pid, u32 tgid)
{
    if (!pid && !tgid)
        return;

    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&tmp_cpu_stats, &pid, &ts, BPF_ANY);
}
*/

SEC("kprobe/ttwu_do_wakeup")
int netdata_ttwu_do_wakeup(struct pt_regs* ctx)
{
    /*
    struct task_struct *ts = (struct task_struct *)PT_REGS_PARM2(ctx);
    u32 pid, tgid;

    bpf_probe_read(&pid, sizeof(pid), &ts->pid);
    bpf_probe_read(&tgid, sizeof(tgid), &ts->tgid);
    */

    netdata_update_global(NETDATA_KEY_TRY_TO_WAKE_UP);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&tmp_cpu_stats, &pid_tgid, &ts, BPF_ANY);

    //netdata_trace_enqueue(pid, tgid);
    return 0;
}

SEC("kprobe/wake_up_new_task")
int netdata_wake_up_new_task(struct pt_regs* ctx)
{
    /*
    struct task_struct *ts = (struct task_struct *)PT_REGS_PARM1(ctx);
    u32 pid, tgid;

    bpf_probe_read(&pid, sizeof(pid), &ts->pid);
    bpf_probe_read(&tgid, sizeof(tgid), &ts->tgid);
    */

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&tmp_cpu_stats, &pid_tgid, &ts, BPF_ANY);

    netdata_update_global(NETDATA_KEY_WAKE_UP);

    //netdata_trace_enqueue(pid, tgid);
    return 0;
}

SEC("kprobe/finish_task_switch")
int netdata_finish_task_switch(struct pt_regs* ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    long state;
    __u64 *fill;
    __u64 *nl, data;

    struct task_struct *prev = (struct task_struct *)PT_REGS_PARM1(ctx);

    bpf_probe_read(&state, sizeof(state), (void *)&prev->state);

    netdata_update_global(NETDATA_KEY_FINISH_TASK_SWITCH);

    /*
    if (state == TASK_RUNNING)
        netdata_trace_enqueue(pid, tgid);
     */

    fill = bpf_map_lookup_elem(&tmp_cpu_stats ,&pid_tgid);
    if (!fill) {
        return 0;
    }

    u64 curr = bpf_ktime_get_ns();
    u32 offset = select_idx((curr - *fill)/1000);
    nl = bpf_map_lookup_elem(&tbl_cpu_stats ,&offset);
    if (nl) {
        netdata_update_u64(nl, 1);
    } else {
        data = 1;
        bpf_map_update_elem(&tbl_cpu_stats, &offset, &data, BPF_ANY);
    }

    return 0;
}

/*
SEC("kprobe/try_to_wake_up")
int netdata_enter_try_to_wake_up(struct pt_regs* ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&tmp_cpu_stats, &pid_tgid, &ts, BPF_ANY);

    netdata_update_global(NETDATA_KEY_TRY_TO_WAKE_UP);

    return 0;
}

SEC("kretprobe/try_to_wake_up")
int netdata_return_try_to_wake_up(struct pt_regs* ctx)
{
    u64 ts = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *fill;
    __u64 *nl, data;
    __u32 offset;

    fill = bpf_map_lookup_elem(&tmp_cpu_stats ,&pid_tgid);
    if (!fill) {
        return 0;
    }

    bpf_map_delete_elem(&tmp_cpu_stats, &pid_tgid);

    offset = select_idx((ts - *fill)/1000);
    nl = bpf_map_lookup_elem(&tbl_cpu_stats ,&offset);
    if (nl) {
        netdata_update_u64(nl, 1);
    } else {
        data = 1;
        bpf_map_update_elem(&tbl_cpu_stats, &offset, &data, BPF_ANY);
    }

    netdata_update_pid(pid_tgid, NETDATA_KEY_TRY_TO_WAKE_UP, offset);

    return 0;
}
*/

/************************************************************************************
 *     
 *                             END SCHEDULE SECTION
 *     
 ***********************************************************************************/

/************************************************************************************
 *     
 *                                 DISK SECTION
 *     
 ***********************************************************************************/

SEC("tracepoint/block/block_rq_issue")
int netdata_block_rq_issue(struct netdata_block_rq_issue *ptr)
{
    // blkid generates these and we're not interested in them
    if (!ptr->dev)
        return 0;

    netdata_disk_key_t key = {};
    key.dev = ptr->dev;
    key.sector = ptr->sector;

    if (key.sector < 0)
        key.sector = 0;

    netdata_disk_value_t value = {};
    value.timestamp = bpf_ktime_get_ns();
    value.bytes = ptr->bytes;

    netdata_update_global(NETDATA_KEY_CALLS_BLOCK_RQ_ISSUE);

    bpf_map_update_elem(&tmp_disk_stats, &key, &value, BPF_ANY);

    return 0;
}

SEC("tracepoint/block/block_rq_complete")
int netdata_block_rq_complete(struct netdata_block_rq_complete *ptr)
{
    netdata_disk_value_t *fill;
    netdata_disk_key_t key = {};
    block_key_t blk;
    key.dev = ptr->dev;
    key.sector = ptr->sector;

    if (key.sector < 0)
        key.sector = 0;

    fill = bpf_map_lookup_elem(&tmp_disk_stats ,&key);
    if (!fill)
        return 0;

    // calculate and convert to microsecond
    u64 data, *update, curr = bpf_ktime_get_ns();
    curr -= fill->timestamp;
    curr /= 1000;

    blk.bin = select_idx(curr);
    blk.dev = new_encode_dev(ptr->dev);

    netdata_update_global(NETDATA_KEY_CALLS_BLOCK_RQ_COMPLETE);

    bpf_map_delete_elem(&tmp_disk_stats, &key);

    update = bpf_map_lookup_elem(&tbl_disk_stats ,&blk);
    if (update) {
        netdata_update_u64(update, 1);
    } else {
        data = 1;
        bpf_map_update_elem(&tbl_disk_stats, &blk, &data, BPF_ANY);
    }

    return 0;
}

/*
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0))
SEC("kprobe/blk_start_request")
int netdata_blk_start_request(struct pt_regs *ctx)
{
    __u64 ct = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    bpf_map_update_elem(&tmp_disk_stats, &pid_tgid, &ct, BPF_ANY);

    netdata_update_global(NETDATA_KEY_CALLS_BLOCK_START_REQUEST);

    netdata_update_pid(pid_tgid, NETDATA_KEY_CALLS_BLOCK_START_REQUEST, 0);

    return 0;
}
#endif

SEC("kprobe/blk_mq_start_request")
int netdata_blk_mq_start_request(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 ct = bpf_ktime_get_ns();

    bpf_map_update_elem(&tmp_disk_stats, &pid_tgid, &ct, BPF_ANY);
    
    netdata_update_global(NETDATA_KEY_CALLS_BLOCK_MQ_START_REQUEST);

    netdata_update_pid(pid_tgid, NETDATA_KEY_CALLS_BLOCK_MQ_START_REQUEST, 0);

    return 0;
}

SEC("kprobe/blk_account_io_done")
int netdata_blk_account_io_completion(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *fill;
    u64 ts = bpf_ktime_get_ns();
    __u64 data;
    block_key_t blk = { };

    netdata_update_global(NETDATA_KEY_CALLS_BLOCK_ACCOUNT_IO_DONE);

    fill = bpf_map_lookup_elem(&tmp_disk_stats ,&pid_tgid);
    if (!fill) {
        return 0;
    }

    bpf_map_delete_elem(&tmp_disk_stats, &pid_tgid);

    // There are write request with zero length on sector zero,
    // which do not seem to be real writes to device.
//    if (req->__sector == 0 && req->__data_len == 0)
//        return 0;

    blk.bin = select_idx((ts - *fill)/1000);

    // Resolve disk_name path
    struct request *req = (struct request *)PT_REGS_PARM1(ctx);
    struct gendisk *gd = (struct gendisk *)&req->rq_disk;
    char *disk_name = (char *)&gd->disk_name;
    bpf_probe_read(blk.disk, sizeof(blk.disk), disk_name);
 //   if (req)
  //  {
//    blk.disk[0] = 's';
//    blk.disk[1] = 'd';
    blk.disk[2] = 'a';
//    }

    fill = bpf_map_lookup_elem(&tbl_disk_stats ,&blk);
    if (fill) {
        netdata_update_u64(fill, 1);
    } else {
        data = 1;
        bpf_map_update_elem(&tbl_disk_stats, &blk, &data, BPF_ANY);
    }

    netdata_update_pid(pid_tgid, NETDATA_KEY_CALLS_BLOCK_ACCOUNT_IO_DONE, blk.bin);

    return 0;
}
    */

/************************************************************************************
 *     
 *                               END DISK SECTION
 *     
 ***********************************************************************************/

char _license[] SEC("license") = "GPL";

