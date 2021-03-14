#define KBUILD_MODNAME "ext4_netdata"
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/genhd.h>

#include "bpf_helpers.h"
#include "netdata_ebpf.h"

/************************************************************************************
 *     
 *                                 MAP Section
 *     
 ***********************************************************************************/

struct bpf_map_def SEC("maps") tbl_ext4 = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(netdata_fs_hist_t),
    .value_size = sizeof(__u64),
    .max_entries = 8192
};

struct bpf_map_def SEC("maps") tmp_ext4 = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 8192
};

/************************************************************************************
 *     
 *                                 COMMON Section
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

    rlog = log2l(val);

    if (rlog > NETDATA_FS_MAX_BINS_POS)
        rlog = NETDATA_FS_MAX_BINS_POS;

    return rlog;
}

static inline void netdata_update_u64(__u64 *res, __u64 value)
{
    __sync_fetch_and_add(res, value);
    if ( (0xFFFFFFFFFFFFFFFF - *res) <= value) {
        *res = value;
    }
}


/************************************************************************************
 *     
 *                                 ENTRY Section
 *     
 ***********************************************************************************/

static int netdata_ext4_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&tmp_ext4, &pid, &ts, BPF_ANY);

    return 0;
}

SEC("kprobe/ext4_file_read_iter")
int netdata_ext4_file_read_iter(struct pt_regs *ctx) 
{
    return netdata_ext4_entry(ctx);
}

SEC("kprobe/ext4_file_write_iter")
int netdata_ext4_file_write_iter(struct pt_regs *ctx) 
{
    return netdata_ext4_entry(ctx);
}

SEC("kprobe/ext4_file_open")
int netdata_ext4_file_open(struct pt_regs *ctx) 
{
    return netdata_ext4_entry(ctx);
}

SEC("kprobe/ext4_sync_file")
int netdata_ext4_sync_file(struct pt_regs *ctx) 
{
    return netdata_ext4_entry(ctx);
}

/************************************************************************************
 *     
 *                                 END Section
 *     
 ***********************************************************************************/

static int netdata_ext4_end(struct pt_regs *ctx, __u32 selection)
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    netdata_fs_hist_t blk;

    fill = bpf_map_lookup_elem(&tmp_ext4 ,&pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_ext4, &pid);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;

    blk.hist_id = selection;
    blk.bin = select_idx(data);

    fill = bpf_map_lookup_elem(&tbl_ext4 ,&blk);
    if (fill) {
        netdata_update_u64(fill, 1);
    } else {
        data = 1;
        bpf_map_update_elem(&tbl_ext4, &blk, &data, BPF_ANY);
    }

    return 0;
}

SEC("kretprobe/ext4_file_read_iter")
int netdata_ret_ext4_ext4_file_read_iter(struct pt_regs *ctx)
{
    return netdata_ext4_end(ctx, NETDATA_KEY_CALLS_READ);
}

SEC("kretprobe/ext4_file_write_iter")
int netdata_ret_ext4_file_write_iter(struct pt_regs *ctx)
{
    return netdata_ext4_end(ctx, NETDATA_KEY_CALLS_WRITE);
}

SEC("kretprobe/ext4_file_open")
int netdata_ret_ext4_file_open(struct pt_regs *ctx)
{
    return netdata_ext4_end(ctx, NETDATA_KEY_CALLS_OPEN);
}

SEC("kretprobe/ext4_sync_file")
int netdata_ret_ext4_sync_file(struct pt_regs *ctx) 
{
    return netdata_ext4_end(ctx, NETDATA_KEY_CALLS_SYNC);
}

char _license[] SEC("license") = "GPL";

