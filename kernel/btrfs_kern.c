#define KBUILD_MODNAME "btrfs_netdata"
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/genhd.h>
#include <linux/fs.h>

#include "bpf_helpers.h"
#include "netdata_ebpf.h"


/************************************************************************************
 *     
 *                                 MAP Section
 *     
 ***********************************************************************************/

struct bpf_map_def SEC("maps") tbl_btrfs = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(netdata_fs_hist_t),
    .value_size = sizeof(__u64),
    .max_entries = 8192
};

struct bpf_map_def SEC("maps") tbl_btrfs_ext = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1
};

struct bpf_map_def SEC("maps") tmp_btrfs = {
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
 *                                 ENTRY Section
 *     
 ***********************************************************************************/

static int netdata_btrfs_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&tmp_btrfs, &pid, &ts, BPF_ANY);

    return 0;
}

SEC("kprobe/btrfs_file_write_iter")
int netdata_btrfs_file_write_iter(struct pt_regs *ctx) 
{
    return netdata_btrfs_entry(ctx);
}

SEC("kprobe/btrfs_sync_file")
int netdata_btrfs_sync_file(struct pt_regs *ctx) 
{
    return netdata_btrfs_entry(ctx);
}

SEC("kprobe/generic_file_read_iter")
int netdata_generic_file_read_iter(struct pt_regs *ctx) 
{
    __u32 key = 0;
    __u64 *bfo = bpf_map_lookup_elem(&tbl_btrfs_ext ,&key);
    if (!bfo)
        return 0;

    struct file *ptr = (struct file *)PT_REGS_PARM2(ctx);
    struct file_operations *fo = _(ptr->f_op);
    if ((u64)fo != *bfo)
        return 0;

    return netdata_btrfs_entry(ctx);
}

SEC("kprobe/generic_file_open")
int netdata_generic_file_open(struct pt_regs *ctx) 
{
    __u32 key = 0;
    __u64 *bfo = bpf_map_lookup_elem(&tbl_btrfs_ext ,&key);
    if (!bfo)
        return 0;

    struct file *ptr = (struct file *)PT_REGS_PARM2(ctx);
    struct file_operations *fo = _(ptr->f_op);
    if ((u64)fo != *bfo)
        return 0;

    return netdata_btrfs_entry(ctx);
}

/************************************************************************************
 *     
 *                                 END Section
 *     
 ***********************************************************************************/

static int netdata_btrfs_end(struct pt_regs *ctx, __u32 selection)
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    netdata_fs_hist_t blk;

    fill = bpf_map_lookup_elem(&tmp_btrfs ,&pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_btrfs, &pid);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;

    blk.hist_id = selection;
    blk.bin = libnetdata_select_idx(data);

    fill = bpf_map_lookup_elem(&tbl_btrfs ,&blk);
    if (fill) {
        libnetdata_update_u64(fill, 1);
    } else {
        data = 1;
        bpf_map_update_elem(&tbl_btrfs, &blk, &data, BPF_ANY);
    }

    return 0;
}

SEC("kretprobe/btrfs_file_write_iter")
int netdata_ret_btrfs_file_write_iter(struct pt_regs *ctx)
{
    return netdata_btrfs_end(ctx, NETDATA_KEY_CALLS_WRITE);
}

SEC("kretprobe/generic_file_open")
int netdata_ret_generic_file_open(struct pt_regs *ctx)
{
    return netdata_btrfs_end(ctx, NETDATA_KEY_CALLS_OPEN);
}

SEC("kretprobe/btrfs_sync_file")
int netdata_ret_btrfs_sync_file(struct pt_regs *ctx) 
{
    return netdata_btrfs_end(ctx, NETDATA_KEY_CALLS_SYNC);
}

SEC("kretprobe/generic_file_read_iter")
int netdata_ret_generic_file_read_iter(struct pt_regs *ctx) 
{
    return netdata_btrfs_end(ctx, NETDATA_KEY_CALLS_READ);
}

char _license[] SEC("license") = "GPL";

