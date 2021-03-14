#define KBUILD_MODNAME "nfs_netdata"
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

struct bpf_map_def SEC("maps") tbl_nfs = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(netdata_fs_hist_t),
    .value_size = sizeof(__u64),
    .max_entries = 8192
};

struct bpf_map_def SEC("maps") tmp_nfs = {
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

static int netdata_nfs_entry(struct pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&tmp_nfs, &pid, &ts, BPF_ANY);

    return 0;
}

SEC("kprobe/nfs_file_read")
int netdata_nfs_file_read_iter(struct pt_regs *ctx) 
{
    return netdata_nfs_entry(ctx);
}

SEC("kprobe/nfs_file_write")
int netdata_nfs_file_write_iter(struct pt_regs *ctx) 
{
    return netdata_nfs_entry(ctx);
}

SEC("kprobe/nfs_file_open")
int netdata_nfs_file_open(struct pt_regs *ctx) 
{
    return netdata_nfs_entry(ctx);
}

SEC("kprobe/nfs4_file_open")
int netdata_nfs4_file_open(struct pt_regs *ctx) 
{
    return netdata_nfs_entry(ctx);
}

SEC("kprobe/nfs_getattr")
int netdata_nfs_sync_file(struct pt_regs *ctx) 
{
    return netdata_nfs_entry(ctx);
}

/************************************************************************************
 *     
 *                                 END Section
 *     
 ***********************************************************************************/

static int netdata_nfs_end(struct pt_regs *ctx, __u32 selection)
{
    __u64 *fill, data;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    netdata_fs_hist_t blk;

    fill = bpf_map_lookup_elem(&tmp_nfs, pid);
    if (!fill)
        return 0;

    data = bpf_ktime_get_ns() - *fill;
    bpf_map_delete_elem(&tmp_nfs, &pid);

    // Skip entries with backward time
    if ( (s64)data < 0)
        return 0;

    // convert to microseconds
    data /= 1000;

    blk.hist_id = selection;
    blk.bin = libnetdata_select_idx(data);

    fill = bpf_map_lookup_elem(&tbl_nfs ,&blk);
    if (fill) {
        libnetdata_update_u64(fill, 1);
    } else {
        data = 1;
        bpf_map_update_elem(&tbl_nfs, &blk, &data, BPF_ANY);
    }

    return 0;
}

SEC("kretprobe/nfs_file_read")
int netdata_ret_nfs_nfs_file_read_iter(struct pt_regs *ctx)
{
    return netdata_nfs_end(ctx, NETDATA_KEY_CALLS_READ);
}

SEC("kretprobe/nfs_file_write")
int netdata_ret_nfs_file_write_iter(struct pt_regs *ctx)
{
    return netdata_nfs_end(ctx, NETDATA_KEY_CALLS_WRITE);
}

SEC("kretprobe/nfs_file_open")
int netdata_ret_nfs_file_open(struct pt_regs *ctx)
{
    return netdata_nfs_end(ctx, NETDATA_KEY_CALLS_OPEN);
}

SEC("kretprobe/nfs4_file_open")
int netdata_ret_nfs4_file_open(struct pt_regs *ctx)
{
    return netdata_nfs_end(ctx, NETDATA_KEY_CALLS_OPEN);
}

SEC("kretprobe/nfs_getattr")
int netdata_ret_nfs_sync_file(struct pt_regs *ctx) 
{
    return netdata_nfs_end(ctx, NETDATA_KEY_CALLS_SYNC);
}

char _license[] SEC("license") = "GPL";

