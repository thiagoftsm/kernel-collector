#define KBUILD_MODNAME "latency_tp_netdata"
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/genhd.h>

#include "bpf_helpers.h"
#include "netdata_ebpf.h"

/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

//Hardware
struct bpf_map_def SEC("maps") tbl_disk_rcall = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(block_key_t),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_LATENCY_HISTOGRAM_LENGTH
};

// NOT HISTOGRAM, VALUES PER SECOND
struct bpf_map_def SEC("maps") tbl_disk_rbytes = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(block_key_t),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_LATENCY_MAX_HD
};

struct bpf_map_def SEC("maps") tbl_disk_wcall = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(block_key_t),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_LATENCY_HISTOGRAM_LENGTH
};

struct bpf_map_def SEC("maps") tbl_disk_wbytes = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(block_key_t),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_LATENCY_MAX_HD
};

struct bpf_map_def SEC("maps") tbl_io_error = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(block_key_t),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_LATENCY_MAX_BINS
};

/*
struct bpf_map_def SEC("maps") tbl_io_latency = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_IO_LATENCY_COUNTER
};
*/

/*
struct bpf_map_def SEC("maps") tbl_md_flush = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
    .key_size = sizeof(netdata_flush_key_t),
    .value_size = sizeof(u64),
    .max_entries = NETDATA_LATENCY_MAX_HD
};
*/

struct bpf_map_def SEC("maps") tbl_security_info = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(dev_t),
    .value_size = sizeof(netdata_bootsector_t),
    .max_entries = NETDATA_LATENCY_MAX_HD
};

// Temporary use only
struct bpf_map_def SEC("maps") tmp_disk_tp_stat = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0))
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif
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

/*
static void netdata_update_global(__u64 key, __u64 value)
{
    __u64 *res;
    res = bpf_map_lookup_elem(&tbl_io_latency, &key);
    if (res) {
        netdata_update_u64(res, value) ;
    } else
        bpf_map_update_elem(&tbl_io_latency, &key, &value, BPF_NOEXIST);
}
*/

/************************************************************************************
 *     
 *                                 END COMMON SECTION
 *     
 ***********************************************************************************/

/************************************************************************************
 *     
 *                                 DISK SECTION
 *     
 ***********************************************************************************/

// Probably it is available after 4.13 only

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

    bpf_map_update_elem(&tmp_disk_tp_stat, &key, &value, BPF_ANY);

    return 0;
}

SEC("tracepoint/block/block_rq_complete")
int netdata_block_rq_complete(struct netdata_block_rq_complete *ptr)
{
    netdata_disk_value_t *fill;
    netdata_disk_key_t key = {};
    block_key_t blk = {};
    key.dev = ptr->dev;
    key.sector = ptr->sector;

    if (key.sector < 0)
        key.sector = 0;

    fill = bpf_map_lookup_elem(&tmp_disk_tp_stat ,&key);
    if (!fill)
        return 0;

    // W - write
    // S - Sync
    int selector = ((ptr->rwbs[0] == 'F') || (ptr->rwbs[0] == 'S') || (ptr->rwbs[0] == 'W') ||
                    (ptr->rwbs[1] == 'F') || (ptr->rwbs[1] == 'S') || (ptr->rwbs[0] == 'W'));

    u64 bytes = (u64)fill->bytes;

    // calculate and convert to microsecond
    u64 curr = bpf_ktime_get_ns();
    __u64 data, *update;
    curr -= fill->timestamp;
    curr /= 1000;

    blk.bin = select_idx(curr);
    blk.dev = new_encode_dev(ptr->dev);

    // Update IOPS
    struct bpf_map_def *tbl = (!selector)?&tbl_disk_rcall:&tbl_disk_wcall;
    update = bpf_map_lookup_elem(tbl ,&blk);
    if (update) {
        netdata_update_u64(update, 1);
    } else {
        data = 1;
        bpf_map_update_elem(tbl, &blk, &data, BPF_ANY);
    }

    blk.bin =  0;

    tbl = (!selector)?&tbl_disk_rbytes:&tbl_disk_wbytes;
    update = bpf_map_lookup_elem(tbl ,&blk);
    if (update) {
        netdata_update_u64(update, bytes);
    } else {
        bpf_map_update_elem(tbl, &blk, &bytes, BPF_ANY);
    }

    bpf_map_delete_elem(&tmp_disk_tp_stat, &key);

    // UEFI and MBR
    if (selector) {
        netdata_bootsector_t *rm = bpf_map_lookup_elem(&tbl_security_info ,&key.dev);
        if (rm) {
            if (rm->start_sector <= key.sector && key.sector <= rm->end_sector) {
                data = bpf_get_current_pid_tgid();

                rm->timestamp = bpf_ktime_get_ns();
                rm->changed_sector = (u64)key.sector;
                rm->size = bytes;
            }
        }
    }

    // ERROR
    blk.bin = ptr->error;
    update = bpf_map_lookup_elem(&tbl_io_error ,&blk);
    if (update) {
        netdata_update_u64(update, 1);
    } else {
        data = 1;
        bpf_map_update_elem(&tbl_io_error, &blk, &data, BPF_ANY);
    }

    return 0;
}

/************************************************************************************
 *     
 *                               END DISK SECTION
 *     
 ***********************************************************************************/
/************************************************************************************
 *     
 *                               MOUNT SECTION
 *     
 ***********************************************************************************/

/*
SEC("kretprobe/" NETDATA_SYSCALL(mount)) 
int netdata_syscall_mount(struct pt_regs* ctx)
{
    netdata_update_global(NETDATA_KEY_CALL_MOUNT_CALL, 1);

    int ret = (ssize_t)PT_REGS_RC(ctx);
    if (ret < 0)
        netdata_update_global(NETDATA_KEY_CALL_MOUNT_ERR, 1);

    return 0;
}

SEC("kretprobe/" NETDATA_SYSCALL(umount)) 
int netdata_syscall_umount(struct pt_regs* ctx)
{
    netdata_update_global(NETDATA_KEY_CALL_UMOUNT_CALL, 1);

    int ret = (ssize_t)PT_REGS_RC(ctx);
    if (ret < 0)
        netdata_update_global(NETDATA_KEY_CALL_UMOUNT_ERR, 1);

    return 0;
}
*/

/************************************************************************************
 *     
 *                             END MOUNT SECTION
 *     
 ***********************************************************************************/

char _license[] SEC("license") = "GPL";

