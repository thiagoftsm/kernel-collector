#include "libnetdata_ebpf.h"
#include "netdata_process.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, u32);
    __type(value, struct netdata_pid_stat_t);
} tbl_pid_stats  SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, NETDATA_GLOBAL_COUNTER);
    __type(key, u32);
    __type(value, u64);
} tbl_total_stats  SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u32);
} tbl_syscall_stats  SEC(".maps");


/************************************************************************************
 *     
 *                                 COMMON Section
 *     
 ***********************************************************************************/

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

static unsigned int log2l(unsigned long v)
{
    unsigned int hi = v >> 32;
    if (hi)
        return log2(hi) + 32;
    else
        return log2(v);
}

static void netdata_update_u32(u32 *res, u32 value) 
{
    if (!value)
        return;

    __sync_fetch_and_add(res, value);
    if ( (0xFFFFFFFFFFFFFFFF - *res) <= value) {
        *res = value;
    }
}

/************************************************************************************
 *     
 *                                   FILE Section
 *     
 ***********************************************************************************/

SEC("kprobe/vfs_write")
int netdata_vfs_write(struct pt_regs* ctx)
{
    struct netdata_pid_stat_t *fill;
    struct netdata_pid_stat_t data = { };
    size_t size = PT_REGS_PARM3(ctx);
    u64 tot;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    u32 tgid = (u32)( 0x00000000FFFFFFFF & pid_tgid);

    tot = log2l(size);

    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_VFS_WRITE, 1);
    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_BYTES_VFS_WRITE, tot);

    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->write_call, 1) ;

        libnetdata_update_u64(&fill->write_bytes, tot);
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  
        data.write_call = 1;
        data.write_bytes = tot;

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }

    return 0;
}


SEC("kretprobe/vfs_write")
int BPF_KRETPROBE(netdata_ret_vfs_write, ssize_t ret)
{
    if (ret >= 0)
        return 0;

    struct netdata_pid_stat_t *fill;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_ERROR_VFS_WRITE, 1);
        netdata_update_u32(&fill->write_err, 1) ;
    }

    return 0;
}

SEC("kprobe/vfs_writev")
int netdata_vfs_writev(struct pt_regs* ctx)
{
    struct netdata_pid_stat_t *fill;
    struct netdata_pid_stat_t data = { };
    size_t size = PT_REGS_PARM3(ctx);
    u64 tot;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    u32 tgid = (u32)( 0x00000000FFFFFFFF & pid_tgid);

    tot = log2l(size);

    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_VFS_WRITEV, 1);
    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_BYTES_VFS_WRITEV, tot);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->writev_call, 1) ;

        libnetdata_update_u64(&fill->writev_bytes, tot);
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  
        data.writev_call = 1;
        data.writev_bytes = tot;

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }

    return 0;
}

SEC("kretprobe/vfs_writev")
int BPF_KRETPROBE(netdata_ret_vfs_writev, ssize_t ret)
{
    if (ret >= 0)
        return 0;

    struct netdata_pid_stat_t *fill;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_ERROR_VFS_WRITEV, 1);
        netdata_update_u32(&fill->writev_err, 1) ;
    }

    return 0;
}

SEC("kprobe/vfs_read")
int netdata_vfs_read(struct pt_regs* ctx)
{
    struct netdata_pid_stat_t *fill;
    struct netdata_pid_stat_t data = { };
    size_t size = PT_REGS_PARM3(ctx);
    u64 tot;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    u32 tgid = (u32)( 0x00000000FFFFFFFF & pid_tgid);

    tot = log2l(size);

    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_VFS_READ, 1);
    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_BYTES_VFS_READ, tot);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->read_call, 1) ;

        libnetdata_update_u64(&fill->read_bytes, tot);
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  
        data.read_call = 1;
        data.read_bytes = tot;

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }

    return 0;
}

SEC("kretprobe/vfs_read")
int BPF_KRETPROBE(netdata_ret_vfs_read, ssize_t ret)
{
    if (ret >= 0)
        return 0;

    struct netdata_pid_stat_t *fill;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_ERROR_VFS_READ, 1);
        netdata_update_u32(&fill->read_err, 1) ;
    }

    return 0;
}

SEC("kprobe/vfs_readv")
int netdata_vfs_readv(struct pt_regs* ctx)
{
    struct netdata_pid_stat_t *fill;
    struct netdata_pid_stat_t data = { };
    size_t size = PT_REGS_PARM3(ctx);
    u64 tot;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    u32 tgid = (u32)( 0x00000000FFFFFFFF & pid_tgid);

    tot = log2l(size);

    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_VFS_READV, 1);
    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_BYTES_VFS_READV, tot);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->readv_call, 1) ;

        libnetdata_update_u64(&fill->readv_bytes, tot);
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  
        data.readv_call = 1;
        data.readv_bytes = tot;

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }

    return 0;
}

SEC("kretprobe/vfs_readv")
int BPF_KRETPROBE(netdata_ret_vfs_readv, ssize_t ret)
{
    if (ret >= 0)
        return 0;

    struct netdata_pid_stat_t *fill;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_ERROR_VFS_READV, 1);
        netdata_update_u32(&fill->readv_err, 1) ;
    }

    return 0;
}

SEC("kprobe/do_sys_openat2")
int netdata_do_sys_openat2(struct pt_regs* ctx)
{
    struct netdata_pid_stat_t *fill;
    struct netdata_pid_stat_t data = { };
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);

    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_DO_SYS_OPEN, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->open_call, 1) ;
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  
        data.open_call = 1;

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }

    return 0;
}

SEC("kretprobe/do_sys_openat2")
int BPF_KRETPROBE(netdata_ret_do_sys_openat2, long ret)
{
    if (ret >= 0 )
        return 0;

    struct netdata_pid_stat_t *fill;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_ERROR_DO_SYS_OPEN, 1);
        netdata_update_u32(&fill->open_err, 1) ;
    }

    return 0;
}

SEC("kprobe/vfs_unlink")
int netdata_vfs_unlink(struct pt_regs* ctx)
{
    struct netdata_pid_stat_t data = { };
    struct netdata_pid_stat_t *fill;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    u32 tgid = (u32)( 0x00000000FFFFFFFF & pid_tgid);

    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_VFS_UNLINK, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->unlink_call, 1) ;
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  
        data.unlink_call = 1;

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }

    return 0;
}

SEC("kretprobe/vfs_unlink")
int BPF_KRETPROBE(netdata_ret_vfs_unlink, long ret)
{
    if (ret >= 0 )
        return 0;

    struct netdata_pid_stat_t *fill;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_ERROR_VFS_UNLINK, 1);
        netdata_update_u32(&fill->unlink_err, 1) ;
    }

    return 0;
}

/************************************************************************************
 *     
 *                                   PROCESS Section
 *     
 ***********************************************************************************/

SEC("kprobe/do_exit")
int netdata_sys_exit(struct pt_regs* ctx)
{
    struct netdata_pid_stat_t *fill;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    u32 tgid = (u32)( 0x00000000FFFFFFFF & pid_tgid);

    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_DO_EXIT, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->exit_call, 1) ;
    } 

    return 0;
}

SEC("kprobe/release_task")
int netdata_release_task(struct pt_regs* ctx)
{
    struct netdata_pid_stat_t *fill;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    u32 tgid = (u32)( 0x00000000FFFFFFFF & pid_tgid);

    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_RELEASE_TASK, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->release_call, 1) ;
        fill->removeme = 1;
    }

    return 0;
}

/*
 * when 0 is returned the father has the son cloned, when they 
 * http://www2.comp.ufscar.br/mediawiki/index.php/Grupo_16
SEC("kprobe/kernel_clone")
int netdata_kernel_clone(struct pt_regs* ctx)
{
    struct netdata_pid_stat_t data = { };
    struct netdata_pid_stat_t *fill;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);
    u32 tgid = (u32)( 0x00000000FFFFFFFF & pid_tgid);


    return 0;
}

SEC("kretprobe/kernel_clone")
int BPF_KRETPROBE(netdata_ret_kernel_clone, pid_t ret)
{
    if (ret >= 0 )
        return 0;

    struct netdata_pid_stat_t *fill;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);

    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_ERROR_SYS_CLONE, 1);
        netdata_update_u32(&fill->fork_err, 1) ;
    }

    return 0;
}

#if NETDATASEL < 2
// https://lore.kernel.org/patchwork/patch/1290639/
SEC("kretprobe/kernel_clone")
#else
SEC("kprobe/kernel_clone")
#endif
int netdata_sys_clone(struct pt_regs *ctx)
{

    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_DO_FORK, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        fill->release_call = 0;
        netdata_update_u32(&fill->fork_call, 1) ;

        if(threads) {
            netdata_update_u32(&fill->clone_call, 1) ;
        }

#if NETDATASEL < 2
        if (ret < 0) {
            netdata_update_u32(&fill->fork_err, 1) ;
            libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_ERROR_DO_FORK, 1);
            if(threads) {
                libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_ERROR_SYS_CLONE, 1);
                netdata_update_u32(&fill->clone_err, 1) ;
            }
        } 
#endif
    } else {
        data.pid_tgid = pid_tgid;
        data.pid = tgid;
        data.fork_call = 1;
        if(threads) {
            data.clone_call = 1;
        }
#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_ERROR_DO_FORK, 1);
            data.fork_err = 1;
            if (threads) {
                libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_ERROR_SYS_CLONE, 1);
                data.clone_err = 1;
            }
        }
#endif

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }
    return 0;
}

#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)) 
#if NETDATASEL < 2
SEC("kretprobe/close_fd")
#else
SEC("kprobe/close_fd")
#endif
#else
#if NETDATASEL < 2
SEC("kretprobe/__close_fd")
#else
SEC("kprobe/__close_fd")
#endif
#endif
int netdata_close(struct pt_regs* ctx)
{
#if NETDATASEL < 2
    int ret = (int)PT_REGS_RC(ctx);
#endif
    struct netdata_pid_stat_t data = { };
    struct netdata_pid_stat_t *fill;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);

    libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_CALLS_CLOSE_FD, 1);
    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (fill) {
        netdata_update_u32(&fill->close_call, 1) ;

#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_ERROR_CLOSE_FD, 1);
            netdata_update_u32(&fill->close_err, 1) ;
        } 
#endif
    } else {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  
        data.close_call = 1;
#if NETDATASEL < 2
        if (ret < 0) {
            libnetdata_update_global(&tbl_total_stats, NETDATA_KEY_ERROR_CLOSE_FD, 1);
            data.close_err = 1;
        } 
#endif

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/try_to_wake_up")
int netdata_enter_try_to_wake_up(struct pt_regs* ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    __u32 tgid = (__u32)( 0x00000000FFFFFFFF & pid_tgid);
    struct netdata_pid_stat_t *fill;
    struct netdata_pid_stat_t data = { };

    fill = bpf_map_lookup_elem(&tbl_pid_stats ,&pid);
    if (!fill) {
        data.pid_tgid = pid_tgid;  
        data.pid = tgid;  

        bpf_map_update_elem(&tbl_pid_stats, &pid, &data, BPF_ANY);
    }


    return 0;
}
*/

char _license[] SEC("license") = "GPL";
