#include "kernel/vmlinux_5_10.h"
#include "kernel/vmlinux_5_10.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "netdata_sync.h"
//#include "libnetdata_ebpf.h"

// Use __always_inline instead inline to keep compatiblity with old kernels
// https://docs.cilium.io/en/v1.8/bpf/
// The condition to test kernel was added, because __always_inline broke the epbf.plugin
// on CentOS 7 and Ubuntu 18.04 (kernel 4.18)
static __always_inline void libnetdata_update_u64(u64 *res, u64 value)
{
    __sync_fetch_and_add(res, value);
    if ( (0xFFFFFFFFFFFFFFFF - *res) <= value) {
        *res = value;
    }
}

static __always_inline void libnetdata_update_global(void *tbl,u32 key, u64 value)
{
    u64 *res;
    res = bpf_map_lookup_elem(tbl, &key);
    if (res)
        libnetdata_update_u64(res, value) ;
    else
        bpf_map_update_elem(tbl, &key, &value, BPF_NOEXIST);
}


/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, NETDATA_SYNC_END);
        __type(key, u32);
        __type(value, u64);
} tbl_sync SEC(".maps");

/************************************************************************************
 *
 *                               SYNC SECTION
 *
 ***********************************************************************************/

SEC("kprobe/__x64_sys_sync")
int BPF_KPROBE(netdata_syscall_sync)
{
    libnetdata_update_global(&tbl_sync, NETDATA_KEY_SYNC_CALL, 1);

    return 0;
}

/************************************************************************************
 *
 *                             END SYNC SECTION
 *
 ***********************************************************************************/

char _license[] SEC("license") = "GPL";

