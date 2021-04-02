#ifndef _LIBNETDATA_EBPF_
#define _LIBNETDATA_EBPF_ 1

#include "vmlinux_5_10.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifdef __x86_64__
#define NETDATA_SYSCALL(SYS) "__x64_sys_"
#elif defined(__s390x__)
#define NETDATA_SYSCALL(SYS) "__s390x_"
#else
#define NETDATA_SYSCALL(SYS) "sys_"
#endif


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

#endif
