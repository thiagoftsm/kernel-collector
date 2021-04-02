#include "libnetdata_ebpf.h"
#include "netdata_sync.h"

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
} tbl_fdatasync SEC(".maps");

/************************************************************************************
 *
 *                               FDATASYNC SECTION
 *
 ***********************************************************************************/

#ifdef __x86_64__
SEC("kprobe/__x64_sys_fdatasync")
#elif defined(__s390x__)
SEC("kprobe/__s390x_sys_fdatasync")
#else
SEC("kprobe/__sys_fdatasync")
#endif
int BPF_KPROBE(netdata_syscall_fdatasync)
{
    libnetdata_update_global(&tbl_fdatasync, NETDATA_KEY_SYNC_CALL, 1);

    return 0;
}

/************************************************************************************
 *
 *                             END FDATASYNC SECTION
 *
 ***********************************************************************************/

