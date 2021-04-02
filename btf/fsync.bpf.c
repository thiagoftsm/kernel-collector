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
} tbl_fsync SEC(".maps");

/************************************************************************************
 *
 *                               FSYNC SECTION
 *
 ***********************************************************************************/

#ifdef __x86_64__
SEC("kprobe/__x64_sys_fsync")
#elif defined(__s390x__)
SEC("kprobe/__s390x_sys_fsync")
#else
SEC("kprobe/__sys_fsync")
#endif
int BPF_KPROBE(netdata_syscall_fsync, int fd)
{
    libnetdata_update_global(&tbl_fsync, NETDATA_KEY_SYNC_CALL, 1);

    return 0;
}

/************************************************************************************
 *
 *                             END FSYNC SECTION
 *
 ***********************************************************************************/

