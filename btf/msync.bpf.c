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
} tbl_msync SEC(".maps");

/************************************************************************************
 *
 *                               MSYNC SECTION
 *
 ***********************************************************************************/


SEC("kprobe/" NETDATA_SYSCALL(msync))
int BPF_KPROBE(netdata_syscall_sync)
{
    libnetdata_update_global(&tbl_msync, NETDATA_KEY_SYNC_CALL, 1);

    return 0;
}

/************************************************************************************
 *
 *                             END MSYNC SECTION
 *
 ***********************************************************************************/

