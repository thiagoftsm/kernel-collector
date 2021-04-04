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

SEC("kprobe/" NETDATA_SYSCALL(fdatasync))
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

