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
} tbl_syncfr SEC(".maps");

/************************************************************************************
 *
 *                               SYNC_FILE_RANGE SECTION
 *
 ***********************************************************************************/

SEC("kprobe/__x64_sys_sync_file_range")
int BPF_KPROBE(netdata_syscall_sync_file_range)
{
    libnetdata_update_global(&tbl_syncfr, NETDATA_KEY_SYNC_CALL, 1);

    return 0;
}

/************************************************************************************
 *
 *                             END SYNC_FILE_RANGE SECTION
 *
 ***********************************************************************************/

