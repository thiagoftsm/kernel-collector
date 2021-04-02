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
} tbl_sync SEC(".maps");

/************************************************************************************
 *
 *                               SYNC SECTION
 *
 ***********************************************************************************/

#ifdef __x86_64__
SEC("kprobe/__x64_sys_sync")
#elif defined(__s390x__)
SEC("kprobe/__s390x_sys_sync")
#else
SEC("kprobe/__sys_sync")
#endif
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

