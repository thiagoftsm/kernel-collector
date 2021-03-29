#define KBUILD_MODNAME "md_netdata"
#include <linux/bpf.h>
#include <linux/ptrace.h>

#include "bpf_helpers.h"
#include "netdata_ebpf.h"

/************************************************************************************
 *     
 *                                 MAPS
 *     
 ***********************************************************************************/

struct bpf_map_def SEC("maps") tbl_sync = {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)) 
    .type = BPF_MAP_TYPE_HASH,
#else
    .type = BPF_MAP_TYPE_PERCPU_HASH,
#endif    
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = NETDATA_MD_END
};

/************************************************************************************
 *
 *                               SYNC SECTION
 *
 ***********************************************************************************/

SEC("kprobe/md_flush_request")
int netdata_md_flush_request(struct pt_regs* ctx)
{
    libnetdata_update_global(&tbl_sync, NETDATA_KEY_MD_CALL, 1);

    return 0;
}

/************************************************************************************
 *
 *                             END SYNC SECTION
 *
 ***********************************************************************************/

char _license[] SEC("license") = "GPL";

