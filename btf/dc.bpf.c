#include "libnetdata_ebpf.h"
#include "netdata_dc.h"

/************************************************************************************
 *
 *                                   Maps Section
 *
 ***********************************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, NETDATA_DIRECTORY_CACHE_END);
    __type(key, u32);
    __type(value, u64);
} dcstat_global  SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 100000);
    __type(key, u32);
    __type(value, netdata_dc_stat_t);
} dcstat_pid SEC(".maps");

/************************************************************************************
 *
 *                                   Probe Section
 *
 ***********************************************************************************/

SEC("kprobe/lookup_fast")
int BPF_KPROBE(netdata_lookup_fast)
{
    netdata_dc_stat_t *fill, data = {};
    libnetdata_update_global(&dcstat_global, NETDATA_KEY_DC_REFERENCE, 1);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    fill = bpf_map_lookup_elem(&dcstat_pid ,&pid);
    if (fill) {
        libnetdata_update_u64(&fill->references, 1);
    } else {
        data.references = 1;
        bpf_map_update_elem(&dcstat_pid, &pid, &data, BPF_ANY);
    }

    return 0;
}

SEC("kretprobe/d_lookup")
int BPF_KPROBE(netdata_d_lookup, int ret)
{
    netdata_dc_stat_t *fill, data = {};
    libnetdata_update_global(&dcstat_global, NETDATA_KEY_DC_SLOW, 1);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    fill = bpf_map_lookup_elem(&dcstat_pid ,&pid);
    if (fill) {
        libnetdata_update_u64(&fill->slow, 1);
    } else {
        data.slow = 1;
        bpf_map_update_elem(&dcstat_pid, &pid, &data, BPF_ANY);
    }

    // file not found
    if (ret == 0) {
        libnetdata_update_global(&dcstat_global, NETDATA_KEY_DC_MISS, 1);
        fill = bpf_map_lookup_elem(&dcstat_pid ,&pid);
        if (fill) {
            libnetdata_update_u64(&fill->missed, 1);
        } else {
            data.missed = 1;
            bpf_map_update_elem(&dcstat_pid, &pid, &data, BPF_ANY);
        }
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

