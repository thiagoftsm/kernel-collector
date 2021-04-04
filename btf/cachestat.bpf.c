#include "libnetdata_ebpf.h"
#include "netdata_cache.h"

/************************************************************************************
 *
 *                                   MAPS
 *
 ***********************************************************************************/

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, NETDATA_CACHESTAT_END);
    __type(key, u32);
    __type(value, u64);
} cstat_global SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 100000);
    __type(key, u32);
    __type(value, netdata_cachestat_t);
} cstat_pid SEC(".maps");

/************************************************************************************
 *
 *                                   Probe Section
 *
 ***********************************************************************************/

SEC("kprobe/add_to_page_cache_lru")
int BPF_KPROBE(netdata_add_to_page_cache_lru)
{
    netdata_cachestat_t *fill, data = {};
    libnetdata_update_global(&cstat_global, NETDATA_KEY_CALLS_ADD_TO_PAGE_CACHE_LRU, 1);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    fill = bpf_map_lookup_elem(&cstat_pid ,&pid);
    if (fill) {
        libnetdata_update_u64(&fill->add_to_page_cache_lru, 1);
    } else {
        data.add_to_page_cache_lru = 1;
        bpf_map_update_elem(&cstat_pid, &pid, &data, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/mark_page_accessed")
int BPF_KPROBE(netdata_mark_page_accessed)
{
    netdata_cachestat_t *fill, data = {};
    libnetdata_update_global(&cstat_global, NETDATA_KEY_CALLS_MARK_PAGE_ACCESSED, 1);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    fill = bpf_map_lookup_elem(&cstat_pid ,&pid);
    if (fill) {
        libnetdata_update_u64(&fill->mark_page_accessed, 1);
    } else {
        data.mark_page_accessed = 1;
        bpf_map_update_elem(&cstat_pid, &pid, &data, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/account_page_dirtied")
int BPF_KPROBE(netdata_account_page_dirtied)
{
    netdata_cachestat_t *fill, data = {};
    libnetdata_update_global(&cstat_global, NETDATA_KEY_CALLS_ACCOUNT_PAGE_DIRTIED, 1);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    fill = bpf_map_lookup_elem(&cstat_pid ,&pid);
    if (fill) {
        libnetdata_update_u64(&fill->account_page_dirtied, 1);
    } else {
        data.account_page_dirtied = 1;
        bpf_map_update_elem(&cstat_pid, &pid, &data, BPF_ANY);
    }

    return 0;
}

SEC("kprobe/mark_buffer_dirty")
int BPF_KPROBE(netdata_mark_buffer_dirty)
{
    netdata_cachestat_t *fill, data = {};
    libnetdata_update_global(&cstat_global, NETDATA_KEY_CALLS_MARK_BUFFER_DIRTY, 1);

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid >> 32);
    fill = bpf_map_lookup_elem(&cstat_pid ,&pid);
    if (fill) {
        libnetdata_update_u64(&fill->mark_buffer_dirty, 1);
    } else {
        data.mark_buffer_dirty = 1;
        bpf_map_update_elem(&cstat_pid, &pid, &data, BPF_ANY);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";

