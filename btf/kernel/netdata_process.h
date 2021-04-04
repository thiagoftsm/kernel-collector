// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_EBPF_PROCESS_H_
#define _NETDATA_EBPF_PROCESS_H_ 1

struct netdata_pid_stat_t {
    u64 pid_tgid;                     //Unique identifier
    u32 pid;                          //process id

    //Counter
    u32 open_call;                    //open syscalls (open and openat)
    u32 write_call;                   //Write syscalls (write and writev)
    u32 writev_call;                   //Write syscalls (write and writev)
    u32 read_call;                    //Read syscalls ( read and readv)
    u32 readv_call;                    //Read syscalls ( read and readv)
    u32 unlink_call;                  //Remove syscalls (unlink for while)
    u32 exit_call;                    //Exit syscalls (exit for exit_group)
    u32 release_call;                 //Exit syscalls (exit and exit_group)
    u32 fork_call;                    //Start syscall (fork, clone, forkv)
    u32 clone_call;                    //Start syscall (fork, clone, forkv)
    u32 close_call;                   //Close syscall (close)

    //Accumulator
    u64 write_bytes;
    u64 writev_bytes;
    u64 readv_bytes;
    u64 read_bytes;

    //Counter
    u32 open_err;
    u32 write_err;
    u32 writev_err;
    u32 read_err;
    u32 readv_err;
    u32 unlink_err;
    u32 fork_err;
    u32 clone_err;
    u32 close_err;

    u8 removeme;
};

enum process_counters {
    NETDATA_KEY_CALLS_DO_SYS_OPEN,
    NETDATA_KEY_ERROR_DO_SYS_OPEN,

    NETDATA_KEY_CALLS_VFS_WRITE,
    NETDATA_KEY_ERROR_VFS_WRITE,
    NETDATA_KEY_BYTES_VFS_WRITE,

    NETDATA_KEY_CALLS_VFS_READ,
    NETDATA_KEY_ERROR_VFS_READ,
    NETDATA_KEY_BYTES_VFS_READ,

    NETDATA_KEY_CALLS_VFS_UNLINK,
    NETDATA_KEY_ERROR_VFS_UNLINK,

    NETDATA_KEY_CALLS_DO_EXIT,

    NETDATA_KEY_CALLS_RELEASE_TASK,

    NETDATA_KEY_CALLS_DO_FORK,
    NETDATA_KEY_ERROR_DO_FORK,

    NETDATA_KEY_CALLS_CLOSE_FD,
    NETDATA_KEY_ERROR_CLOSE_FD,

    NETDATA_KEY_CALLS_SYS_CLONE,
    NETDATA_KEY_ERROR_SYS_CLONE,

    NETDATA_KEY_CALLS_VFS_WRITEV,
    NETDATA_KEY_ERROR_VFS_WRITEV,
    NETDATA_KEY_BYTES_VFS_WRITEV,

    NETDATA_KEY_CALLS_VFS_READV,
    NETDATA_KEY_ERROR_VFS_READV,
    NETDATA_KEY_BYTES_VFS_READV,

    // Keep this as last and don't skip numbers as it is used as element counter
    NETDATA_GLOBAL_COUNTER
};

#endif /* _NETDATA_EBPF_PROCESS_H_ */
