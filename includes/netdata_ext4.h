// SPDX-License-Identifier: GPL-3.0-or-later

#ifndef _NETDATA_EXT4_H_
#define _NETDATA_EXT4_H_ 1

typedef struct netdata_ext4_hist {
    u32 hist_id;
    u32 bin;
} netdata_ext4_hist_t;

enum ext4_counters {
    NETDATA_KEY_CALLS_READ,
    NETDATA_KEY_CALLS_WRITE,
    NETDATA_KEY_CALLS_OPEN,
    NETDATA_KEY_CALLS_SYNC,

    NETDATA_EXT4_END
};

#define NETDATA_EXT4_MAX_BINS 32UL
#define NETDATA_EXT4_MAX_BINS_POS (NETDATA_EXT4_MAX_BINS - 1)
#define NETDATA_EXT4_HISTOGRAM_LENGTH  (NETDATA_EXT4_MAX_BINS * NETDATA_EXT4_MAX_BINS)


#endif /* _NETDATA_EXT4_H_ */

