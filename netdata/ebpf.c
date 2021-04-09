#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <pthread.h>
#include <unistd.h>

#include "cachestat.skel.h"
#include "dc.skel.h"
#include "sync.skel.h"
#include "syncfs.skel.h"
#include "msync.skel.h"
#include "fsync.skel.h"
#include "fdatasync.skel.h"
#include "sync_file_range.skel.h"
#include "process.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level,
                const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

static int bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = {
        .rlim_cur       = RLIM_INFINITY,
        .rlim_max       = RLIM_INFINITY,
    };

    return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}


void *sync_thread(void *ptr)
{
    char *localname = { "sync" };
    int *sl = ptr;
    struct sync_bpf *obj = NULL;
    struct bpf_object *obj_sl = NULL;
    struct bpf_map *map;
    int i;
    if (*sl == 0) {
        printf("STATIC\n");
        obj = sync_bpf__open();
        if (!obj) {
            fprintf(stderr, "Cannot allocate %s\n", localname);
            return NULL;
        }

        int err = sync_bpf__load(obj);
        if (err) {
            fprintf(stderr, "Error to load %s %d\n", localname, err);
            goto endsync;
        }

        err = sync_bpf__attach(obj);
        if (err) {
            fprintf(stderr, "Error to attach %s %d\n", localname, err);
            goto endsync;
        }

        printf("MAP ID: %d\n", bpf_map__fd(obj->maps.tbl_sync));
    } else {
        printf("SHARED\n");
        obj_sl = bpf_object__open("../kernel/psync_kern.o");
        bpf_object__load(obj_sl);

        bpf_map__for_each(map, obj_sl)
        {
            printf("%d\n", bpf_map__fd(map));
        }

    }

    for ( i = 0; i < 10 ; i++) {
        sleep(1);
    }


endsync:
    if (*sl == 0) {
        sync_bpf__destroy(obj);
    } else {
        bpf_object__unload(obj_sl);
    }

    return NULL;
}

void *msync_thread(void *ptr)
{
    char *localname = { "msync" };
    int *sl = ptr;
    struct msync_bpf *obj = NULL;
    struct bpf_object *obj_sl = NULL;
    struct bpf_map *map;
    int i;
    if (*sl == 0) {
        printf("STATIC\n");
        obj = msync_bpf__open();
        if (!obj) {
            fprintf(stderr, "Cannot allocate %s\n", localname);
            return NULL;
        }

        int err = msync_bpf__load(obj);
        if (err) {
            fprintf(stderr, "Error to load %s %d\n", localname, err);
            goto endmsync;
        }

        err = msync_bpf__attach(obj);
        if (err) {
            fprintf(stderr, "Error to attach %s %d\n", localname, err);
            goto endmsync;
        }

        printf("MAP ID: %d\n", bpf_map__fd(obj->maps.tbl_msync));
    } else {
        printf("SHARED\n");
        obj_sl = bpf_object__open("../kernel/pmsync_kern.o");
        bpf_object__load(obj_sl);

        bpf_map__for_each(map, obj_sl)
        {
            printf("%d\n", bpf_map__fd(map));
        }

    }

    for ( i = 0; i < 10 ; i++) {
        sleep(1);
    }


endmsync:
    if (*sl == 0) {
        msync_bpf__destroy(obj);
    } else {
        bpf_object__unload(obj_sl);
    }

    return NULL;
}

void *fsync_thread(void *ptr)
{
    char *localname = { "fsync" };
    int *sl = ptr;
    struct fsync_bpf *obj = NULL;
    struct bpf_object *obj_sl = NULL;
    struct bpf_map *map;
    int i;
    if (*sl == 0) {
        printf("STATIC\n");
        obj = fsync_bpf__open();
        if (!obj) {
            fprintf(stderr, "Cannot allocate %s\n", localname);
            return NULL;
        }

        int err = fsync_bpf__load(obj);
        if (err) {
            fprintf(stderr, "Error to load %s %d\n", localname, err);
            goto endfsync;
        }

        err = fsync_bpf__attach(obj);
        if (err) {
            fprintf(stderr, "Error to attach %s %d\n", localname, err);
            goto endfsync;
        }

        printf("MAP ID: %d\n", bpf_map__fd(obj->maps.tbl_fsync));
    } else {
        printf("SHARED\n");
        obj_sl = bpf_object__open("../kernel/pfsync_kern.o");
        bpf_object__load(obj_sl);

        bpf_map__for_each(map, obj_sl)
        {
            printf("%d\n", bpf_map__fd(map));
        }

    }

    for ( i = 0; i < 10 ; i++) {
        sleep(1);
    }


endfsync:
    if (*sl == 0) {
        fsync_bpf__destroy(obj);
    } else {
        bpf_object__unload(obj_sl);
    }

    return NULL;
}

void *syncfs_thread(void *ptr)
{
    char *localname = { "syncfs" };
    int *sl = ptr;
    struct syncfs_bpf *obj = NULL;
    struct bpf_object *obj_sl = NULL;
    struct bpf_map *map;
    int i;
    if (*sl == 0) {
        printf("STATIC\n");
        obj = syncfs_bpf__open();
        if (!obj) {
            fprintf(stderr, "Cannot allocate %s\n", localname);
            return NULL;
        }

        int err = syncfs_bpf__load(obj);
        if (err) {
            fprintf(stderr, "Error to load %s %d\n", localname, err);
            goto endsyncfs;
        }

        err = syncfs_bpf__attach(obj);
        if (err) {
            fprintf(stderr, "Error to attach %s %d\n", localname, err);
            goto endsyncfs;
        }

        printf("MAP ID: %d\n", bpf_map__fd(obj->maps.tbl_syncfs));
    } else {
        printf("SHARED\n");
        obj_sl = bpf_object__open("../kernel/psyncfs_kern.o");
        bpf_object__load(obj_sl);

        bpf_map__for_each(map, obj_sl)
        {
            printf("%d\n", bpf_map__fd(map));
        }

    }

    for ( i = 0; i < 10 ; i++) {
        sleep(1);
    }


endsyncfs:
    if (*sl == 0) {
        syncfs_bpf__destroy(obj);
    } else {
        bpf_object__unload(obj_sl);
    }

    return NULL;
}

void *fdatasync_thread(void *ptr)
{
    char *localname = { "fdatasync" };
    int *sl = ptr;
    struct fdatasync_bpf *obj = NULL;
    struct bpf_object *obj_sl = NULL;
    struct bpf_map *map;
    int i;
    if (*sl == 0) {
        printf("STATIC\n");
        obj = fdatasync_bpf__open();
        if (!obj) {
            fprintf(stderr, "Cannot allocate %s\n", localname);
            return NULL;
        }

        int err = fdatasync_bpf__load(obj);
        if (err) {
            fprintf(stderr, "Error to load %s %d\n", localname, err);
            goto endfdatasync;
        }

        err = fdatasync_bpf__attach(obj);
        if (err) {
            fprintf(stderr, "Error to attach %s %d\n", localname, err);
            goto endfdatasync;
        }

        printf("MAP ID: %d\n", bpf_map__fd(obj->maps.tbl_fdatasync));
    } else {
        printf("SHARED\n");
        obj_sl = bpf_object__open("../kernel/pfdatasync_kern.o");
        bpf_object__load(obj_sl);

        bpf_map__for_each(map, obj_sl)
        {
            printf("%d\n", bpf_map__fd(map));
        }

    }

    for ( i = 0; i < 10 ; i++) {
        sleep(1);
    }


endfdatasync:
    if (*sl == 0) {
        fdatasync_bpf__destroy(obj);
    } else {
        bpf_object__unload(obj_sl);
    }

    return NULL;
}

void *sync_file_range_thread(void *ptr)
{
    char *localname = { "sync_file_range" };
    int *sl = ptr;
    struct sync_file_range_bpf *obj = NULL;
    struct bpf_object *obj_sl = NULL;
    struct bpf_map *map;
    int i;
    if (*sl == 0) {
        printf("STATIC\n");
        obj = sync_file_range_bpf__open();
        if (!obj) {
            fprintf(stderr, "Cannot allocate %s\n", localname);
            return NULL;
        }

        int err = sync_file_range_bpf__load(obj);
        if (err) {
            fprintf(stderr, "Error to load %s %d\n", localname, err);
            goto endsync_file_range;
        }

        err = sync_file_range_bpf__attach(obj);
        if (err) {
            fprintf(stderr, "Error to attach %s %d\n", localname, err);
            goto endsync_file_range;
        }

        printf("MAP ID: %d\n", bpf_map__fd(obj->maps.tbl_syncfr));
    } else {
        printf("SHARED\n");
        obj_sl = bpf_object__open("../kernel/psync_file_range_kern.o");
        bpf_object__load(obj_sl);

        bpf_map__for_each(map, obj_sl)
        {
            printf("%d\n", bpf_map__fd(map));
        }

    }

    for ( i = 0; i < 10 ; i++) {
        sleep(1);
    }


endsync_file_range:
    if (*sl == 0) {
        sync_file_range_bpf__destroy(obj);
    } else {
        bpf_object__unload(obj_sl);
    }

    return NULL;
}

void *cachestat_thread(void *ptr)
{
    char *localname = { "cachestat" };
    int *sl = ptr;
    struct cachestat_bpf *obj = NULL;
    struct bpf_object *obj_sl = NULL;
    struct bpf_map *map;
    int i;
    if (*sl == 0) {
        printf("STATIC\n");
        obj = cachestat_bpf__open();
        if (!obj) {
            fprintf(stderr, "Cannot allocate %s\n", localname);
            return NULL;
        }

        int err = cachestat_bpf__load(obj);
        if (err) {
            fprintf(stderr, "Error to load %s %d\n", localname, err);
            goto endcachestat;
        }

        err = cachestat_bpf__attach(obj);
        if (err) {
            fprintf(stderr, "Error to attach %s %d\n", localname, err);
            goto endcachestat;
        }

        printf("MAP ID: %d\n", bpf_map__fd(obj->maps.cstat_global));
    } else {
        printf("SHARED\n");
        obj_sl = bpf_object__open("../kernel/pcachestat_kern.o");
        bpf_object__load(obj_sl);

        bpf_map__for_each(map, obj_sl)
        {
            printf("%d\n", bpf_map__fd(map));
        }

    }

    for ( i = 0; i < 10 ; i++) {
        sleep(1);
    }


endcachestat:
    if (*sl == 0) {
        cachestat_bpf__destroy(obj);
    } else {
        bpf_object__unload(obj_sl);
    }

    return NULL;
}

void *dc_thread(void *ptr)
{
    char *localname = { "dc" };
    int *sl = ptr;
    struct dc_bpf *obj = NULL;
    struct bpf_object *obj_sl = NULL;
    struct bpf_map *map;
    int i;
    if (*sl == 0) {
        printf("STATIC\n");
        obj = dc_bpf__open();
        if (!obj) {
            fprintf(stderr, "Cannot allocate %s\n", localname);
            return NULL;
        }

        int err = dc_bpf__load(obj);
        if (err) {
            fprintf(stderr, "Error to load %s %d\n", localname, err);
            goto enddc;
        }

        err = dc_bpf__attach(obj);
        if (err) {
            fprintf(stderr, "Error to attach %s %d\n", localname, err);
            goto enddc;
        }

        printf("MAP ID: %d\n", bpf_map__fd(obj->maps.dcstat_global));
    } else {
        printf("SHARED\n");
        obj_sl = bpf_object__open("../kernel/pdc_kern.o");
        bpf_object__load(obj_sl);

        bpf_map__for_each(map, obj_sl)
        {
            printf("%d\n", bpf_map__fd(map));
        }

    }

    for ( i = 0; i < 10 ; i++) {
        sleep(1);
    }


enddc:
    if (*sl == 0) {
        dc_bpf__destroy(obj);
    } else {
        bpf_object__unload(obj_sl);
    }

    return NULL;
}

void *process_thread(void *ptr)
{
    char *localname = { "process" };
    int *sl = ptr;
    struct process_bpf *obj = NULL;
    struct bpf_object *obj_sl = NULL;
    struct bpf_map *map;
    int i;
    if (*sl == 0) {
        printf("STATIC\n");
        obj = process_bpf__open();
        if (!obj) {
            fprintf(stderr, "Cannot allocate %s\n", localname);
            return NULL;
        }

        int err = process_bpf__load(obj);
        if (err) {
            fprintf(stderr, "Error to load %s %d\n", localname, err);
            goto endprocess;
        }

        err = process_bpf__attach(obj);
        if (err) {
            fprintf(stderr, "Error to attach %s %d\n", localname, err);
            goto endprocess;
        }

        printf("MAP ID: %d\n", bpf_map__fd(obj->maps.tbl_total_stats));
    } else {
        printf("SHARED\n");
        obj_sl = bpf_object__open("../kernel/pprocess_kern.o");
        bpf_object__load(obj_sl);

        bpf_map__for_each(map, obj_sl)
        {
            printf("%d\n", bpf_map__fd(map));
        }

    }

    for ( i = 0; i < 10 ; i++) {
        sleep(1);
    }


endprocess:
    if (*sl == 0) {
        process_bpf__destroy(obj);
    } else {
        bpf_object__unload(obj_sl);
    }

    return NULL;
}

int main(int argc, char **argv)
{
    if (bump_memlock_rlimit()) {
        return 1;
    }

    int sl = 1;
    if (argc > 1) {
        sl = atoi(argv[1]);
    }

    libbpf_set_print(libbpf_print_fn);

#define MAX_LOOP 9
    pthread_t threads[MAX_LOOP];
    void * (*fp[])(void *) = { sync_thread, msync_thread, fsync_thread, fdatasync_thread,
        syncfs_thread, sync_file_range_thread, cachestat_thread, dc_thread, process_thread};

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    int i, ret;
    for ( i = 0 ; i < MAX_LOOP; i++) {
        ret = pthread_create(&threads[i], &attr, fp[i], (void *)&sl);
        if (ret)
            break;
    }

    for ( i = 0 ; i < MAX_LOOP; i++) {
        if ( (ret = pthread_join(threads[i], NULL) ) )
            break;
    }

    return 0;
}
