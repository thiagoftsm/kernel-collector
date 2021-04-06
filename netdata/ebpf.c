#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <pthread.h>
#include <unistd.h>

#include "sync.skel.h"

/*
static struct env {
        bool verbose;
        bool count;
        bool print_timestamp;
        bool print_uid;
        pid_t pid;
        uid_t uid;
        int nports;
        int ports[MAX_PORTS];
} env = {
    .uid = (uid_t) -1,
};
*/

static int libbpf_print_fn(enum libbpf_print_level level,
                const char *format, va_list args)
{
    /*
        if (level == LIBBPF_DEBUG && !env.verbose)
                return 0;
                */
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
    int *sl = ptr;
    struct sync_bpf *obj = NULL;
    struct bpf_object *obj_sl = NULL;
    struct bpf_map *map;
    int i;
    if (*sl == 0) {
        printf("STATIC\n");
        obj = sync_bpf__open();
        if (!obj) {
            fprintf(stderr, "Cannot allocate\n");
            return NULL;
        }

        int err = sync_bpf__load(obj);
        if (err) {
            fprintf(stderr, "Error to load %d\n", err);
            goto endsync;
        }

        err = sync_bpf__attach(obj);
        if (err) {
            fprintf(stderr, "Error to attach %d\n", err);
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

        /*
        int prog_fd;
        if (bpf_prog_load("../kernel/psync_kern.o", BPF_PROG_TYPE_UNSPEC, sl_obj, &prog_fd)) {
            fprintf(stderr, "Fail to load ebpf_program");
            goto endsync;
        }

        struct bpf_map *map;
        i = 0;
        bpf_map__for_each(map, *sl_obj)
        {
            map_fd[i] = bpf_map__fd(map);
            i++;
        }

        struct bpf_program *prog;
        struct bpf_link **links = calloc(64 , sizeof(struct bpf_link *));
        i = 0;
        bpf_object__for_each_program(prog, *sl_obj)
        {
            links[i] = bpf_program__attach(prog);
            i++;
        }
        */
    }

    for ( i = 0; i < 10 ; i++) {
        sleep(1);
        fprintf(stdout, "MAP ID: %d\n", i);
    }


endsync:
    if (*sl == 0) {
        sync_bpf__destroy(obj);
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

#define MAX_LOOP 1
    pthread_t threads[MAX_LOOP];
    void * (*fp[])(void *) = { sync_thread};

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
