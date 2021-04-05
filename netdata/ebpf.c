#include <stdio.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <pthread.h>

#include "msync.skel.h"

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


void *msync_thread(void *ptr)
{
    struct msync_bpf *obj = msync_bpf__open();
    if (!obj) {
        fprintf(stderr, "Cannot allocate\n");
        return NULL;
    }

    int err = msync_bpf__load(obj);
    if (err) {
        fprintf(stderr, "Error to load %d\n", err);
        goto endmsync;
    }

    err = msync_bpf__attach(obj);
    if (err) {
        fprintf(stderr, "Error to attach %d\n", err);
        goto endmsync;
    }

    // INFINITE LOOP HERE

endmsync:
    msync_bpf__destroy(obj);
    return NULL;
}


int main(int argc, char **argv)
{
    if (bump_memlock_rlimit()) {
        return 1;
    }

    libbpf_set_print(libbpf_print_fn);

#define MAX_LOOP 1
    pthread_t threads[MAX_LOOP];
    void * (*fp[])(void *) = { msync_thread};

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    int i, ret;
    for ( i = 0 ; i < MAX_LOOP; i++) {
        ret = pthread_create(&threads[i], &attr, fp[i], NULL);
        if (ret)
            break;
    }

    for ( i = 0 ; i < MAX_LOOP; i++) {
        if ( (ret = pthread_join(threads[i], NULL) ) )
            break;
    }

    return 0;
}
