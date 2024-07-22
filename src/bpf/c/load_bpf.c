#include <stdio.h>
#include <bpf/libbpf.h>
#include <unistd.h>

struct event {
    __u32 pid;
    char comm[16];
    char filename[512];
};

static int event_logger(void* ctx, void* data, size_t len) {
    struct event* evt = (struct event*)data;
    printf("Process %s with PID = %d accessed %s\n", evt->comm, evt->pid, evt->filename);
    return 0;
}

int main() {
    const char* filename = "openat.bpf.o";
    const char* mapname = "ringbuf";
    const char* progname = "detect_openat";
    struct bpf_object* bpfObject = bpf_object__open(filename);
    if (!bpfObject) {
        printf("Failed to open %s\n", filename);
        return 1;
    }
    int err = bpf_object__load(bpfObject);
    if (err) {
        printf("Failed to load %s\n", filename);
        return 1;
    }
    int rbfd = bpf_object__find_map_fd_by_name(bpfObject, mapname);
    struct ring_buffer* ringBuffer = ring_buffer__new(rbfd, event_logger, NULL, NULL);
    if (!ringBuffer) {
        puts("Failed to create ring buffer");
        return 1;
    }
    struct bpf_program* bpfProg = bpf_object__find_program_by_name(bpfObject, progname);
    if (!bpfProg) {
        printf("Failed to find %s\n", progname);
        return 1;
    }
    bpf_program__attach(bpfProg);
    while (1) {
        ring_buffer__consume(ringBuffer);
        sleep(1);
    }
    return 0;
}
