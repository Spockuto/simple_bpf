#include <linux/bpf.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

struct event {
    int pid;
    char comm[16];
    char filename[512];
};

struct sys_enter_openat_args {
    unsigned long long unused;
    long syscall_nr;
    long dfd;
    const char *filename;
    long flags;
    long mode;
};

SEC("tp/syscalls/sys_enter_openat")
int detect_openat(struct sys_enter_openat_args *ctx) {
    
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct event* evt = bpf_ringbuf_reserve(&ringbuf, sizeof(struct event), 0);
    if (!evt) {
        bpf_printk("bpf_ringbuf_reserve failed\\n");
        return 1;
    }
    evt->pid = pid;
    bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), ctx->filename);
    bpf_get_current_comm(evt->comm, sizeof(evt->comm));
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";
