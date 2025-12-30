//go:build ignore

#include "vmlinux.h"
#include "constants.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct file_descriptor {
    int pid;
    int tid;
    int ppid;
    int fd;
    char path[FILE_PATH_LEN];
};

SEC("iter/task_file")
int dump_task_file(struct bpf_iter__task_file *ctx)
{
    struct seq_file *seq = ctx->meta->seq;
    struct task_struct *task = ctx->task;
    struct file *file = ctx->file;
    __u32 fd = ctx->fd;
    struct file_descriptor f = {};

    if (task == NULL || file == NULL)
        return 0;

    f.pid = task->tgid;
    f.tid = task->pid;
    f.ppid = task->real_parent->tgid;
    f.fd = fd;
    bpf_d_path(&file->f_path, f.path, sizeof(f.path));

    bpf_seq_write(seq, &f, sizeof(f));

    return 0;
}