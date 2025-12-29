//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_STACK_TRACE_DEPTH 128
#define SIZE_OF_ULONG (sizeof(unsigned long))

// Task descriptor field sizes
#define TASK_COMM_LEN    16
#define TASK_ENV_LEN     4096
#define TASK_CWD_LEN     256
#define TASK_ROOT_LEN    256
#define TASK_EXE_LEN     256
#define TASK_PATH_LEN    4096
#define TASK_CMDLINE_LEN 4096
#define TASK_CGROUP_LEN  256

static unsigned long entries[MAX_STACK_TRACE_DEPTH];

struct task_descriptor {
	int pid;
    int tid;
    int ppid;
    char comm[TASK_COMM_LEN];
};

static __always_inline void fill_task_descriptor(struct task_descriptor *td, struct task_struct *task)
{
	td->pid = task->tgid;
	td->tid = task->pid;
	td->ppid = task->real_parent->tgid;
	bpf_probe_read_str(&td->comm, sizeof(td->comm), task->comm);
}

SEC("iter/task")
int ps_task(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	struct task_descriptor td = {};

	if (task == (void *)0)
		return 0;

	fill_task_descriptor(&td, task);
	bpf_seq_write(seq, &td, sizeof(td));

	return 0;
}

// Iterate stack traces
SEC("iter/task")
int dump_task_stack(struct bpf_iter__task *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	struct task_struct *task = ctx->task;
	long i, retlen;

	if (task == (void *)0)
		return 0;

	retlen = bpf_get_task_stack(task, entries,
				    MAX_STACK_TRACE_DEPTH * SIZE_OF_ULONG, 0);
	if (retlen < 0)
		return 0;

	BPF_SEQ_PRINTF(seq, "pid: %8u num_entries: %8u\n", task->pid,
		       retlen / SIZE_OF_ULONG);
	for (i = 0; i < MAX_STACK_TRACE_DEPTH; i++) {
		if (retlen > i * SIZE_OF_ULONG)
			BPF_SEQ_PRINTF(seq, "[<0>] %pB\n", (void *)entries[i]);
	}
	BPF_SEQ_PRINTF(seq, "\n");

	return 0;
}
