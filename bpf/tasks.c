//go:build ignore

#include "vmlinux.h"
#include "constants.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

static unsigned long entries[MAX_STACK_TRACE_DEPTH];

struct task_descriptor {
	int euid;
	int ruid;                 
	int suid;                
	int pid;
	int tid;
	int ppid;
	unsigned int state;       // Process state (__state field)
	unsigned long start_time; // Start time in nanoseconds (start_time)
	unsigned long utime;      // User CPU time in nanoseconds
	unsigned long stime;      // System CPU time in nanoseconds
	unsigned long vsz;        // Virtual memory size in bytes
	unsigned long rss;        // Resident set size in bytes
	// Capabilities
	unsigned long cap_effective;
	unsigned long cap_permitted;
	unsigned long cap_inheritable;
	// Namespace inodes
	unsigned int ns_uts;
	unsigned int ns_ipc;
	unsigned int ns_mnt;
	unsigned int ns_pid;
	unsigned int ns_net;
	unsigned int ns_cgroup;
	unsigned int _pad;        // padding for alignment
	char comm[TASK_COMM_LEN];
	// Note: cmdline is read from /proc in userspace as BPF iterators
	// have restrictions on reading userspace memory
};

static __always_inline void fill_task_descriptor(struct task_descriptor *td, struct task_struct *task)
{
	struct mm_struct *mm;
	struct nsproxy *nsp;
	s64 rss_file, rss_anon, rss_shmem;

	// UIDs from credentials
	td->euid = task->cred->euid.val;
	td->ruid = task->cred->uid.val;
	td->suid = task->cred->suid.val;

	td->pid = task->tgid;
	td->tid = task->pid;
	td->ppid = task->real_parent->tgid;
	td->state = task->__state;
	td->start_time = task->start_time;
	td->utime = task->utime;
	td->stime = task->stime;

	// Capabilities from credentials
	// kernel_cap_struct has cap[2] (two __u32 values), combine into __u64
	struct kernel_cap_struct cap_eff = {};
	struct kernel_cap_struct cap_perm = {};
	struct kernel_cap_struct cap_inh = {};
	
	bpf_probe_read_kernel(&cap_eff, sizeof(cap_eff), &task->cred->cap_effective);
	bpf_probe_read_kernel(&cap_perm, sizeof(cap_perm), &task->cred->cap_permitted);
	bpf_probe_read_kernel(&cap_inh, sizeof(cap_inh), &task->cred->cap_inheritable);
	
	td->cap_effective = ((__u64)cap_eff.cap[1] << 32) | cap_eff.cap[0];
	td->cap_permitted = ((__u64)cap_perm.cap[1] << 32) | cap_perm.cap[0];
	td->cap_inheritable = ((__u64)cap_inh.cap[1] << 32) | cap_inh.cap[0];

	// Get memory info from mm_struct
	mm = task->mm;
	if (mm) {
		// VSZ: total_vm is in pages, convert to bytes (PAGE_SIZE = 4096)
		td->vsz = mm->total_vm * 4096;

		// RSS: sum of file, anon, and shmem pages (approximation using base count)
		// Note: This is the base count only, actual RSS may be slightly different
		// due to per-CPU deltas in percpu_counter
		// rss_stat is a struct with count[4] array (atomic_long_t = atomic64_t)
		// atomic64_t has a .counter field containing the actual value
		atomic64_t count_file, count_anon, count_shmem;
		bpf_probe_read_kernel(&count_file, sizeof(count_file), &mm->rss_stat.count[MM_FILEPAGES]);
		rss_file = BPF_CORE_READ(&count_file, counter);
		bpf_probe_read_kernel(&count_anon, sizeof(count_anon), &mm->rss_stat.count[MM_ANONPAGES]);
		rss_anon = BPF_CORE_READ(&count_anon, counter);
		bpf_probe_read_kernel(&count_shmem, sizeof(count_shmem), &mm->rss_stat.count[MM_SHMEMPAGES]);
		rss_shmem = BPF_CORE_READ(&count_shmem, counter);
		
		// Ensure non-negative (percpu counters can temporarily go negative)
		if (rss_file < 0) rss_file = 0;
		if (rss_anon < 0) rss_anon = 0;
		if (rss_shmem < 0) rss_shmem = 0;
		
		td->rss = (rss_file + rss_anon + rss_shmem) * 4096;
	} else {
		td->vsz = 0;
		td->rss = 0;
	}

	// Namespace inodes from nsproxy
	nsp = task->nsproxy;
	if (nsp) {
		if (nsp->uts_ns)
			td->ns_uts = nsp->uts_ns->ns.inum;
		if (nsp->ipc_ns)
			td->ns_ipc = nsp->ipc_ns->ns.inum;
		if (nsp->mnt_ns)
			td->ns_mnt = nsp->mnt_ns->ns.inum;
		if (nsp->pid_ns_for_children)
			td->ns_pid = nsp->pid_ns_for_children->ns.inum;
		if (nsp->net_ns)
			td->ns_net = nsp->net_ns->ns.inum;
		if (nsp->cgroup_ns)
			td->ns_cgroup = nsp->cgroup_ns->ns.inum;
	}

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
// NOTE: Commented out because BPF_SEQ_PRINTF with %pB format specifier causes
// the BPF verifier to generate too many instructions (program too large error).
// This function is not currently used in the codebase.
/*
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
*/
