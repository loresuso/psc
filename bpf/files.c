//go:build ignore

#include "vmlinux.h"
#include "constants.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Inet socket info (IPv4 uses first 4 bytes of addr, IPv6 uses all 16)
struct inet_sock_info {
    __u8 src_addr[16];
    __u8 dst_addr[16];
    __u16 src_port;
    __u16 dst_port;
    __u8 _pad[220];  // Pad to match FILE_PATH_LEN (256 bytes total)
};

struct file_descriptor {
    int pid;
    int tid;
    int ppid;
    int fd;

    // Type information
    __u8 fd_type;       // FD_TYPE_OTHER, FD_TYPE_FILE, FD_TYPE_SOCKET
    __u8 sock_family;   // AF_UNIX, AF_INET, AF_INET6
    __u8 sock_type;     // SOCK_STREAM (TCP), SOCK_DGRAM (UDP)
    __u8 sock_state;    // TCP state (for TCP sockets)

    // Union of data based on fd_type and sock_family
    union {
        char path[FILE_PATH_LEN];           // For regular files
        struct inet_sock_info inet;          // For TCP/UDP sockets
        char unix_path[FILE_PATH_LEN];       // For unix sockets
    } data;
};

static __always_inline void fill_inet_sock(struct file_descriptor *f, struct sock *sk)
{
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    f->sock_family = family;
    f->sock_type = BPF_CORE_READ(sk, sk_type);
    f->sock_state = BPF_CORE_READ(sk, __sk_common.skc_state);

    // Get ports (network byte order)
    f->data.inet.src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    f->data.inet.dst_port = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));

    if (family == AF_INET) {
        // IPv4 - addresses are 4 bytes
        __be32 src = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __be32 dst = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(f->data.inet.src_addr, &src, 4);
        __builtin_memcpy(f->data.inet.dst_addr, &dst, 4);
    } else if (family == AF_INET6) {
        // IPv6 - addresses are 16 bytes
        BPF_CORE_READ_INTO(&f->data.inet.src_addr, sk, __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
        BPF_CORE_READ_INTO(&f->data.inet.dst_addr, sk, __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    }
}

static __always_inline void fill_unix_sock(struct file_descriptor *f, struct sock *sk)
{
    f->sock_family = AF_UNIX;
    f->sock_type = BPF_CORE_READ(sk, sk_type);
    f->sock_state = BPF_CORE_READ(sk, __sk_common.skc_state);

    struct unix_sock *unix_sk = (struct unix_sock *)sk;
    struct unix_address *addr = NULL;
    int len = 0;
    char first_byte = 0;

    // Try to get the local address first
    addr = BPF_CORE_READ(unix_sk, addr);
    if (addr) {
        len = BPF_CORE_READ(addr, len);
    }

    // If no local address, try to get peer's address
    if (!addr || len <= (int)sizeof(short)) {
        struct sock *peer = BPF_CORE_READ(unix_sk, peer);
        if (peer) {
            struct unix_sock *peer_unix = (struct unix_sock *)peer;
            addr = BPF_CORE_READ(peer_unix, addr);
            if (addr) {
                len = BPF_CORE_READ(addr, len);
            }
        }
    }

    if (addr && len > (int)sizeof(short)) {
        // Check first byte to detect abstract sockets
        bpf_probe_read_kernel(&first_byte, 1, addr->name->sun_path);
        
        if (first_byte == '\0' && len > (int)sizeof(short) + 1) {
            // Abstract socket - prefix with '@' and copy the name (skip first null byte)
            f->data.unix_path[0] = '@';
            bpf_probe_read_kernel_str(f->data.unix_path + 1, sizeof(f->data.unix_path) - 1, 
                                       addr->name->sun_path + 1);
        } else if (first_byte != '\0') {
            // Pathname socket
            bpf_probe_read_kernel_str(f->data.unix_path, sizeof(f->data.unix_path), 
                                       addr->name->sun_path);
        }
    }
}

SEC("iter/task_file")
int dump_task_file(struct bpf_iter__task_file *ctx)
{
    struct seq_file *seq = ctx->meta->seq;
    struct task_struct *task = ctx->task;
    struct file *file = ctx->file;
    __u32 fd = ctx->fd;
    struct file_descriptor f = {};
    long ret;

    if (task == NULL || file == NULL)
        return 0;

    f.pid = task->tgid;
    f.tid = task->pid;
    f.ppid = task->real_parent->tgid;
    f.fd = fd;

    // Check if this is a socket first
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    unsigned short imode = BPF_CORE_READ(inode, i_mode);

    // S_IFSOCK = 0140000, check if it's a socket
    if ((imode & 0170000) == 0140000) {
        f.fd_type = FD_TYPE_SOCKET;

        // Get the socket from file->private_data
        struct socket *socket = BPF_CORE_READ(file, private_data);
        if (socket) {
            struct sock *sk = BPF_CORE_READ(socket, sk);
            if (sk) {
                __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
                
                if (family == AF_INET || family == AF_INET6) {
                    fill_inet_sock(&f, sk);
                } else if (family == AF_UNIX) {
                    fill_unix_sock(&f, sk);
                } else {
                    f.sock_family = family;
                }
            }
        }
    } else {
        f.fd_type = FD_TYPE_FILE;
        
        // Get the file path
        ret = bpf_d_path(&file->f_path, f.data.path, sizeof(f.data.path));
        if (ret < 0) {
            f.data.path[0] = '\0';
        }
    }

    bpf_seq_write(seq, &f, sizeof(f));

    return 0;
}
