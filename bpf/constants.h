#define MAX_STACK_TRACE_DEPTH 128
#define SIZE_OF_ULONG (sizeof(unsigned long))

// Task descriptor field sizes
#define TASK_COMM_LEN 16
#define TASK_CMDLINE_LEN 256

// RSS stat indices (from kernel mm_types.h)
#define MM_FILEPAGES  0
#define MM_ANONPAGES  1
#define MM_SWAPENTS   2
#define MM_SHMEMPAGES 3

// File descriptor field sizes
#define FILE_PATH_LEN 256
#define UNIX_PATH_LEN 108

// File descriptor types
#define FD_TYPE_OTHER    0
#define FD_TYPE_FILE     1
#define FD_TYPE_SOCKET   2

// Socket families (from socket.h)
#define AF_UNIX   1
#define AF_INET   2
#define AF_INET6 10

// Socket types (from socket.h)
#define SOCK_STREAM 1  // TCP
#define SOCK_DGRAM  2  // UDP
