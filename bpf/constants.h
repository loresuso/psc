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
