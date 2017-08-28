#ifndef _LINUX_KCOV_IOCTLS_H
#define _LINUX_KCOV_IOCTLS_H

#include <linux/types.h>

#define KCOV_INIT_TRACE			_IOR('c', 1, unsigned long)
#define KCOV_ENABLE			_IO('c', 100)
#define KCOV_DISABLE			_IO('c', 101)

enum {
	/*
	 * Tracing coverage collection mode.
	 * Covered PCs are collected in a per-task buffer.
	 * In new KCOV version the mode is chosen by calling
	 * ioctl(fd, KCOV_ENABLE, mode). In older versions the mode argument
	 * was supposed to be 0 in such a call. So, for reasons of backward
	 * compatibility, we have chosen the value KCOV_TRACE_PC to be 0.
	 */
	KCOV_TRACE_PC = 0,
	/* Collecting comparison operands mode. */
	KCOV_TRACE_CMP = 1,
};

/*
 * Defines the format for the types of collected comparisons.
 */
enum kcov_cmp_type {
	/*
	 * LSB shows whether one of the arguments is a compile-time constant.
	 */
	KCOV_CMP_CONST = 1,
	/*
	 * Second and third LSBs contain the size of arguments (1/2/4/8 bytes).
	 */
	KCOV_CMP_SIZE1 = 0,
	KCOV_CMP_SIZE2 = 2,
	KCOV_CMP_SIZE4 = 4,
	KCOV_CMP_SIZE8 = 6,
	KCOV_CMP_SIZE_MASK = 6,
};


#endif /* _LINUX_KCOV_IOCTLS_H */
