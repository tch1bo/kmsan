#ifndef _LINUX_KCOV_H
#define _LINUX_KCOV_H

#include <uapi/linux/kcov.h>

struct task_struct;

enum kcov_mode {
	/*
	 * Tracing coverage collection mode.
	 * Covered PCs are collected in a per-task buffer.
	 */
	KCOV_MODE_TRACE_PC = 0,
	/* Collecting comparison operands mode. */
	KCOV_MODE_TRACE_CMP = 1,
	/* Coverage collection is not enabled yet. */
	KCOV_MODE_DISABLED = 2,
	/* KCOV was initialized, but tracing mode hasn't been chosen yet. */
	KCOV_MODE_INIT = 3,
};

#ifdef CONFIG_KCOV

void kcov_task_init(struct task_struct *t);
void kcov_task_exit(struct task_struct *t);

#else

static inline void kcov_task_init(struct task_struct *t) {}
static inline void kcov_task_exit(struct task_struct *t) {}

#endif /* CONFIG_KCOV */
#endif /* _LINUX_KCOV_H */
