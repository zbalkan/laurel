#ifndef LAUREL_SELINUX_SHIM_H
#define LAUREL_SELINUX_SHIM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct laurel_selinux laurel_selinux_t;

enum laurel_selinux_status {
    LAUREL_SELINUX_OK = 0,
    LAUREL_SELINUX_DISABLED = 1,
    LAUREL_SELINUX_BUSY = 2,
    LAUREL_SELINUX_INVALID_ARGUMENT = 3,
    LAUREL_SELINUX_NOMEM = 4,
    LAUREL_SELINUX_POLICY_ERROR = 5,
    LAUREL_SELINUX_BAD_SCON = 6,
    LAUREL_SELINUX_BAD_TCON = 7,
    LAUREL_SELINUX_BAD_CLASS = 8,
    LAUREL_SELINUX_BAD_PERMISSION = 9,
    LAUREL_SELINUX_COMPUTE_ERROR = 10
};

enum laurel_selinux_reason {
    LAUREL_SELINUX_ALLOW = 0,
    LAUREL_SELINUX_DONTAUDIT = 1,
    LAUREL_SELINUX_TERULE = 2,
    LAUREL_SELINUX_BOOLEAN = 3,
    LAUREL_SELINUX_CONSTRAINT = 4,
    LAUREL_SELINUX_RBAC = 5,
    LAUREL_SELINUX_BOUNDS = 6
};

/*
 * detail is owned by ctx and remains valid only until the next
 * laurel_selinux_analyze() call or laurel_selinux_close(). Callers must copy it.
 */
typedef struct laurel_selinux_result {
    int reason;
    const char *detail;
    size_t detail_len;
} laurel_selinux_result_t;

int laurel_selinux_open(laurel_selinux_t **out);

/*
 * Returns LAUREL_SELINUX_OK and sets *changed to 0 or 1. A change means the
 * active SELinux policy generation differs from the one loaded by ctx.
 */
int laurel_selinux_policy_changed(laurel_selinux_t *ctx, int *changed);

int laurel_selinux_analyze(
    laurel_selinux_t *ctx,
    const char *scontext,
    const char *tcontext,
    const char *tclass,
    const char *const *permissions,
    size_t permission_count,
    laurel_selinux_result_t *out);

void laurel_selinux_close(laurel_selinux_t *ctx);

#ifdef __cplusplus
}
#endif

#endif
