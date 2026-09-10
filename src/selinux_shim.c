#include "selinux_shim.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sepol/policydb.h>
#include <sepol/policydb/services.h>
#include <sepol/sepol.h>
#include <selinux/avc.h>
#include <selinux/selinux.h>

#define POLICY_SNAPSHOT_RETRIES 3

struct laurel_boolean {
    char *name;
    int active;
};

struct laurel_selinux {
    sepol_handle_t *handle;
    sepol_policydb_t *policydb;
    struct laurel_boolean *booleans;
    size_t boolean_count;
    size_t boolean_capacity;
    int tracks_policyload;
    int policyload;
    char *detail;
    size_t detail_len;
};

static laurel_selinux_t *active_ctx;
static sidtab_t active_sidtab;
static int sidtab_initialized;
static int status_opened;

static void clear_detail(laurel_selinux_t *ctx)
{
    free(ctx->detail);
    ctx->detail = NULL;
    ctx->detail_len = 0;
}

static int set_detail(laurel_selinux_t *ctx, const char *data, size_t len)
{
    char *p;

    clear_detail(ctx);
    if (!data || len == 0)
        return LAUREL_SELINUX_OK;

    p = malloc(len + 1);
    if (!p)
        return LAUREL_SELINUX_NOMEM;

    memcpy(p, data, len);
    p[len] = '\0';
    ctx->detail = p;
    ctx->detail_len = len;
    return LAUREL_SELINUX_OK;
}

static int append_boolean_detail(laurel_selinux_t *ctx, const char *name, int value)
{
    size_t name_len = strlen(name);
    size_t extra = name_len + 2 + (ctx->detail_len ? 1 : 0);
    size_t old_len = ctx->detail_len;
    char *p = realloc(ctx->detail, old_len + extra + 1);
    int written;

    if (!p)
        return LAUREL_SELINUX_NOMEM;

    ctx->detail = p;
    if (old_len)
        ctx->detail[old_len++] = ',';

    written = snprintf(ctx->detail + old_len, extra + 1, "%s=%d", name, value ? 1 : 0);
    if (written < 0 || (size_t)written > extra)
        return LAUREL_SELINUX_COMPUTE_ERROR;

    ctx->detail_len = old_len + (size_t)written;
    return LAUREL_SELINUX_OK;
}

static int load_boolean(const sepol_bool_t *boolean, void *arg)
{
    laurel_selinux_t *ctx = arg;
    struct laurel_boolean *dst;
    const char *name;

    if (ctx->boolean_count >= ctx->boolean_capacity)
        return -1;

    name = sepol_bool_get_name(boolean);
    if (!name)
        return -1;

    dst = &ctx->booleans[ctx->boolean_count];
    dst->name = strdup(name);
    if (!dst->name)
        return -1;

    /* /sys/fs/selinux/policy is the effective policy; keep its Boolean value. */
    dst->active = sepol_bool_get_value(boolean);
    ctx->boolean_count++;
    return 0;
}

static int set_policy_boolean(laurel_selinux_t *ctx, const char *name, int value)
{
    sepol_bool_key_t *key = NULL;
    sepol_bool_t *boolean = NULL;
    int rc;

    rc = sepol_bool_key_create(ctx->handle, name, &key);
    if (rc < 0)
        goto error;

    rc = sepol_bool_query(ctx->handle, ctx->policydb, key, &boolean);
    if (rc < 0 || !boolean)
        goto error;

    sepol_bool_set_value(boolean, value);
    rc = sepol_bool_set(ctx->handle, ctx->policydb, key, boolean);

    sepol_bool_free(boolean);
    sepol_bool_key_free(key);
    return rc < 0 ? -1 : 0;

error:
    if (boolean)
        sepol_bool_free(boolean);
    if (key)
        sepol_bool_key_free(key);
    return -1;
}

static void destroy_unpublished(laurel_selinux_t *ctx)
{
    size_t i;

    if (!ctx)
        return;

    clear_detail(ctx);
    for (i = 0; i < ctx->boolean_count; i++)
        free(ctx->booleans[i].name);
    free(ctx->booleans);

    if (ctx->policydb)
        sepol_policydb_free(ctx->policydb);
    if (ctx->handle)
        sepol_handle_destroy(ctx->handle);
    free(ctx);
}

/*
 * Opening /sys/fs/selinux/policy snapshots the active policy. Check the
 * policy-load sequence immediately before and after that open so the snapshot
 * can be associated with a generation unambiguously. If a policy change races
 * with the open, discard the snapshot and retry a bounded number of times.
 */
static int open_current_policy(FILE **out, int *generation)
{
    const char *policy_path;
    FILE *fp;
    int before;
    int after;
    int attempt;

    if (!out || !generation)
        return LAUREL_SELINUX_INVALID_ARGUMENT;

    *out = NULL;
    *generation = -1;

    for (attempt = 0; attempt < POLICY_SNAPSHOT_RETRIES; attempt++) {
        before = selinux_status_policyload();
        if (before < 0)
            return LAUREL_SELINUX_POLICY_ERROR;

        policy_path = selinux_current_policy_path();
        if (!policy_path)
            return LAUREL_SELINUX_POLICY_ERROR;

        fp = fopen(policy_path, "re");
        if (!fp)
            return LAUREL_SELINUX_POLICY_ERROR;

        after = selinux_status_policyload();
        if (after < 0) {
            fclose(fp);
            return LAUREL_SELINUX_POLICY_ERROR;
        }

        if (before == after) {
            *out = fp;
            *generation = after;
            return LAUREL_SELINUX_OK;
        }

        fclose(fp);
    }

    return LAUREL_SELINUX_POLICY_ERROR;
}

static int laurel_selinux_open_impl(
    laurel_selinux_t **out,
    const char *explicit_policy_path)
{
    laurel_selinux_t *ctx = NULL;
    struct sepol_policy_file *pf = NULL;
    FILE *fp = NULL;
    unsigned int boolean_count = 0;
    int enabled;
    int snapshot_generation = -1;
    int rc = LAUREL_SELINUX_POLICY_ERROR;

    if (!out)
        return LAUREL_SELINUX_INVALID_ARGUMENT;
    *out = NULL;

    if (active_ctx)
        return LAUREL_SELINUX_BUSY;

    if (explicit_policy_path) {
        if (!*explicit_policy_path)
            return LAUREL_SELINUX_INVALID_ARGUMENT;
        fp = fopen(explicit_policy_path, "re");
        if (!fp)
            return LAUREL_SELINUX_POLICY_ERROR;
    } else {
        enabled = is_selinux_enabled();
        if (enabled == 0)
            return LAUREL_SELINUX_DISABLED;
        if (enabled < 0)
            return LAUREL_SELINUX_POLICY_ERROR;

        /* Use the kernel status page; do not fall back to netlink. */
        if (selinux_status_open(0) < 0)
            return LAUREL_SELINUX_POLICY_ERROR;
        status_opened = 1;

        rc = open_current_policy(&fp, &snapshot_generation);
        if (rc != LAUREL_SELINUX_OK)
            goto error;
    }

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        rc = LAUREL_SELINUX_NOMEM;
        goto error;
    }
    ctx->tracks_policyload = explicit_policy_path == NULL;
    ctx->policyload = snapshot_generation;

    if (sepol_policy_file_create(&pf) != 0 ||
        sepol_policydb_create(&ctx->policydb) != 0) {
        rc = LAUREL_SELINUX_POLICY_ERROR;
        goto error;
    }

    sepol_policy_file_set_fp(pf, fp);
    if (sepol_policydb_read(ctx->policydb, pf) != 0) {
        rc = LAUREL_SELINUX_POLICY_ERROR;
        goto error;
    }

    sepol_policy_file_free(pf);
    pf = NULL;
    fclose(fp);
    fp = NULL;

    ctx->handle = sepol_handle_create();
    if (!ctx->handle) {
        rc = LAUREL_SELINUX_NOMEM;
        goto error;
    }
    sepol_msg_set_callback(ctx->handle, NULL, NULL);

    if (sepol_bool_count(ctx->handle, ctx->policydb, &boolean_count) < 0) {
        rc = LAUREL_SELINUX_POLICY_ERROR;
        goto error;
    }

    if (boolean_count) {
        ctx->booleans = calloc(boolean_count, sizeof(*ctx->booleans));
        if (!ctx->booleans) {
            rc = LAUREL_SELINUX_NOMEM;
            goto error;
        }

        ctx->boolean_capacity = boolean_count;
        if (sepol_bool_iterate(ctx->handle, ctx->policydb, load_boolean, ctx) < 0 ||
            ctx->boolean_count != boolean_count) {
            rc = LAUREL_SELINUX_POLICY_ERROR;
            goto error;
        }
    }

    if (sepol_sidtab_init(&active_sidtab) < 0) {
        rc = LAUREL_SELINUX_POLICY_ERROR;
        goto error;
    }
    sidtab_initialized = 1;

    /* libsepol's service API uses process-global policydb and sidtab pointers. */
    sepol_set_policydb(&ctx->policydb->p);
    sepol_set_sidtab(&active_sidtab);

    active_ctx = ctx;
    *out = ctx;
    return LAUREL_SELINUX_OK;

error:
    if (pf)
        sepol_policy_file_free(pf);
    if (fp)
        fclose(fp);
    if (sidtab_initialized) {
        sepol_sidtab_shutdown(&active_sidtab);
        sepol_sidtab_destroy(&active_sidtab);
        sidtab_initialized = 0;
    }
    if (status_opened) {
        selinux_status_close();
        status_opened = 0;
    }
    destroy_unpublished(ctx);
    return rc;
}

int laurel_selinux_open(laurel_selinux_t **out)
{
    return laurel_selinux_open_impl(out, NULL);
}

int laurel_selinux_open_policy(laurel_selinux_t **out, const char *policy_path)
{
    if (!policy_path)
        return LAUREL_SELINUX_INVALID_ARGUMENT;
    return laurel_selinux_open_impl(out, policy_path);
}

int laurel_selinux_policy_changed(laurel_selinux_t *ctx, int *changed)
{
    int current;

    if (!ctx || ctx != active_ctx || !changed)
        return LAUREL_SELINUX_INVALID_ARGUMENT;

    if (!ctx->tracks_policyload) {
        *changed = 0;
        return LAUREL_SELINUX_OK;
    }

    current = selinux_status_policyload();
    if (current < 0)
        return LAUREL_SELINUX_POLICY_ERROR;

    *changed = current != ctx->policyload;
    return LAUREL_SELINUX_OK;
}

static int check_booleans(
    laurel_selinux_t *ctx,
    sepol_security_id_t ssid,
    sepol_security_id_t tsid,
    sepol_security_class_t tclass,
    sepol_access_vector_t av,
    size_t *found)
{
    size_t i;
    struct sepol_av_decision avd;
    unsigned int reason;
    int rc;

    *found = 0;

    for (i = 0; i < ctx->boolean_count; i++) {
        struct laurel_boolean *entry = &ctx->booleans[i];
        int candidate = !entry->active;

        /*
         * A failed mutation leaves the userspace policydb state uncertain.
         * Discard the analyzer rather than use it for another decision.
         */
        if (set_policy_boolean(ctx, entry->name, candidate) < 0)
            return LAUREL_SELINUX_RELOAD_REQUIRED;

        rc = sepol_compute_av_reason(ssid, tsid, tclass, av, &avd, &reason);

        /* Restore before interpreting either the result or the error. */
        if (set_policy_boolean(ctx, entry->name, entry->active) < 0)
            return LAUREL_SELINUX_RELOAD_REQUIRED;

        if (rc < 0)
            return LAUREL_SELINUX_COMPUTE_ERROR;

        if (!reason) {
            rc = append_boolean_detail(ctx, entry->name, candidate);
            if (rc != LAUREL_SELINUX_OK)
                return rc;
            (*found)++;
        }
    }

    return LAUREL_SELINUX_OK;
}

int laurel_selinux_analyze(
    laurel_selinux_t *ctx,
    const char *scontext,
    const char *tcontext,
    const char *tclass_name,
    const char *const *permissions,
    size_t permission_count,
    laurel_selinux_result_t *out)
{
    sepol_security_id_t ssid;
    sepol_security_id_t tsid;
    sepol_security_class_t tclass;
    sepol_access_vector_t av = 0;
    sepol_access_vector_t perm;
    struct sepol_av_decision avd;
    unsigned int reason;
    char *reason_buf = NULL;
    size_t i;
    size_t boolean_found = 0;
    int status = LAUREL_SELINUX_OK;
    int result_reason = -1;

    if (!ctx || ctx != active_ctx || !scontext || !tcontext || !tclass_name ||
        !permissions || permission_count == 0 || !out)
        return LAUREL_SELINUX_INVALID_ARGUMENT;

    clear_detail(ctx);

    if (sepol_context_to_sid(scontext, strlen(scontext) + 1, &ssid) < 0)
        return LAUREL_SELINUX_BAD_SCON;
    if (sepol_context_to_sid(tcontext, strlen(tcontext) + 1, &tsid) < 0)
        return LAUREL_SELINUX_BAD_TCON;
    if (sepol_string_to_security_class(tclass_name, &tclass) < 0)
        return LAUREL_SELINUX_BAD_CLASS;

    for (i = 0; i < permission_count; i++) {
        if (!permissions[i])
            return LAUREL_SELINUX_INVALID_ARGUMENT;
        if (sepol_string_to_av_perm(tclass, permissions[i], &perm) < 0)
            return LAUREL_SELINUX_BAD_PERMISSION;
        av |= perm;
    }

    if (sepol_compute_av_reason_buffer(
            ssid, tsid, tclass, av, &avd, &reason, &reason_buf, 0) < 0) {
        status = LAUREL_SELINUX_COMPUTE_ERROR;
        goto done;
    }

    if (!reason) {
        result_reason = LAUREL_SELINUX_ALLOW;
        goto done;
    }

    if (reason & SEPOL_COMPUTEAV_TE) {
        status = check_booleans(ctx, ssid, tsid, tclass, av, &boolean_found);
        if (status != LAUREL_SELINUX_OK)
            goto done;

        if (boolean_found)
            result_reason = LAUREL_SELINUX_BOOLEAN;
        else if (av & ~avd.auditdeny)
            result_reason = LAUREL_SELINUX_DONTAUDIT;
        else
            result_reason = LAUREL_SELINUX_TERULE;
        goto done;
    }

    if (reason & SEPOL_COMPUTEAV_CONS) {
        result_reason = LAUREL_SELINUX_CONSTRAINT;
        if (reason_buf) {
            status = set_detail(ctx, reason_buf, strlen(reason_buf));
            if (status != LAUREL_SELINUX_OK)
                goto done;
        }
        goto done;
    }
    if (reason & SEPOL_COMPUTEAV_RBAC) {
        result_reason = LAUREL_SELINUX_RBAC;
        goto done;
    }
    if (reason & SEPOL_COMPUTEAV_BOUNDS) {
        result_reason = LAUREL_SELINUX_BOUNDS;
        goto done;
    }

    status = LAUREL_SELINUX_COMPUTE_ERROR;

done:
    free(reason_buf);
    if (status != LAUREL_SELINUX_OK)
        return status;

    out->reason = result_reason;
    out->detail = ctx->detail;
    out->detail_len = ctx->detail_len;
    return LAUREL_SELINUX_OK;
}

void laurel_selinux_close(laurel_selinux_t *ctx)
{
    size_t i;

    if (!ctx || ctx != active_ctx)
        return;

    active_ctx = NULL;

    if (sidtab_initialized) {
        sepol_sidtab_shutdown(&active_sidtab);
        sepol_sidtab_destroy(&active_sidtab);
        sidtab_initialized = 0;
    }
    if (status_opened) {
        selinux_status_close();
        status_opened = 0;
    }

    clear_detail(ctx);
    for (i = 0; i < ctx->boolean_count; i++)
        free(ctx->booleans[i].name);
    free(ctx->booleans);

    if (ctx->policydb)
        sepol_policydb_free(ctx->policydb);
    if (ctx->handle)
        sepol_handle_destroy(ctx->handle);
    free(ctx);
}
