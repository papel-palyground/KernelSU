#ifndef __KSU_H_KSU_MANAGER
#define __KSU_H_KSU_MANAGER

#include <linux/cred.h>
#include <linux/types.h>
#include "allowlist.h"

/*
 * Multi-manager support: up to KSU_MAX_MANAGERS manager apps may be
 * installed simultaneously. Each entry is a base appid (uid % PER_USER_RANGE)
 * so that the check works for any Android user profile.
 */
#define KSU_INVALID_APPID ((uid_t)-1)
#define KSU_MAX_MANAGERS  16

/* Defined in throne_tracker.c */
extern uid_t ksu_manager_appids[KSU_MAX_MANAGERS];
extern int   ksu_manager_count;

/* ── predicates ─────────────────────────────────────────────────────────── */

static inline bool ksu_is_manager_appid_valid(void)
{
    return ksu_manager_count > 0;
}

static inline bool is_manager(void)
{
    int i;
    uid_t cur = current_uid().val % PER_USER_RANGE;

    for (i = 0; i < ksu_manager_count; i++) {
        if (unlikely(ksu_manager_appids[i] == cur))
            return true;
    }
    return false;
}

/* ── getters & setters ──────────────────────────────────────────────────── */

/*
 * Returns the first registered manager appid for backward-compatibility
 * with callers that only care about one manager.
 */
static inline uid_t ksu_get_manager_appid(void)
{
    return ksu_manager_count > 0 ? ksu_manager_appids[0] : KSU_INVALID_APPID;
}

static inline bool ksu_has_manager_appid(uid_t appid)
{
    int i;
    for (i = 0; i < ksu_manager_count; i++) {
        if (ksu_manager_appids[i] == appid)
            return true;
    }
    return false;
}

/* Add a manager if not already present and there is room. */
static inline void ksu_add_manager_appid(uid_t appid)
{
    if (ksu_has_manager_appid(appid))
        return;
    if (ksu_manager_count < KSU_MAX_MANAGERS)
        ksu_manager_appids[ksu_manager_count++] = appid;
}

/* Remove a specific manager by its appid (swap-remove). */
static inline void ksu_remove_manager_appid(uid_t appid)
{
    int i;
    for (i = 0; i < ksu_manager_count; i++) {
        if (ksu_manager_appids[i] == appid) {
            ksu_manager_appids[i] =
                ksu_manager_appids[--ksu_manager_count];
            return;
        }
    }
}

/*
 * Compatibility shim: ksu_set_manager_appid() previously *replaced* the
 * single manager; now it simply registers the uid.
 */
static inline void ksu_set_manager_appid(uid_t appid)
{
    ksu_add_manager_appid(appid);
}

/*
 * Compatibility shim used when the *only* registered manager is uninstalled.
 * With multi-manager, callers should prefer ksu_remove_manager_appid().
 */
static inline void ksu_invalidate_manager_uid(void)
{
    /* Clear all managers – used as last-resort reset. */
    ksu_manager_count = 0;
}

int ksu_observer_init(void);

#endif /* __KSU_H_KSU_MANAGER */
