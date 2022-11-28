/*
 * Copyright (c) 2015-2020 Intel, Inc.  All rights reserved.
 * Copyright (c) 2016-2018 IBM Corporation.  All rights reserved.
 * Copyright (c) 2018      Research Organization for Information Science
 *                         and Technology (RIST).  All rights reserved.
 * Copyright (c) 2018-2020 Mellanox Technologies, Inc.
 *                         All rights reserved.
 * Copyright (c) 2021-2022 Nanook Consulting.  All rights reserved.
 * Copyright (c) 2022      Triad National Security, LLC. All rights reserved.
 * $COPYRIGHT$
 *
 * Additional copyrights may follow
 *
 * $HEADER$
 */

#include "gds_shmem_utils.h"

#include "src/util/pmix_show_help.h"
#include "src/mca/pcompress/base/base.h"

pmix_status_t
pmix_gds_shmem_get_job_tracker(
    const pmix_nspace_t nspace,
    bool create,
    pmix_gds_shmem_job_t **job
) {
    pmix_status_t rc = PMIX_SUCCESS;

    // Try to find the tracker for this job.
    pmix_gds_shmem_job_t *ti = NULL, *target_tracker = NULL;
    pmix_gds_shmem_component_t *component = &pmix_mca_gds_shmem_component;
    PMIX_LIST_FOREACH (ti, &component->jobs, pmix_gds_shmem_job_t) {
        if (0 == strcmp(nspace, ti->nspace_id)) {
            target_tracker = ti;
            break;
        }
    }
    // If we didn't find the requested target and we aren't asked
    // to create a new one, then the request cannot be fulfilled.
    if (!target_tracker && !create) {
        rc = PMIX_ERR_NOT_FOUND;
        goto out;
    }
    // Create one if not found and asked to create one.
    if (!target_tracker && create) {
        target_tracker = PMIX_NEW(pmix_gds_shmem_job_t);
        if (!target_tracker) {
            rc = PMIX_ERR_NOMEM;
            goto out;
        }
        target_tracker->nspace_id = strdup(nspace);
        if (!target_tracker->nspace_id) {
            rc = PMIX_ERR_NOMEM;
            goto out;
        }
        // See if we already have this nspace in global namespaces.
        pmix_namespace_t *nsi = NULL, *inspace = NULL;
        PMIX_LIST_FOREACH (nsi, &pmix_globals.nspaces, pmix_namespace_t) {
            if (0 == strcmp(nsi->nspace, nspace)) {
                inspace = nsi;
                break;
            }
        }
        // If not, create one and update global namespace list.
        if (!inspace) {
            inspace = PMIX_NEW(pmix_namespace_t);
            if (!inspace) {
                rc = PMIX_ERR_NOMEM;
                goto out;
            }
            inspace->nspace = strdup(nspace);
            if (!inspace->nspace) {
                rc = PMIX_ERR_NOMEM;
                goto out;
            }
            pmix_list_append(&pmix_globals.nspaces, &inspace->super);
        }
        PMIX_RETAIN(inspace);
        target_tracker->nspace = inspace;
        // Add it to the list of jobs I'm supporting.
        pmix_list_append(&component->jobs, &target_tracker->super);
    }
out:
    if (PMIX_SUCCESS != rc) {
        if (target_tracker) {
            PMIX_RELEASE(target_tracker);
            target_tracker = NULL;
        }
    }
    *job = target_tracker;
    return rc;
}

pmix_gds_shmem_session_t *
pmix_gds_shmem_check_session(
    pmix_gds_shmem_job_t *job,
    uint32_t sid
) {
    pmix_gds_shmem_session_t *sptr = NULL;

    /* if this is an invalid session ID, we don't look for it
     * on the list - someone is trying to register a new
     * session for a job prior to actually getting a
     * session ID. We simply add it to the end of the
     * list and return a pointer that they can later
     * use to assign an actual SID */
    if (UINT32_MAX != sid) {
        /* if the tracker is NULL, then they are asking for the
         * session tracker for a specific sid */
        if (NULL == job) {
            PMIX_LIST_FOREACH(sptr, &pmix_mca_gds_shmem_component.sessions, pmix_gds_shmem_session_t) {
                if (sptr->session == sid) {
                    return sptr;
                }
            }
        } else {
            /* if the job tracker already has a session object, then
             * check that the IDs match */
            if (NULL != job->session) {
                sptr = job->session;
                if (sptr->session != sid) {
                    /* this is an error */
                    PMIX_ERROR_LOG(PMIX_ERR_BAD_PARAM);
                    return NULL;
                }
                return sptr;
            }
        }
        /* get here because the job tracker doesn't have
         * a session tracker, so create the session tracker */
        sptr = PMIX_NEW(pmix_gds_shmem_session_t);
        sptr->session = sid;
        /* add to the global list */
        pmix_list_append(&pmix_mca_gds_shmem_component.sessions, &sptr->super);
        if (NULL != job) {
            /* also add it to the job */
            PMIX_RETAIN(sptr);
            job->session = sptr;
        }
        return sptr;
    }

    if (NULL == job) {
        /* this is an error */
        PMIX_ERROR_LOG(PMIX_ERR_BAD_PARAM);
        return NULL;
    }

    if (NULL != job->session) {
        return job->session;
    }

    /* create the session tracker */
    sptr = PMIX_NEW(pmix_gds_shmem_session_t);
    /* we don't add it to the global list because it doesn't have
     * a specific ID, but we do add it to the job */
    job->session = sptr;
    return sptr;
}

pmix_gds_shmem_nodeinfo_t *
pmix_gds_shmem_get_nodeinfo_by_nodename(
    pmix_list_t *nodes,
    const char *hostname
) {
    bool aliases_exist = false;

    if (NULL == hostname) {
        return NULL;
    }
    // First, just check all the node names as this is the most likely match.
    pmix_gds_shmem_nodeinfo_t *ni;
    PMIX_LIST_FOREACH (ni, nodes, pmix_gds_shmem_nodeinfo_t) {
        if (0 == strcmp(ni->hostname, hostname)) {
            return ni;
        }
        if (!pmix_list_is_empty(ni->aliases)) {
            aliases_exist = true;
        }
    }
    // We didn't find it by name and name aliases do not exists.
    if (!aliases_exist) {
        return NULL;
    }
    // If a match wasn't found, then we have to try the aliases.
    PMIX_LIST_FOREACH (ni, nodes, pmix_gds_shmem_nodeinfo_t) {
        pmix_gds_shmem_host_alias_t *nai = NULL;
        PMIX_LIST_FOREACH (nai, ni->aliases, pmix_gds_shmem_host_alias_t) {
            if (0 == strcmp(nai->name, hostname)) {
                return ni;
            }
        }
    }
    // No match found.
    return NULL;
}

bool
pmix_gds_shmem_check_hostname(
    const char *h1,
    const char *h2
) {
    return (0 == strcmp(h1, h2));
}

/**
 * Returns page size.
 */
static inline size_t
get_page_size(void)
{
    const long i = sysconf(_SC_PAGE_SIZE);
    if (-1 == i) {
        PMIX_ERROR_LOG(PMIX_ERROR);
        return 0;
    }
    return i;
}

/**
 * Returns amount needed to pad provided size to page boundary.
 */
size_t
pmix_gds_shmem_pad_amount_to_page(
    size_t size
) {
    const size_t page_size = get_page_size();
    return ((~size) + page_size + 1) & (page_size - 1);
}

/**
 * Returns the base temp directory.
 */
static const char *
fetch_base_tmpdir(
    pmix_gds_shmem_job_t *job
) {
    pmix_status_t rc = PMIX_SUCCESS;

    static char fetched_path[PMIX_PATH_MAX] = {'\0'};
    // Keys we will need to fetch in priority order.
    char *fetch_keys[] = {
        PMIX_NSDIR,
        PMIX_TMPDIR,
        NULL
    };
    // Did we get a usable fetched key/value?
    bool fetched_kv = false;

    for (int i = 0; NULL != fetch_keys[i]; ++i) {
        pmix_cb_t cb;
        PMIX_CONSTRUCT(&cb, pmix_cb_t);

        pmix_proc_t wildcard;
        PMIX_LOAD_PROCID(
            &wildcard,
            job->nspace->nspace,
            PMIX_RANK_WILDCARD
        );

        cb.key = fetch_keys[i];
        cb.proc = &wildcard;
        cb.copy = true;
        cb.scope = PMIX_LOCAL;

        PMIX_GDS_FETCH_KV(rc, pmix_globals.mypeer, &cb);
        if (rc != PMIX_SUCCESS) {
            PMIX_DESTRUCT(&cb);
            break;
        }
        // We should only have one item here.
        assert(1 == pmix_list_get_size(&cb.kvs));
        // Get a pointer to the only item in the list.
        pmix_kval_t *kv = (pmix_kval_t *)pmix_list_get_first(&cb.kvs);
        // Make sure we are dealing with the right stuff.
        assert(PMIX_CHECK_KEY(kv, fetch_keys[i]));
        assert(kv->value->type == PMIX_STRING);
        // Copy the value over.
        size_t nw = snprintf(
            fetched_path, PMIX_PATH_MAX, "%s",
            kv->value->data.string
        );
        PMIX_DESTRUCT(&cb);
        if (nw >= PMIX_PATH_MAX) {
            // Try another.
            continue;
        }
        else {
            // We got a usable fetched key.
            fetched_kv = true;
            break;
        }
    }
    // Didn't find a specific temp basedir, so just use a general one.
    if (!fetched_kv) {
        static const char *tmpdir = NULL;
        if (NULL == (tmpdir = getenv("TMPDIR"))) {
            tmpdir = "/tmp";
        }
        return tmpdir;
    }
    else {
        return fetched_path;
    }
}

/**
 * Returns a valid path or NULL on error.
 */
static const char *
get_shmem_backing_path(
    pmix_gds_shmem_job_t *job,
    const char *id
) {
    static char path[PMIX_PATH_MAX] = {'\0'};
    const char *basedir = fetch_base_tmpdir(job);
    // Now that we have the base path, append unique name.
    size_t nw = snprintf(
        path, PMIX_PATH_MAX, "%s/gds-%s.%s.%d",
        basedir, PMIX_GDS_SHMEM_NAME, id, getpid()
    );
    if (nw >= PMIX_PATH_MAX) {
        return NULL;
    }
    return path;
}

/**
 * Create and attach to a shared-memory segment.
 */
pmix_status_t
pmix_gds_shmem_segment_create_and_attach(
    pmix_gds_shmem_job_t *job,
    const char *segment_id,
    size_t segment_size
) {
    pmix_status_t rc = PMIX_SUCCESS;

    // Find a hole in virtual memory that meets our size requirements.
    size_t base_addr = 0;
    rc = pmix_vmem_find_hole(
        VMEM_HOLE_BIGGEST, &base_addr, segment_size
    );
    if (PMIX_SUCCESS != rc) {
        goto out;
    }
    PMIX_GDS_SHMEM_VOUT(
        "%s: found vmhole at address=0x%zx", __func__, base_addr
    );
    // Find a unique path for the shared-memory backing file.
    const char *segment_path = get_shmem_backing_path(job, segment_id);
    if (!segment_path) {
        rc = PMIX_ERROR;
        goto out;
    }
    PMIX_GDS_SHMEM_VOUT(
        "%s: segment backing file path is %s (size=%zd B)",
        __func__, segment_path, segment_size
    );
    // Create a shared-memory segment backing store at the given path.
    rc = pmix_shmem_segment_create(
        job->shmem, segment_size, segment_path
    );
    if (PMIX_SUCCESS != rc) {
        goto out;
    }
    // Attach to the shared-memory segment with the given address.
    uintptr_t mmap_addr;
    rc = pmix_shmem_segment_attach(
        job->shmem, (void *)base_addr, &mmap_addr
    );
    if (PMIX_SUCCESS != rc) {
        goto out;
    }
    // Make sure that we mapped to the requested address.
    if (mmap_addr != (uintptr_t)job->shmem->base_address) {
        pmix_show_help(
            "help-gds-shmem.txt",
            "shmem-segment-attach:address-mismatch",
            true,
            (size_t)base_addr,
            (size_t)mmap_addr

        );
        rc = PMIX_ERROR;
        goto out;
    }
    PMIX_GDS_SHMEM_VOUT(
        "%s: mmapd at address=0x%zx", __func__, (size_t)mmap_addr
    );
out:
    if (PMIX_SUCCESS != rc) {
        (void)pmix_shmem_segment_detach(job->shmem);
        PMIX_ERROR_LOG(rc);
    }
    return rc;
}

/*
 * vim: ft=cpp ts=4 sts=4 sw=4 expandtab
 */
