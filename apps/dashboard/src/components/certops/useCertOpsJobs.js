import { useCallback, useEffect, useRef, useState } from 'react';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import {
  getJob,
  listJobEvidence,
  listJobLog,
  listJobs,
} from './certopsJobsApi';
import { listApiTokens } from './certopsTokensApi';
import {
  useCertOpsAvailability,
  useCertOpsCanManage,
  useCertOpsEnabled,
} from './useCertOps.js';

/**
 * Loads the CertOps job list for the active workspace.
 *
 * Gated on workspaceId and `certops.enabled === true` (same pattern as
 * useWorkspaceCertOps). Re-fetches when filters change.
 *
 * @param {{ limit?: number, offset?: number, status?: string, subjectType?: string, subjectId?: string, operation?: string, source?: string }} [filters]
 * @returns {{ enabled: boolean|null, jobs: object[], pagination: { limit: number, offset: number }|null, loading: boolean, error: string, refresh: function }}
 */
export function useCertOpsJobs(filters = {}) {
  const { workspaceId } = useWorkspace();
  const enabled = useCertOpsEnabled();
  const {
    limit = 20,
    offset = 0,
    status,
    subjectType,
    subjectId,
    operation,
    source,
  } = filters;

  const [jobs, setJobs] = useState([]);
  const [pagination, setPagination] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [reloadTick, setReloadTick] = useState(0);

  const refresh = useCallback(() => {
    setReloadTick(tick => tick + 1);
  }, []);

  useEffect(() => {
    if (!workspaceId || enabled !== true) {
      setJobs([]);
      setPagination(null);
      setLoading(false);
      setError('');
      return undefined;
    }

    let cancelled = false;
    const controller = new AbortController();
    setLoading(true);
    setError('');

    listJobs(workspaceId, {
      limit,
      offset,
      status,
      subjectType,
      subjectId,
      operation,
      source,
      signal: controller.signal,
    })
      .then(data => {
        if (!cancelled) {
          setJobs(Array.isArray(data?.items) ? data.items : []);
          setPagination(data?.pagination || null);
        }
      })
      .catch(err => {
        if (cancelled) return;
        setJobs([]);
        setPagination(null);
        setError(
          err?.response?.data?.error ||
            err?.message ||
            'Could not load certificate operations jobs.'
        );
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [
    workspaceId,
    enabled,
    reloadTick,
    limit,
    offset,
    status,
    subjectType,
    subjectId,
    operation,
    source,
  ]);

  return { enabled, jobs, pagination, loading, error, refresh };
}

/**
 * Loads a single job plus its log and evidence timeline in parallel.
 *
 * A 404 on getJob clears the job and leaves error empty (job gone is not an
 * outage). Other failures surface a user-readable error string, including an
 * availability probe that completed with a non-404 failure (which would
 * otherwise leave the timeline loading forever); `refresh()` re-probes
 * availability as well, so it doubles as the retry path for that case.
 *
 * `externalRefreshToken` lets a parent (e.g. a job list's own "Refresh"
 * button) force a refetch of an already-mounted timeline from the outside:
 * this hook's own `refresh()` only helps a caller that holds this specific
 * hook instance, but an expanded timeline is normally owned by a child
 * component (EvidenceTimeline) the parent list doesn't have a handle to.
 * Any value that changes between renders (a counter, `Date.now()`, ...)
 * works; it is only ever compared by reference/equality, never read.
 *
 * @param {string|null|undefined} jobId
 * @param {*} [externalRefreshToken]
 * @returns {{ enabled: boolean|null, job: object|null, logEntries: object[], logPagination: object|null, evidence: object[], evidencePagination: object|null, loading: boolean, error: string, refresh: function }}
 */
export function useCertOpsJobTimeline(jobId, externalRefreshToken) {
  const { workspaceId } = useWorkspace();
  // The full availability state (not just the collapsed boolean of
  // useCertOpsEnabled): `enabled` is null both while the probe is still
  // resolving (ready: false) and after it failed (ready: true, error).
  // The two must render differently -- a spinner versus an error -- or a
  // failed probe leaves the timeline spinning forever with no way out.
  const {
    ready: availabilityReady,
    enabled,
    error: availabilityError,
    retry: retryAvailability,
  } = useCertOpsAvailability();
  const [job, setJob] = useState(null);
  const [logEntries, setLogEntries] = useState([]);
  const [logPagination, setLogPagination] = useState(null);
  const [evidence, setEvidence] = useState([]);
  const [evidencePagination, setEvidencePagination] = useState(null);
  // Defaults to true (not false): the very first render happens before any
  // effect has a chance to run, and a mounted timeline for a real jobId is
  // always about to check availability/fetch. Defaulting to false here made
  // that first paint show "Job not found or no longer available" instead of
  // a spinner, however briefly (worse the more mounts happen, since every
  // job-row expand mounts a fresh instance of this hook).
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [reloadTick, setReloadTick] = useState(0);

  const refresh = useCallback(() => {
    // Re-probe availability too: if the previous probe failed, bumping only
    // this hook's own tick would re-run the effect against the same failed
    // availability state and change nothing.
    retryAvailability();
    setReloadTick(tick => tick + 1);
  }, [retryAvailability]);

  // A parent-driven refresh (externalRefreshToken change) must offer the
  // same recovery as refresh(). Guarded by a ref so availability is only
  // re-probed when the token actually changes, not on every effect run
  // (retrying unconditionally would loop: retry -> state change -> rerun).
  const lastExternalRefreshTokenRef = useRef(externalRefreshToken);
  useEffect(() => {
    if (lastExternalRefreshTokenRef.current === externalRefreshToken) return;
    lastExternalRefreshTokenRef.current = externalRefreshToken;
    retryAvailability();
  }, [externalRefreshToken, retryAvailability]);

  useEffect(() => {
    if (!workspaceId || !jobId) {
      setJob(null);
      setLogEntries([]);
      setLogPagination(null);
      setEvidence([]);
      setEvidencePagination(null);
      setLoading(false);
      setError('');
      return undefined;
    }

    if (!availabilityReady) {
      // The availability probe (a separate hook instance per CertOps screen)
      // hasn't resolved yet for this mount. This is "still finding out",
      // not "not applicable" -- treat it as loading. Otherwise every fresh
      // mount (e.g. re-opening a job's evidence timeline) briefly rendered
      // "Job not found or no longer available" before the probe settled,
      // even though the job existed the whole time.
      setLoading(true);
      setError('');
      return undefined;
    }

    if (availabilityError) {
      // The probe completed but failed (network/5xx, not a 404): surface it
      // instead of spinning forever, and leave refresh() as the retry path.
      setJob(null);
      setLogEntries([]);
      setLogPagination(null);
      setEvidence([]);
      setEvidencePagination(null);
      setLoading(false);
      setError(availabilityError);
      return undefined;
    }

    if (enabled !== true) {
      setJob(null);
      setLogEntries([]);
      setLogPagination(null);
      setEvidence([]);
      setEvidencePagination(null);
      setLoading(false);
      setError('');
      return undefined;
    }

    let cancelled = false;
    const controller = new AbortController();
    setLoading(true);
    setError('');

    (async () => {
      try {
        const [jobData, logData, evidenceData] = await Promise.all([
          getJob(workspaceId, jobId, { signal: controller.signal }),
          listJobLog(workspaceId, jobId, { signal: controller.signal }),
          listJobEvidence(workspaceId, jobId, { signal: controller.signal }),
        ]);
        if (cancelled) return;
        setJob(jobData?.job || null);
        setLogEntries(Array.isArray(logData?.items) ? logData.items : []);
        setLogPagination(logData?.pagination || null);
        setEvidence(
          Array.isArray(evidenceData?.items) ? evidenceData.items : []
        );
        setEvidencePagination(evidenceData?.pagination || null);
      } catch (err) {
        if (cancelled) return;
        if (err?.response?.status === 404) {
          setJob(null);
          setLogEntries([]);
          setLogPagination(null);
          setEvidence([]);
          setEvidencePagination(null);
          setError('');
          return;
        }
        setJob(null);
        setLogEntries([]);
        setLogPagination(null);
        setEvidence([]);
        setEvidencePagination(null);
        setError(
          err?.response?.data?.error ||
            err?.message ||
            'Could not load certificate operations job timeline.'
        );
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [
    workspaceId,
    availabilityReady,
    availabilityError,
    enabled,
    jobId,
    reloadTick,
    externalRefreshToken,
  ]);

  return {
    enabled,
    job,
    logEntries,
    logPagination,
    evidence,
    evidencePagination,
    loading,
    error,
    refresh,
  };
}

/**
 * Loads CertOps API token metadata for the active workspace (read-only).
 * Create/revoke are called imperatively via certopsTokensApi from the panel.
 *
 * The list endpoint is manager-only server-side; the fetch is skipped for
 * non-managers so viewers see an empty state instead of a 403 error banner.
 *
 * @param {{ limit?: number, offset?: number }} [page] - Page position. Same
 *   convention as useCertOpsAgents: omitting `limit` asks for the whole
 *   token inventory.
 * @returns {{ enabled: boolean|null, tokens: object[], pagination: { limit: number|null, offset: number, total: number }|null, loading: boolean, error: string, refresh: function }}
 */
export function useCertOpsApiTokens(page = {}) {
  const { workspaceId } = useWorkspace();
  const enabled = useCertOpsEnabled();
  const canManage = useCertOpsCanManage();
  const { limit, offset = 0 } = page;
  const [tokens, setTokens] = useState([]);
  const [pagination, setPagination] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [reloadTick, setReloadTick] = useState(0);

  const refresh = useCallback(() => {
    setReloadTick(tick => tick + 1);
  }, []);

  useEffect(() => {
    if (!workspaceId || enabled !== true || !canManage) {
      setTokens([]);
      setPagination(null);
      setLoading(false);
      setError('');
      return undefined;
    }

    let cancelled = false;
    const controller = new AbortController();
    setLoading(true);
    setError('');

    listApiTokens(workspaceId, { limit, offset, signal: controller.signal })
      .then(data => {
        if (!cancelled) {
          setTokens(Array.isArray(data?.items) ? data.items : []);
          setPagination(data?.pagination || null);
        }
      })
      .catch(err => {
        if (cancelled) return;
        setTokens([]);
        setPagination(null);
        setError(
          err?.response?.data?.error ||
            err?.message ||
            'Could not load certificate operations API tokens.'
        );
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [workspaceId, enabled, canManage, reloadTick, limit, offset]);

  return { enabled, tokens, pagination, loading, error, refresh };
}
