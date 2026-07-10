import { useCallback, useEffect, useState } from 'react';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import {
  getJob,
  listJobEvidence,
  listJobLog,
  listJobs,
} from './certopsJobsApi';
import { listApiTokens } from './certopsTokensApi';
import { useCertOpsEnabled } from './useCertOps.js';

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
 * outage). Other failures surface a user-readable error string.
 *
 * @param {string|null|undefined} jobId
 * @returns {{ enabled: boolean|null, job: object|null, logEntries: object[], evidence: object[], loading: boolean, error: string, refresh: function }}
 */
export function useCertOpsJobTimeline(jobId) {
  const { workspaceId } = useWorkspace();
  const enabled = useCertOpsEnabled();
  const [job, setJob] = useState(null);
  const [logEntries, setLogEntries] = useState([]);
  const [evidence, setEvidence] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [reloadTick, setReloadTick] = useState(0);

  const refresh = useCallback(() => {
    setReloadTick(tick => tick + 1);
  }, []);

  useEffect(() => {
    if (!workspaceId || enabled !== true || !jobId) {
      setJob(null);
      setLogEntries([]);
      setEvidence([]);
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
        setEvidence(
          Array.isArray(evidenceData?.items) ? evidenceData.items : []
        );
      } catch (err) {
        if (cancelled) return;
        if (err?.response?.status === 404) {
          setJob(null);
          setLogEntries([]);
          setEvidence([]);
          setError('');
          return;
        }
        setJob(null);
        setLogEntries([]);
        setEvidence([]);
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
  }, [workspaceId, enabled, jobId, reloadTick]);

  return { enabled, job, logEntries, evidence, loading, error, refresh };
}

/**
 * Loads CertOps API token metadata for the active workspace (read-only).
 * Create/revoke are called imperatively via certopsTokensApi from the panel.
 *
 * @returns {{ enabled: boolean|null, tokens: object[], loading: boolean, error: string, refresh: function }}
 */
export function useCertOpsApiTokens() {
  const { workspaceId } = useWorkspace();
  const enabled = useCertOpsEnabled();
  const [tokens, setTokens] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [reloadTick, setReloadTick] = useState(0);

  const refresh = useCallback(() => {
    setReloadTick(tick => tick + 1);
  }, []);

  useEffect(() => {
    if (!workspaceId || enabled !== true) {
      setTokens([]);
      setLoading(false);
      setError('');
      return undefined;
    }

    let cancelled = false;
    const controller = new AbortController();
    setLoading(true);
    setError('');

    listApiTokens(workspaceId, { signal: controller.signal })
      .then(data => {
        if (!cancelled) {
          setTokens(Array.isArray(data?.items) ? data.items : []);
        }
      })
      .catch(err => {
        if (cancelled) return;
        setTokens([]);
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
  }, [workspaceId, enabled, reloadTick]);

  return { enabled, tokens, loading, error, refresh };
}
