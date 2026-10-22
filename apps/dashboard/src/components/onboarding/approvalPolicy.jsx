import { useEffect, useState } from 'react';
import { useInRouterContext, Link as RouterLink } from 'react-router';
import { Link, Text } from '@chakra-ui/react';
import { getWorkspaceCertOpsPauseState } from '../certops/certopsApi.js';
import { useDashboardThemeColors } from '../../hooks/useDashboardTheme';
import { StatusPanel } from './panels.jsx';

const CERTOPS_SETTINGS = '/certops/settings';

/**
 * The workspace "Job approval" policy, read from the same endpoint the
 * CertOps settings panel uses. `required` is null while it is unknown (not
 * loaded, or the read failed): nothing about approval is promised then. It is
 * only a hint for what to say before a job exists; once a job exists its
 * status is the ground truth.
 */
export function useJobApprovalPolicy(workspaceId) {
  const [required, setRequired] = useState(null);
  useEffect(() => {
    if (!workspaceId) return undefined;
    let cancelled = false;
    const controller = new AbortController();
    const load = () =>
      getWorkspaceCertOpsPauseState(workspaceId, { signal: controller.signal })
        .then(state => {
          if (cancelled) return;
          setRequired(
            typeof state?.certOpsRequireApprovalAlways === 'boolean'
              ? state.certOpsRequireApprovalAlways
              : null
          );
        })
        .catch(() => {
          if (!cancelled) setRequired(null);
        });
    load();
    // The setting is changed in another tab, so re-read it on return.
    window.addEventListener('focus', load);
    return () => {
      cancelled = true;
      controller.abort();
      window.removeEventListener('focus', load);
    };
  }, [workspaceId]);
  return { required };
}

/** In-app link when a router is present, a plain link otherwise. */
export function CertOpsSettingsLink() {
  const routed = useInRouterContext();
  const { dashboard } = useDashboardThemeColors();
  return (
    <Link
      {...(routed
        ? { as: RouterLink, to: CERTOPS_SETTINGS }
        : { href: CERTOPS_SETTINGS })}
      color={dashboard.accent.interactiveForeground}
      textDecoration='underline'
    >
      CertOps settings
    </Link>
  );
}

/**
 * Said before a job is created. Approval is only promised when the workspace
 * policy is on; when it is off the operator learns where to turn it on.
 */
export function ApprovalPolicyNote({ required, noun = 'job' }) {
  if (required === true) {
    return (
      <Text fontSize='sm' data-testid='approval-policy-on'>
        Job approval is on for this workspace, so this {noun} waits until a
        workspace manager other than the person who creates it approves it
        (Certificate Management, Jobs).
      </Text>
    );
  }
  if (required === false) {
    return (
      <Text fontSize='sm' data-testid='approval-policy-off'>
        Approval is off for this workspace, jobs start right away. Turn it on in{' '}
        <CertOpsSettingsLink /> if you want to approve each job.
      </Text>
    );
  }
  return null;
}

/** Shown only while the server reports the job as pending approval. */
export function ApprovalWaitPanel({ job, title = 'Waiting for approval' }) {
  if (job?.status !== 'pending_approval') return null;
  return (
    <StatusPanel status='info' title={title} testId='approval-wait'>
      A workspace manager other than the person who created this job must
      approve it (Certificate Management, Jobs). You cannot approve your own
      job. Nothing runs until then.
    </StatusPanel>
  );
}
