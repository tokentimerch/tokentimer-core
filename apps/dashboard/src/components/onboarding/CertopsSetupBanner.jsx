import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { onboardingAPI } from '../../utils/onboardingApi.js';
import { useCertOpsCanManage } from '../certops/useCertOps.js';
import SetupBanner from './SetupBanner.jsx';
import { CERTOPS_FLOW, shouldShowCertopsBanner } from './certopsBannerRules.js';

/**
 * Shown at the top of Certificate Management while the workspace has no
 * agent, certificate or issuer. "Hide" is remembered on the server for this
 * user and workspace, in a flow of its own, so it never affects the dashboard
 * prompt. Any failed check shows nothing: it is advice, never a blocker.
 */
export default function CertopsSetupBanner({
  enabled,
  paused,
  api = onboardingAPI,
}) {
  const { workspaceId } = useWorkspace();
  const canManage = useCertOpsCanManage();
  const navigate = useNavigate();
  // Tied to the workspace it was read for, so a switch never shows (or hides)
  // the banner using the previous workspace's answer.
  const [state, setState] = useState({
    workspaceId: null,
    session: null,
    summary: null,
  });
  const current = state.workspaceId === workspaceId ? state : null;
  const session = useRef(null);

  useEffect(() => {
    // Only someone who can act on it needs the check.
    if (!workspaceId || enabled !== true || !canManage) return undefined;
    let cancelled = false;
    (async () => {
      try {
        const [s, summary] = await Promise.all([
          api.getSession(workspaceId, CERTOPS_FLOW),
          api.getSummary(workspaceId, CERTOPS_FLOW),
        ]);
        if (cancelled) return;
        session.current = s;
        setState({ workspaceId, session: s, summary });
      } catch (_) {
        if (!cancelled) {
          setState({ workspaceId, session: null, summary: null });
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [workspaceId, enabled, canManage, api]);

  const hide = async () => {
    setState(previous => ({
      ...previous,
      workspaceId,
      session: { ...previous.session, status: 'dismissed' },
    }));
    try {
      await api.putSession(workspaceId, CERTOPS_FLOW, {
        status: 'dismissed',
        expectedRevision: session.current?.revision ?? 0,
      });
    } catch (_) {
      /* worst case it shows once more */
    }
  };

  if (
    !shouldShowCertopsBanner({
      enabled,
      paused,
      canManage,
      summary: current?.summary ?? null,
      session: current?.session ?? null,
    })
  ) {
    return null;
  }

  return (
    <SetupBanner
      testId='certops-setup-banner'
      title='Certificate management is not set up yet.'
      message='Nothing is reporting certificates here. The quickstart connects an agent and shows your first certificates.'
      actionLabel='Start the CertOps quickstart'
      onAction={() => navigate('/onboarding?area=certops')}
      onHide={hide}
    />
  );
}
