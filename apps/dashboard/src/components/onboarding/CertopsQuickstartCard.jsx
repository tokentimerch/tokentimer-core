import { useEffect, useId, useState } from 'react';
import { useNavigate } from 'react-router';
import { FiArrowRight } from 'react-icons/fi';
import {
  DashboardActionButton,
  DashboardPanel,
  DashboardPanelHeader,
} from '../DashboardPrimitives';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { onboardingAPI } from '../../utils/onboardingApi.js';
import { showError } from '../../utils/toast.js';
import { useCertOpsCanManage } from '../certops/useCertOps.js';
import { SessionController } from './sessionController.js';
import { clearGoal } from './sessionTransitions.js';
import {
  QUICKSTART_PATH,
  WIZARD_FLOW,
  quickstartLabel,
  quickstartMode,
} from './certopsQuickstartRules.js';

/**
 * A standing way into the CertOps quickstart from the Settings tab, shown
 * whether or not the empty-workspace banner is. Reopening a finished or
 * dismissed guide starts a clean session; the assets, agents and certificates
 * it created are untouched. People who cannot manage CertOps do not see it.
 */
export default function CertopsQuickstartCard({ api = onboardingAPI }) {
  const { workspaceId } = useWorkspace();
  const canManage = useCertOpsCanManage();
  const navigate = useNavigate();
  const noteId = useId();
  // Tied to its workspace so a switch never labels the button from the last one.
  const [loaded, setLoaded] = useState({ workspaceId: null, session: null });
  const [busy, setBusy] = useState(false);
  const session = loaded.workspaceId === workspaceId ? loaded.session : null;

  useEffect(() => {
    if (!workspaceId || !canManage) return undefined;
    let cancelled = false;
    api
      .getSession(workspaceId, WIZARD_FLOW)
      .then(s => {
        if (!cancelled) setLoaded({ workspaceId, session: s });
      })
      // Only the label depends on it; the click reads the session again.
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [workspaceId, canManage, api]);

  if (!canManage || !workspaceId) return null;

  const open = async () => {
    setBusy(true);
    try {
      const current = await api.getSession(workspaceId, WIZARD_FLOW);
      const mode = quickstartMode(current);
      if (mode === 'restart') {
        await api.resetSession(workspaceId, WIZARD_FLOW);
      } else if (mode === 'switch') {
        await new SessionController({
          api,
          workspaceId,
          flow: WIZARD_FLOW,
        }).update(clearGoal);
      }
      navigate(QUICKSTART_PATH);
    } catch (e) {
      showError(e?.message || 'Could not open the CertOps quickstart.');
      setBusy(false);
    }
  };

  return (
    <DashboardPanel data-testid='certops-quickstart-card'>
      <DashboardPanelHeader
        mb={0}
        title='CertOps quickstart'
        description='Walk through connecting an agent and seeing your first certificates. Run it again any time, for example to add another server. Anything it already created is kept.'
        action={
          <DashboardActionButton
            colorScheme='blue'
            rightIcon={<FiArrowRight />}
            onClick={open}
            isLoading={busy}
            aria-describedby={noteId}
          >
            {quickstartLabel(session)}
          </DashboardActionButton>
        }
      />
      <span id={noteId} hidden>
        Opens the guided CertOps setup for this workspace.
      </span>
    </DashboardPanel>
  );
}
