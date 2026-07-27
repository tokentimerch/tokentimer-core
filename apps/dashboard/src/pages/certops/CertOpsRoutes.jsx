import { Navigate, Route, Routes } from 'react-router';
import CertOpsLayout from './CertOpsLayout.jsx';
import CertOpsJobs from './CertOpsJobs.jsx';
import CertOpsCertificates from './CertOpsCertificates.jsx';
import CertOpsRenewals from './CertOpsRenewals.jsx';
import CertOpsAgents from './CertOpsAgents.jsx';
import CertOpsSettings from './CertOpsSettings.jsx';

/**
 * Router for the /certops/* splat route: one layout (availability gate,
 * kill-switch banner, sub-nav) with a child per tab.
 *
 * `/certops/operations` is a permanent redirect, not a transitional one. It is
 * linked from published documentation, from the Control Center footer, and
 * from agent runbooks, so it has to keep resolving for an operator who reaches
 * it mid-incident.
 */
export default function CertOpsRoutes({ session, onLogout, onAccountClick }) {
  return (
    <Routes>
      <Route
        element={
          <CertOpsLayout
            session={session}
            onLogout={onLogout}
            onAccountClick={onAccountClick}
          />
        }
      >
        <Route path='jobs' element={<CertOpsJobs />} />
        <Route path='certificates' element={<CertOpsCertificates />} />
        <Route path='renewals' element={<CertOpsRenewals />} />
        <Route path='agents' element={<CertOpsAgents />} />
        <Route path='settings' element={<CertOpsSettings />} />
      </Route>
      <Route
        path='operations'
        element={<Navigate to='/certops/jobs' replace />}
      />
      <Route path='*' element={<Navigate to='/certops/jobs' replace />} />
    </Routes>
  );
}
