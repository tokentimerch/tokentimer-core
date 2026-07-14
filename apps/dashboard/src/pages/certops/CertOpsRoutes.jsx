import { Navigate, Route, Routes } from 'react-router-dom';
import CertOpsOperations from './CertOpsOperations.jsx';

/**
 * Router for the /certops/* splat route (plan 11.0: single wiring point in
 * App.jsx). Orchestration-only surfaces (D6): jobs, evidence, machine tokens.
 * Future CertOps pages (agents, approvals) mount here without touching App.jsx.
 */
export default function CertOpsRoutes({ session, onLogout, onAccountClick }) {
  return (
    <Routes>
      <Route
        path='operations'
        element={
          <CertOpsOperations
            session={session}
            onLogout={onLogout}
            onAccountClick={onAccountClick}
          />
        }
      />
      <Route path='*' element={<Navigate to='/certops/operations' replace />} />
    </Routes>
  );
}
