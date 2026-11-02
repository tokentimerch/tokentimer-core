import { Navigate, Route, Routes } from 'react-router';
import OnboardingPage from './OnboardingPage.jsx';

/**
 * Single mount point for the wizard so edition apps only need one route line.
 */
export default function OnboardingRoutes({
  session,
  onLogout,
  onAccountClick,
}) {
  return (
    <Routes>
      <Route
        index
        element={
          <OnboardingPage
            session={session}
            onLogout={onLogout}
            onAccountClick={onAccountClick}
          />
        }
      />
      <Route path='*' element={<Navigate to='/onboarding' replace />} />
    </Routes>
  );
}
