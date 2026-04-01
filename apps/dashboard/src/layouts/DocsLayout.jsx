import { useEffect } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import PublicTopRightControls from '../components/PublicTopRightControls.jsx';

export default function DocsLayout({
  session,
  _sessionLoading,
  _onLogout,
  _onAccountClick,
  _onNavigateToDashboard,
  _onNavigateToLanding,
}) {
  const location = useLocation();

  // removed idle prefetching; rely on router-based code splitting

  // One-time hash scrolling using MutationObserver (no retry counters)
  useEffect(() => {
    const hash = location.hash ? location.hash.slice(1) : '';
    if (!hash) return;
    const targetNow = document.getElementById(hash);
    if (targetNow) {
      try {
        targetNow.scrollIntoView({ behavior: 'smooth', block: 'start' });
      } catch (_) {}
      return;
    }
    const observer = new MutationObserver(() => {
      const el = document.getElementById(hash);
      if (el) {
        try {
          el.scrollIntoView({ behavior: 'smooth', block: 'start' });
        } catch (_) {}
        observer.disconnect();
      }
    });
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true,
    });
    return () => observer.disconnect();
  }, [location.pathname, location.hash]);

  return (
    <>
      <style>{`:root{scroll-behavior:smooth}[id]{scroll-margin-top:90px}`}</style>
      <PublicTopRightControls session={session} />
      <Outlet />
    </>
  );
}
