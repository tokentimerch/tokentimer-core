// Legacy Usage page stub. App.jsx redirects /usage to /control-center; this file
// is not imported as a route element.

import { Navigate } from 'react-router-dom';

export default function Usage() {
  return <Navigate to='/control-center' replace />;
}
