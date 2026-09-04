import TokenDetailModal from './TokenDetailModal.jsx';
import CertificateDetailsModal from './certops/CertificateDetailsModal.jsx';
import { isCertToken } from './certops/certopsFormat.js';
import { useCertOpsForToken } from './certops/useCertOps.js';

function DashboardCertificateDetailModal(props) {
  const certOps = useCertOpsForToken(props.token?.id);
  return (
    <CertificateDetailsModal
      {...props}
      certOps={certOps}
      compactTableSections
      propertyValueRows
    />
  );
}

export default function DashboardTokenDetailModal({
  token,
  TOKEN_CATEGORIES,
  ...props
}) {
  if (isCertToken(token)) {
    return <DashboardCertificateDetailModal token={token} {...props} />;
  }

  return (
    <TokenDetailModal
      token={token}
      TOKEN_CATEGORIES={TOKEN_CATEGORIES}
      {...props}
    />
  );
}
