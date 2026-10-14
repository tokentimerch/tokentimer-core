import { useEffect, useState } from 'react';
import CertOpsBadge from './CertOpsBadge.jsx';
import {
  Box,
  Link,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalHeader,
  ModalOverlay,
  Text,
} from '@chakra-ui/react';
import { Link as RouterLink } from 'react-router';
import { listCertificates } from './certopsApi';
import { formatDate } from './certopsFormat.js';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import {
  BadgeCheck,
  FileText,
  Globe2,
  Info,
  Server,
  ShieldCheck,
} from 'lucide-react';
import {
  DashboardDetailsModalFrame,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import {
  DashboardDetailsModalFooter,
  DashboardDetailsModalHeader,
  DashboardDetailsSummary,
  DashboardModalDataSection,
  DashboardModalDetailRow,
  DashboardModalDetailsGrid,
} from '../DashboardModalDetails.jsx';

function rowsFromProfile(profile) {
  if (!Array.isArray(profile?.certificates)) return [];
  return profile.certificates
    .filter(item => item && item.id)
    .map(item => ({
      id: item.id,
      commonName: item.commonName || item.id,
      profileId: profile.id,
    }));
}

function hasDisplayValue(value) {
  if (Array.isArray(value)) return value.some(hasDisplayValue);
  if (typeof value === 'string') return value.trim().length > 0;
  return value !== null && value !== undefined;
}

function fileModeLabel(value) {
  if (value === null || value === undefined) return null;
  return `0${Number(value).toString(8)}`;
}

function boolLabel(value) {
  if (value === true) return 'Yes';
  if (value === false) return 'No';
  return null;
}

export function useBoundCertificates(workspaceId) {
  const [certificates, setCertificates] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!workspaceId) {
      setCertificates([]);
      setLoading(false);
      return undefined;
    }
    let cancelled = false;
    setLoading(true);
    (async () => {
      const found = [];
      let offset = 0;
      for (let page = 0; page < 8; page += 1) {
        const result = await listCertificates(workspaceId, {
          limit: 100,
          offset,
        });
        const items = Array.isArray(result?.items) ? result.items : [];
        for (const item of items) {
          if (item?.profileId) found.push(item);
        }
        if (items.length < 100) break;
        offset += items.length;
      }
      return found;
    })()
      .then(found => {
        if (!cancelled) setCertificates(found);
      })
      .catch(() => {
        if (!cancelled) setCertificates([]);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [workspaceId]);

  return { certificates, loading };
}

function certificateLabel(certificate) {
  return certificate?.commonName || certificate?.name || 'Unnamed certificate';
}

export function namesForProfile(certificates, profileId) {
  return (certificates || [])
    .filter(item => item?.profileId === profileId)
    .map(certificateLabel);
}

/** Read-only view of the execution contract stored by a renewal profile. */
export default function RenewalProfileDetailsModal({
  isOpen,
  onClose,
  profile,
  boundCertificates = null,
  boundCertificatesLoading = false,
}) {
  const {
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    outlineButtonProps,
    primaryButtonProps,
    tokens,
  } = useDashboardModalProps();

  const { workspaceId } = useWorkspace();
  const provided = Array.isArray(boundCertificates);
  const ownLoad = useBoundCertificates(
    provided || !isOpen ? null : workspaceId
  );
  const scanned = (provided ? boundCertificates : ownLoad.certificates).filter(
    item => item?.profileId === profile?.id
  );
  const apiRows = rowsFromProfile(profile);
  const certificateRows = scanned.length > 0 ? scanned : apiRows;
  const certificatesLoading =
    certificateRows.length === 0 &&
    (provided ? boundCertificatesLoading : ownLoad.loading);

  if (!profile) return null;

  const renewal = profile.renewalProfile || {};
  const sanPolicy = renewal.sanPolicy || {};
  const sans = Array.isArray(sanPolicy.sans) ? sanPolicy.sans : [];
  const targets = Array.isArray(renewal.deploymentTargets)
    ? renewal.deploymentTargets
    : renewal.target
      ? [renewal.target]
      : [];
  const leadTime =
    profile.renewBeforeDays == null
      ? 'Deployment default'
      : `${profile.renewBeforeDays} days`;

  const renderField = (label, value, options = {}) => {
    if (!hasDisplayValue(value)) return null;
    return (
      <DashboardModalDetailRow
        label={label}
        value={value}
        mono={Boolean(options.mono)}
        tokens={tokens}
      />
    );
  };

  const summaryItems = [
    {
      label: 'Certificates',
      value: profile.certificateCount,
    },
    {
      label: 'Auto-renewal',
      value: boolLabel(profile.autoRenewEnabled),
      accent: profile.autoRenewEnabled ? 'green.400' : 'orange.400',
    },
    {
      label: 'Lead time',
      value: leadTime,
    },
    {
      label: 'Status',
      value: profile.status,
    },
  ];

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      scrollBehavior='inside'
      isCentered
      motionPreset='none'
    >
      <ModalOverlay />
      <DashboardDetailsModalFrame>
        <ModalHeader {...headerProps} py={{ base: 4, md: 4 }}>
          <DashboardDetailsModalHeader
            title={profile.name || 'Renewal profile'}
            subtitle='Certificate renewal profile'
            badgeLabel='Renewal profile'
            badgeColorScheme='blue'
            statusBadges={
              <>
                {hasDisplayValue(profile.autoRenewEnabled) ? (
                  <CertOpsBadge
                    colorScheme={profile.autoRenewEnabled ? 'green' : 'orange'}
                  >
                    {profile.autoRenewEnabled
                      ? 'Auto-renews'
                      : 'Auto-renew off'}
                  </CertOpsBadge>
                ) : null}
                {profile.derived ? (
                  <CertOpsBadge colorScheme='blue'>Derived</CertOpsBadge>
                ) : null}
              </>
            }
          />
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} top={{ base: 3, md: 3 }} />

        <ModalBody {...bodyProps} py={{ base: 4, md: 4 }}>
          <DashboardDetailsSummary items={summaryItems} />

          <DashboardModalDetailsGrid>
            <DashboardModalDataSection
              title='Overview'
              tokens={tokens}
              icon={Info}
            >
              {renderField('Auto-renew', boolLabel(profile.autoRenewEnabled))}
              {renderField('Lead time', leadTime)}
              {renderField('Status', profile.status)}
              {renderField('Derived', boolLabel(profile.derived))}
              {renderField('Description', profile.description)}
            </DashboardModalDataSection>

            <DashboardModalDataSection
              title='Certificates using this profile'
              tokens={tokens}
              icon={FileText}
              columns={1}
            >
              {certificatesLoading ? (
                <Text fontSize='sm' color={tokens.subtleText}>
                  Loading certificates...
                </Text>
              ) : null}
              {!certificatesLoading && certificateRows.length === 0 ? (
                <Text fontSize='sm' color={tokens.subtleText}>
                  {Number(profile.certificateCount) > 0
                    ? 'These certificates could not be loaded.'
                    : 'No certificate is using this profile yet.'}
                </Text>
              ) : null}
              {!certificatesLoading &&
              certificateRows.length > 0 &&
              Number(profile.certificateCount) > certificateRows.length ? (
                <Text
                  fontSize='xs'
                  color={tokens.subtleText}
                  gridColumn='1 / -1'
                >
                  {`${Number(profile.certificateCount) - certificateRows.length} more certificates use this profile than this list shows.`}
                </Text>
              ) : null}
              {certificateRows.map(certificate => {
                const names = Array.isArray(certificate.subjectAltNames)
                  ? certificate.subjectAltNames.filter(Boolean)
                  : [];
                return (
                  <Box key={certificate.id} py={2} gridColumn='1 / -1'>
                    <Link
                      as={RouterLink}
                      to={`../certificates?certificateId=${encodeURIComponent(certificate.id)}`}
                      color='blue.500'
                      fontSize='sm'
                      fontWeight='medium'
                    >
                      {certificateLabel(certificate)}
                    </Link>
                    <Text fontSize='sm' color={tokens.subtleText}>
                      {[
                        certificate.status,
                        formatDate(certificate.notAfter) ||
                          'No expiry recorded',
                      ]
                        .filter(Boolean)
                        .join(' · ')}
                    </Text>
                    {names.length > 0 ? (
                      <Text fontSize='xs' color={tokens.subtleText}>
                        {names.join(', ')}
                      </Text>
                    ) : null}
                    {certificate.deployedCertPath ? (
                      <Text fontSize='xs' fontFamily='mono'>
                        {certificate.deployedCertPath}
                      </Text>
                    ) : null}
                  </Box>
                );
              })}
            </DashboardModalDataSection>

            <DashboardModalDataSection
              title='Renewal recipe'
              tokens={tokens}
              icon={FileText}
            >
              {certificateRows.length > 1
                ? renderField(
                    'Shared recipe',
                    'These fields are stored once on the profile. Each certificate above keeps its own name and install path.'
                  )
                : null}
              {renderField(
                'Key',
                renewal.keyAlgorithm
                  ? `${String(renewal.keyAlgorithm).toUpperCase()} ${renewal.keySize || ''}`.trim()
                  : null
              )}
              {renderField(
                'Rotate key on renew',
                boolLabel(renewal.keyRotationPolicy?.rotateOnRenew)
              )}
              {renderField('Preferred chain', renewal.preferredChain)}
              {renderField('SAN policy', sanPolicy.mode)}
              {renderField(
                'Allow wildcard SANs',
                boolLabel(sanPolicy.allowWildcards)
              )}
              {renderField('SANs', sans.join(', '))}
            </DashboardModalDataSection>

            <DashboardModalDataSection
              title='CA & ACME'
              tokens={tokens}
              icon={ShieldCheck}
            >
              {renderField('CA endpoint', renewal.ca?.endpoint, {
                mono: true,
              })}
              {renderField('Account reference', renewal.ca?.accountRef, {
                mono: true,
              })}
              {renderField('EAB reference', renewal.ca?.eabRef, {
                mono: true,
              })}
              {renderField('ACME client', renewal.acme?.kind)}
              {renderField('Command profile', renewal.acme?.commandRef, {
                mono: true,
              })}
            </DashboardModalDataSection>

            <DashboardModalDataSection
              title='DNS-01 challenge'
              tokens={tokens}
              icon={Globe2}
            >
              {renderField('Provider', renewal.dns?.provider)}
              {renderField('Zone', renewal.dns?.zone, { mono: true })}
            </DashboardModalDataSection>

            {targets.length === 0 ? (
              <DashboardModalDataSection
                title='Deployment target'
                tokens={tokens}
                icon={Server}
              >
                {renderField('Deployment target', 'None recorded')}
              </DashboardModalDataSection>
            ) : (
              targets.map((target, index) => (
                <DashboardModalDataSection
                  key={`${target.reference || 'target'}-${index}`}
                  title={
                    targets.length > 1
                      ? `Deployment target ${index + 1}`
                      : 'Deployment target'
                  }
                  tokens={tokens}
                  icon={Server}
                >
                  {renderField('Type', target.type)}
                  {renderField('Reference', target.reference, { mono: true })}
                  {renderField('Certificate path', target.certPath, {
                    mono: true,
                  })}
                  {renderField('Key path', target.keyPath, { mono: true })}
                  {renderField('Chain path', target.chainPath, { mono: true })}
                  {renderField('Reload service', target.reloadService, {
                    mono: true,
                  })}
                  {renderField('Owner', target.owner, { mono: true })}
                  {renderField('Group', target.group, { mono: true })}
                  {renderField(
                    'Certificate file mode',
                    fileModeLabel(target.certMode),
                    { mono: true }
                  )}
                  {renderField('Key file mode', fileModeLabel(target.keyMode), {
                    mono: true,
                  })}
                  {renderField(
                    'Chain file mode',
                    fileModeLabel(target.chainMode),
                    { mono: true }
                  )}
                  {renderField('Backup directory', target.backupDir, {
                    mono: true,
                  })}
                  {renderField(
                    'Backup retention',
                    target.backupRetentionCount == null
                      ? null
                      : `${target.backupRetentionCount} ${target.backupRetentionCount === 1 ? 'copy' : 'copies'}`
                  )}
                </DashboardModalDataSection>
              ))
            )}

            <DashboardModalDataSection
              title='Post-renewal verification'
              tokens={tokens}
              icon={BadgeCheck}
            >
              {renderField('Host', renewal.verification?.host, { mono: true })}
              {renderField('Port', renewal.verification?.port)}
              {renderField(
                'Require match',
                boolLabel(renewal.verification?.requireMatch)
              )}
            </DashboardModalDataSection>
          </DashboardModalDetailsGrid>
        </ModalBody>

        <DashboardDetailsModalFooter
          footerProps={footerProps}
          tokens={tokens}
          isViewer
          isEditing={false}
          saveError=''
          saving={false}
          onClose={onClose}
          outlineButtonProps={outlineButtonProps}
          primaryButtonProps={primaryButtonProps}
          message='Deployment details are read-only; changing them means issuing again.'
        />
      </DashboardDetailsModalFrame>
    </Modal>
  );
}
