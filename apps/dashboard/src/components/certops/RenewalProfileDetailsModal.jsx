import {
  Badge,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalHeader,
  ModalOverlay,
} from '@chakra-ui/react';
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

/** Read-only view of the execution contract stored by a renewal profile. */
export default function RenewalProfileDetailsModal({
  isOpen,
  onClose,
  profile,
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
                  <Badge
                    colorScheme={profile.autoRenewEnabled ? 'green' : 'orange'}
                    variant='subtle'
                    textTransform='none'
                    fontWeight='medium'
                  >
                    {profile.autoRenewEnabled
                      ? 'Auto-renews'
                      : 'Auto-renew off'}
                  </Badge>
                ) : null}
                {profile.derived ? (
                  <Badge
                    colorScheme='blue'
                    variant='subtle'
                    textTransform='none'
                    fontWeight='medium'
                  >
                    Derived
                  </Badge>
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
              {renderField('Certificates using it', profile.certificateCount)}
              {renderField('Auto-renew', boolLabel(profile.autoRenewEnabled))}
              {renderField('Lead time', leadTime)}
              {renderField('Status', profile.status)}
              {renderField('Derived', boolLabel(profile.derived))}
              {renderField('Description', profile.description)}
            </DashboardModalDataSection>

            <DashboardModalDataSection
              title='Certificate'
              tokens={tokens}
              icon={FileText}
            >
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
