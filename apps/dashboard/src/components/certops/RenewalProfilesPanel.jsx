import CertOpsBadge from './CertOpsBadge.jsx';
import { useEffect, useState } from 'react';
import {
  Box,
  Button,
  Flex,
  HStack,
  IconButton,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  NumberDecrementStepper,
  NumberIncrementStepper,
  NumberInput,
  NumberInputField,
  NumberInputStepper,
  Select,
  Spinner,
  Table,
  TableContainer,
  Tbody,
  Td,
  Text,
  Th,
  Thead,
  Tooltip,
  Tr,
  VStack,
  useColorModeValue,
} from '@chakra-ui/react';
import { MoreVertical } from 'lucide-react';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import { DashboardErrorAlert } from '../DashboardPrimitives.jsx';
import { useDashboardThemeColors } from '../../hooks/useDashboardTheme';
import DashboardPagination from '../DashboardPagination.jsx';
import {
  CERTOPS_PAGE_SIZE_OPTIONS,
  useCertOpsListUrlState,
} from '../../hooks/useCertOpsUrlState.js';
import { showSuccess } from '../../utils/toast.js';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { listIssuers } from './certopsEnrollmentsApi';
import { useCertOpsIsWorkspaceAdmin } from './useCertOps.js';
import {
  useCertOpsRenewalProfiles,
  useUpdateRenewalProfile,
} from './useCertOpsRenewals.js';
import AdcsProfileWizard from './AdcsProfileWizard.jsx';
import RenewalProfileDetailsModal, {
  namesForProfile,
  useBoundCertificates,
} from './RenewalProfileDetailsModal.jsx';
import {
  CertOpsMobileFieldLabel,
  CertOpsSortableHeader,
  CertOpsTruncatedText,
  nextCertOpsTableSort,
  useCertOpsResponsiveTableStyles,
} from './CertOpsResponsiveTable.jsx';

/**
 * Renewal profiles.
 *
 * The profile is what the scheduler hands an agent at renewal time, so this
 * panel is deliberately narrow: it shows the whole stored contract read-only and
 * exposes the automatic-renewal switch, the lead time, and which workspace
 * issuer an AD CS enrollment uses. No issuer keeps the ACME path.
 *
 * Editing paths, reload units, ACME commands, CA endpoints or DNS providers is
 * not offered because those values were derived from an issuance that provably
 * worked, and repointing a live deployment is a re-issuance rather than a
 * settings change. The server enforces the same boundary, so a client that tried
 * anyway would be refused.
 */

function issuerLabel(value, issuers) {
  if (!value) return 'ACME';
  const match = issuers.find(issuer => issuer.id === value);
  return match ? `AD CS · ${match.name}` : 'AD CS issuer';
}

/**
 * Affected certificates come from the profile itself, so the operator sees what
 * the change touches before the server accepts it.
 */
function issuerChangeSentence(profile) {
  const count = Number(profile?.certificateCount || 0);
  if (count === 0) return 'No certificates use this profile yet.';
  const names = Array.isArray(profile?.certificates)
    ? profile.certificates.map(item => item?.commonName).filter(Boolean)
    : [];
  if (names.length === 0) {
    return count === 1
      ? 'The certificate using this profile will renew through the new issuer.'
      : `${count} certificates using this profile will renew through the new issuer.`;
  }
  const extra = count > names.length ? count - names.length : 0;
  const listed =
    extra > 0 ? `${names.join(', ')}, and ${extra} more` : names.join(', ');
  return `${listed} will renew through the new issuer from their next renewal.`;
}

function IssuerChangeModal({
  isOpen,
  onClose,
  profile,
  issuers,
  target,
  saving,
  error,
  onConfirm,
}) {
  const {
    overlayProps,
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    outlineButtonProps,
  } = useDashboardModalProps();

  return (
    <Modal isOpen={isOpen} onClose={onClose} isCentered size='lg'>
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame>
        <ModalHeader {...headerProps}>
          <DashboardModalTitle>
            Change issuer for {profile.name}?
          </DashboardModalTitle>
          <DashboardModalDescription>
            {issuerChangeSentence(profile)}
          </DashboardModalDescription>
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} />
        <ModalBody {...bodyProps}>
          <Text fontSize='sm' mb={3}>
            From {issuerLabel(profile.issuerId, issuers)} to{' '}
            {issuerLabel(target, issuers)}.
          </Text>
          <Text fontSize='sm'>
            {target
              ? 'AD CS renewal needs a Windows/IIS deployment target. An ACME-based profile cannot be converted in place. If the change is refused, create an AD CS renewal profile for these certificates instead.'
              : 'Renewal switches back to ACME, which uses this profile DNS and command settings.'}
          </Text>
          {error ? (
            <Box mt={3}>
              <DashboardErrorAlert>{error}</DashboardErrorAlert>
            </Box>
          ) : null}
        </ModalBody>
        <ModalFooter {...footerProps}>
          <Button {...outlineButtonProps} onClick={onClose} mr={3}>
            Cancel
          </Button>
          <Button
            colorScheme='blue'
            onClick={onConfirm}
            isLoading={Boolean(saving)}
          >
            Change issuer
          </Button>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}

function IssuerChoice({ profile, issuers, saving, onSave, saveError }) {
  const [value, setValue] = useState(profile.issuerId || '');
  const [editing, setEditing] = useState(false);
  // Null means no change is staged. An empty string stages ACME.
  const [pending, setPending] = useState(null);
  useEffect(() => {
    setValue(profile.issuerId || '');
  }, [profile.issuerId]);
  const known = !value || issuers.some(issuer => issuer.id === value);
  if (!editing) {
    return (
      <HStack spacing={2} maxW='240px'>
        <CertOpsTruncatedText
          value={issuerLabel(value, issuers)}
          fontSize='sm'
        />
        <Button
          size='xs'
          variant='outline'
          aria-label={`Change issuer for ${profile.name}`}
          onClick={() => setEditing(true)}
        >
          Change
        </Button>
      </HStack>
    );
  }
  return (
    <>
      <HStack spacing={2}>
        <Select
          size='xs'
          aria-label={`Issuer for ${profile.name}`}
          value={value}
          isDisabled={saving}
          onChange={event => {
            const next = event.target.value;
            if (next === (profile.issuerId || '')) return;
            setPending(next);
          }}
        >
          <option value=''>ACME</option>
          {known ? null : <option value={value}>AD CS issuer</option>}
          {issuers.map(issuer => (
            <option
              key={issuer.id}
              value={issuer.id}
            >{`AD CS · ${issuer.name}`}</option>
          ))}
        </Select>
        <Button size='xs' variant='ghost' onClick={() => setEditing(false)}>
          Done
        </Button>
      </HStack>
      <IssuerChangeModal
        isOpen={pending !== null}
        onClose={() => setPending(null)}
        profile={profile}
        issuers={issuers}
        target={pending}
        saving={saving}
        error={saveError}
        onConfirm={async () => {
          const saved = await onSave(pending || null);
          if (saved) {
            setPending(null);
            setEditing(false);
          }
        }}
      />
    </>
  );
}

function statusBadge(profile) {
  if (profile.autoRenewEnabled) {
    return { label: 'On', scheme: 'green' };
  }
  return {
    label: profile.status === 'archived' ? 'Archived' : 'Off',
    scheme: 'orange',
  };
}

const PROFILE_COLUMNS = [
  ['profile', 'Profile'],
  ['certificates', 'Certificates'],
  ['autoRenew', 'Auto-renew'],
  ['leadTime', 'Lead time'],
  ['key', 'Key'],
];

/**
 * Confirmation for switching automatic renewal off.
 *
 * Turning renewal off means the certificate expires unless a human renews it,
 * which is a silent, delayed outage. Turning it back on needs no confirmation:
 * the safe direction should not be friction.
 */
function stopRenewalSentence(profile) {
  const count = Number(profile?.certificateCount || 0);
  const names = Array.isArray(profile?.certificates)
    ? profile.certificates.map(item => item?.commonName).filter(Boolean)
    : [];
  if (names.length === 0) {
    return count === 1
      ? 'The certificate using this profile will stop renewing automatically.'
      : `${count} certificates using this profile will stop renewing automatically.`;
  }
  const extra = count > names.length ? count - names.length : 0;
  const listed =
    extra > 0 ? `${names.join(', ')}, and ${extra} more` : names.join(', ');
  return `${listed} will stop renewing automatically.`;
}

function DisableRenewalModal({ isOpen, onClose, profile, onConfirm, saving }) {
  const {
    overlayProps,
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    outlineButtonProps,
    dangerButtonProps,
  } = useDashboardModalProps();

  return (
    <Modal isOpen={isOpen} onClose={onClose} isCentered size='lg'>
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame>
        <ModalHeader {...headerProps}>
          <DashboardModalTitle>
            Switch automatic renewal off?
          </DashboardModalTitle>
          <DashboardModalDescription>
            {stopRenewalSentence(profile)}
          </DashboardModalDescription>
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} />
        <ModalBody {...bodyProps}>
          <Text fontSize='sm'>
            TokenTimer will keep monitoring expiry and alerting, but it will not
            renew. Affected certificates will expire on their expiry date unless
            you renew them yourself. You can switch this back on at any time.
          </Text>
        </ModalBody>
        <ModalFooter {...footerProps}>
          <Button {...outlineButtonProps} onClick={onClose} mr={3}>
            Keep renewing
          </Button>
          <Button
            {...dangerButtonProps}
            onClick={onConfirm}
            isLoading={Boolean(saving)}
          >
            Switch renewal off
          </Button>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}

/** Inline editor for the renewal lead time. */
function LeadTimeEditor({ profile, onSave, saving, disabled }) {
  const [value, setValue] = useState(String(profile.renewBeforeDays ?? ''));
  const [editing, setEditing] = useState(false);
  const { muted, dashboard } = useDashboardThemeColors();

  useEffect(() => {
    setValue(String(profile.renewBeforeDays ?? ''));
  }, [profile.renewBeforeDays]);

  if (!editing) {
    return (
      <HStack spacing={2}>
        <Text fontSize='sm' noOfLines={1}>
          {profile.renewBeforeDays == null
            ? 'Deployment default'
            : `${profile.renewBeforeDays} days`}
        </Text>
        {disabled ? null : (
          <Button
            size='xs'
            variant='outline'
            flexShrink={0}
            onClick={() => setEditing(true)}
          >
            Change
          </Button>
        )}
      </HStack>
    );
  }

  const parsed = Number(value);
  const valid = Number.isSafeInteger(parsed) && parsed >= 1 && parsed <= 365;

  return (
    <VStack align='stretch' spacing={1}>
      <HStack spacing={2}>
        <NumberInput
          size='xs'
          maxW='5.5rem'
          min={1}
          max={365}
          value={value}
          onChange={next => setValue(next)}
        >
          <NumberInputField aria-label='Renewal lead time in days' />
          <NumberInputStepper>
            <NumberIncrementStepper />
            <NumberDecrementStepper />
          </NumberInputStepper>
        </NumberInput>
        <Button
          size='xs'
          colorScheme='blue'
          isDisabled={!valid}
          isLoading={Boolean(saving)}
          onClick={async () => {
            const saved = await onSave(parsed);
            if (saved) setEditing(false);
          }}
        >
          Save
        </Button>
        <Button
          size='xs'
          variant='ghost'
          onClick={() => {
            setValue(String(profile.renewBeforeDays ?? ''));
            setEditing(false);
          }}
        >
          Cancel
        </Button>
      </HStack>
      <Text fontSize='xs' color={valid ? muted : dashboard.state.danger}>
        {valid
          ? 'Days before expiry to start renewing.'
          : 'Enter a whole number of days between 1 and 365.'}
      </Text>
    </VStack>
  );
}

export default function RenewalProfilesPanel({ refreshSignal, onChanged }) {
  const isAdmin = useCertOpsIsWorkspaceAdmin();
  const { workspaceId } = useWorkspace();
  const { certificates: boundCertificates, loading: boundCertificatesLoading } =
    useBoundCertificates(workspaceId);
  const [issuers, setIssuers] = useState([]);
  const [profileWizardOpen, setProfileWizardOpen] = useState(false);
  // Both lists on this tab page independently, so each scopes its own search
  // params; sharing `offset` would move them together.
  const { limit, offset, setPage } = useCertOpsListUrlState({
    scope: 'profile',
  });
  const [sort, setSort] = useState({ key: null, direction: 'asc' });
  const { profiles, pagination, loading, error, refresh } =
    useCertOpsRenewalProfiles(refreshSignal, {
      limit,
      offset,
      ...(sort.key ? { sort: sort.key, direction: sort.direction } : {}),
    });
  const {
    savingIds,
    error: saveError,
    clearError,
    save,
  } = useUpdateRenewalProfile();
  useEffect(() => {
    if (!isAdmin || !workspaceId) return undefined;
    let cancelled = false;
    listIssuers(workspaceId, { limit: 100 })
      .then(page => {
        if (!cancelled) setIssuers(page.items || []);
      })
      .catch(() => {
        if (!cancelled) setIssuers([]);
      });
    return () => {
      cancelled = true;
    };
  }, [isAdmin, workspaceId, profileWizardOpen]);

  const [disableTarget, setDisableTarget] = useState(null);
  const [detailsTarget, setDetailsTarget] = useState(null);

  const { muted, dashboard } = useDashboardThemeColors();
  const titleColor = dashboard.text.primary;
  const tableStyles = useCertOpsResponsiveTableStyles();
  const handleSort = key => {
    setSort(current => nextCertOpsTableSort(current, key));
    setPage({ offset: 0 });
  };
  // The panel token is deliberately translucent, so it cannot serve as the
  // backdrop for a pinned cell: scrolled columns show through it. This is an
  // opaque approximation of the same surface.
  const pinnedBg = useColorModeValue('white', 'gray.800');
  const pinnedShadow = useColorModeValue(
    '-8px 0 8px -8px rgba(0, 0, 0, 0.25)',
    '-8px 0 8px -8px rgba(0, 0, 0, 0.6)'
  );
  const actionColor = useColorModeValue('gray.600', 'rgba(203, 213, 225, 0.9)');
  const actionHoverBg = useColorModeValue('gray.100', 'rgba(30, 41, 59, 0.72)');
  const actionFocusShadow = useColorModeValue(
    '0 0 0 2px rgba(37, 99, 235, 0.28)',
    '0 0 0 2px rgba(96, 165, 250, 0.34)'
  );
  const actionButtonProps = {
    size: 'sm',
    variant: 'ghost',
    color: actionColor,
    borderRadius: 'md',
    _hover: { bg: actionHoverBg },
    _active: { bg: actionHoverBg },
    _focusVisible: {
      bg: actionHoverBg,
      boxShadow: actionFocusShadow,
    },
  };

  /**
   * Keeps the Actions column visible when the table overflows.
   *
   * Row width grows with content: a long profile name, an open lead-time editor,
   * more profiles. So the table exceeds its container at ordinary viewport
   * widths, and the column that scrolls out of sight is the last one, which here
   * holds the only controls the feature has. An operator looking for the off
   * switch would have to find a horizontal scrollbar first. Pinning it means the
   * controls are always reachable; the shadow signals that content continues
   * underneath.
   */
  const stickyActions = {
    position: { base: 'static', lg: 'sticky' },
    right: 0,
    bg: { base: 'transparent', lg: pinnedBg },
    boxShadow: { base: 'none', lg: pinnedShadow },
    zIndex: 1,
  };

  const applyChange = async (profile, changes, successMessage) => {
    clearError();
    const updated = await save(profile.id, changes);
    if (updated) {
      showSuccess(successMessage);
      refresh();
      if (onChanged) onChanged();
    }
    return updated;
  };

  const firstPage = () => setPage({ offset: 0 });
  // Rows can disappear under a page position that is still in the URL, e.g. a
  // shared link outliving the profiles it pointed at. That is not an empty
  // workspace, and offering the way back is the difference.
  const pageIsPastEnd = Boolean(
    pagination && pagination.total > 0 && offset >= pagination.total
  );

  return (
    <Box>
      <AdcsProfileWizard
        isOpen={profileWizardOpen}
        onClose={() => setProfileWizardOpen(false)}
        workspaceId={workspaceId}
        issuers={issuers}
        onCreated={refresh}
      />
      {isAdmin || (!loading && profiles.length > 0 && pagination) ? (
        <Flex align='center' justify='flex-end' gap={3} mb={4} wrap='wrap'>
          {isAdmin ? (
            <Button
              size='sm'
              colorScheme='blue'
              onClick={() => setProfileWizardOpen(true)}
            >
              New AD CS profile
            </Button>
          ) : null}
          {!loading && profiles.length > 0 && pagination ? (
            <DashboardPagination
              limit={pagination.limit || limit}
              offset={offset}
              total={pagination.total}
              pageSizeOptions={CERTOPS_PAGE_SIZE_OPTIONS}
              noun='renewal profiles'
              onChange={setPage}
            />
          ) : null}
        </Flex>
      ) : null}
      {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
      {saveError ? (
        <DashboardErrorAlert>{saveError}</DashboardErrorAlert>
      ) : null}

      {loading ? (
        <HStack spacing={2} color={muted} py={4} justify='center'>
          <Spinner size='sm' />
          <Text fontSize='sm'>Loading renewal profiles...</Text>
        </HStack>
      ) : null}

      {!loading && !error && profiles.length === 0 ? (
        <Box py={6} textAlign='center'>
          {pageIsPastEnd ? (
            <>
              <Text fontSize='sm' fontWeight='semibold' color={titleColor}>
                This page is past the end of the list.
              </Text>
              <Button size='xs' variant='ghost' mt={2} onClick={firstPage}>
                Back to the first page
              </Button>
            </>
          ) : (
            <>
              <Text fontSize='sm' fontWeight='semibold' color={titleColor}>
                No renewal profiles yet.
              </Text>
              <Text fontSize='sm' color={muted} mt={1}>
                Issue a certificate and TokenTimer derives an ACME profile from
                that run. For a private CA, confirm an issuer below, then choose
                New AD CS profile.
              </Text>
            </>
          )}
        </Box>
      ) : null}

      {!loading && profiles.length > 0 ? (
        <>
          <TableContainer {...tableStyles.tableContainerProps}>
            <Table {...tableStyles.tableProps}>
              <Thead {...tableStyles.theadProps}>
                <Tr>
                  {PROFILE_COLUMNS.flatMap(([key, label]) => {
                    const header = (
                      <CertOpsSortableHeader
                        key={key}
                        label={label}
                        sortKey={key}
                        sort={sort}
                        onSort={handleSort}
                      />
                    );
                    return key === 'profile'
                      ? [header, <Th key='issuer'>Issuer</Th>]
                      : [header];
                  })}
                  <Th textAlign='right' {...stickyActions}>
                    Actions
                  </Th>
                </Tr>
              </Thead>
              <Tbody {...tableStyles.tbodyProps}>
                {profiles.map(profile => {
                  const badge = statusBadge(profile);
                  const scannedNames = namesForProfile(
                    boundCertificates,
                    profile.id
                  );
                  const boundNames =
                    scannedNames.length > 0
                      ? scannedNames
                      : Array.isArray(profile.certificates)
                        ? profile.certificates
                            .map(item => item?.commonName)
                            .filter(Boolean)
                        : [];
                  const renewal = profile.renewalProfile || {};
                  const rowSaving = savingIds.has(profile.id);
                  const archived = profile.status === 'archived';
                  return (
                    <Tr key={profile.id} {...tableStyles.rowProps}>
                      <Td {...tableStyles.primaryCellProps}>
                        <CertOpsTruncatedText
                          value={profile.name}
                          fontSize='sm'
                          fontWeight='medium'
                        />
                        <HStack spacing={2} mt={1}>
                          {profile.derived ? (
                            <Tooltip
                              label='Generated automatically from a successful issuance, so its deployment details match what already worked on the host.'
                              hasArrow
                              placement='top'
                              openDelay={250}
                            >
                              <CertOpsBadge colorScheme='blue'>
                                Derived
                              </CertOpsBadge>
                            </Tooltip>
                          ) : null}
                          {boundNames.length > 0 ? (
                            <CertOpsTruncatedText
                              value={boundNames.join(', ')}
                              fontSize='xs'
                              color={muted}
                            />
                          ) : renewal.dns?.provider ? (
                            <CertOpsTruncatedText
                              value={renewal.dns.provider}
                              fontSize='xs'
                              color={muted}
                            />
                          ) : null}
                        </HStack>
                      </Td>
                      <Td {...tableStyles.cellProps}>
                        <CertOpsMobileFieldLabel color={muted}>
                          Issuer
                        </CertOpsMobileFieldLabel>
                        {isAdmin && !archived ? (
                          <IssuerChoice
                            profile={profile}
                            issuers={issuers}
                            saving={rowSaving}
                            saveError={saveError}
                            onSave={next =>
                              applyChange(
                                profile,
                                { issuerId: next },
                                next
                                  ? 'AD CS issuer selected. Enrollment runs only for a CA and template named by an agent enrollment rule.'
                                  : 'Profile stays on ACME'
                              )
                            }
                          />
                        ) : (
                          <CertOpsTruncatedText
                            value={issuerLabel(profile.issuerId, issuers)}
                            fontSize='sm'
                          />
                        )}
                      </Td>
                      <Td {...tableStyles.cellProps}>
                        <CertOpsMobileFieldLabel color={muted}>
                          Certificates
                        </CertOpsMobileFieldLabel>
                        <Text fontSize='sm'>{profile.certificateCount}</Text>
                      </Td>
                      <Td {...tableStyles.cellProps}>
                        <CertOpsMobileFieldLabel color={muted}>
                          Auto-renew
                        </CertOpsMobileFieldLabel>
                        <CertOpsBadge colorScheme={badge.scheme}>
                          {badge.label}
                        </CertOpsBadge>
                      </Td>
                      <Td {...tableStyles.cellProps}>
                        <CertOpsMobileFieldLabel color={muted}>
                          Lead time
                        </CertOpsMobileFieldLabel>
                        <LeadTimeEditor
                          profile={profile}
                          saving={rowSaving}
                          disabled={!isAdmin || archived}
                          onSave={days =>
                            applyChange(
                              profile,
                              { renewBeforeDays: days },
                              `Renewal lead time set to ${days} days`
                            )
                          }
                        />
                      </Td>
                      <Td {...tableStyles.cellProps}>
                        <CertOpsMobileFieldLabel color={muted}>
                          Key
                        </CertOpsMobileFieldLabel>
                        <Text fontSize='sm'>
                          {renewal.keyAlgorithm
                            ? `${String(renewal.keyAlgorithm).toUpperCase()} ${renewal.keySize || ''}`.trim()
                            : '--'}
                        </Text>
                      </Td>
                      <Td
                        {...tableStyles.actionCellProps}
                        textAlign='right'
                        {...stickyActions}
                      >
                        <HStack spacing={1} justify='flex-end'>
                          <Tooltip label='Details' hasArrow openDelay={250}>
                            <IconButton
                              {...actionButtonProps}
                              aria-label='Details'
                              icon={<MoreVertical size={16} />}
                              onClick={() => setDetailsTarget(profile)}
                            />
                          </Tooltip>
                          {isAdmin ? (
                            archived ? (
                              <Text fontSize='xs' color={muted}>
                                Archived
                              </Text>
                            ) : profile.autoRenewEnabled ? (
                              <Button
                                size='xs'
                                variant='outline'
                                colorScheme='red'
                                isLoading={rowSaving}
                                onClick={() => setDisableTarget(profile)}
                              >
                                Switch off
                              </Button>
                            ) : (
                              <Button
                                size='xs'
                                colorScheme='green'
                                isLoading={rowSaving}
                                onClick={() =>
                                  applyChange(
                                    profile,
                                    { autoRenewEnabled: true },
                                    'Automatic renewal switched on'
                                  )
                                }
                              >
                                Switch on
                              </Button>
                            )
                          ) : null}
                        </HStack>
                      </Td>
                    </Tr>
                  );
                })}
              </Tbody>
            </Table>
          </TableContainer>
          {!isAdmin ? (
            <Text fontSize='xs' color={muted} mt={2}>
              Only workspace admins can change renewal settings.
            </Text>
          ) : null}
        </>
      ) : null}

      <DisableRenewalModal
        isOpen={Boolean(disableTarget)}
        onClose={() => setDisableTarget(null)}
        profile={disableTarget}
        saving={disableTarget ? savingIds.has(disableTarget.id) : false}
        onConfirm={async () => {
          const updated = await applyChange(
            disableTarget,
            { autoRenewEnabled: false },
            'Automatic renewal switched off'
          );
          if (updated) setDisableTarget(null);
        }}
      />

      <RenewalProfileDetailsModal
        isOpen={Boolean(detailsTarget)}
        onClose={() => setDetailsTarget(null)}
        profile={detailsTarget}
        boundCertificates={boundCertificates}
        boundCertificatesLoading={boundCertificatesLoading}
      />
    </Box>
  );
}
