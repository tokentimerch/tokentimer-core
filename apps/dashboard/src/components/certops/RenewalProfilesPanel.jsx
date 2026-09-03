import { useEffect, useMemo, useState } from 'react';
import {
  Badge,
  Box,
  Button,
  Flex,
  HStack,
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
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import { DashboardErrorAlert } from '../DashboardPrimitives.jsx';
import DashboardPagination from '../DashboardPagination.jsx';
import {
  CERTOPS_PAGE_SIZE_OPTIONS,
  useCertOpsListUrlState,
} from '../../hooks/useCertOpsUrlState.js';
import { showSuccess } from '../../utils/toast.js';
import { useCertOpsIsWorkspaceAdmin } from './useCertOps.js';
import {
  useCertOpsRenewalProfiles,
  useUpdateRenewalProfile,
} from './useCertOpsRenewals.js';
import RenewalProfileDetailsModal from './RenewalProfileDetailsModal.jsx';
import {
  CertOpsMobileFieldLabel,
  CertOpsSortableHeader,
  CertOpsTruncatedText,
  nextCertOpsTableSort,
  sortCertOpsTableRows,
  useCertOpsResponsiveTableStyles,
} from './CertOpsResponsiveTable.jsx';

/**
 * Renewal profiles.
 *
 * The profile is what the scheduler hands an agent at renewal time, so this
 * panel is deliberately narrow: it shows the whole stored contract read-only and
 * exposes only the two controls that cannot change what executes on a host,
 * namely the automatic-renewal switch and the lead time.
 *
 * Editing paths, reload units, ACME commands, CA endpoints or DNS providers is
 * not offered because those values were derived from an issuance that provably
 * worked, and repointing a live deployment is a re-issuance rather than a
 * settings change. The server enforces the same boundary, so a client that tried
 * anyway would be refused.
 */

function statusBadge(profile) {
  if (profile.autoRenewEnabled) {
    return { label: 'On', scheme: 'green', variant: 'subtle' };
  }
  return {
    label: profile.status === 'archived' ? 'Archived' : 'Off',
    scheme: 'orange',
    variant: 'solid',
  };
}

const PROFILE_COLUMNS = [
  ['profile', 'Profile'],
  ['certificates', 'Certificates'],
  ['autoRenew', 'Auto-renew'],
  ['leadTime', 'Lead time'],
  ['key', 'Key'],
];

function profileSortValue(profile, key) {
  if (key === 'profile') return profile.name || '';
  if (key === 'certificates') return Number(profile.certificateCount || 0);
  if (key === 'autoRenew') return profile.autoRenewEnabled ? 1 : 0;
  if (key === 'leadTime') {
    return profile.renewBeforeDays == null
      ? null
      : Number(profile.renewBeforeDays);
  }
  if (key === 'key') {
    const renewal = profile.renewalProfile || {};
    return renewal.keyAlgorithm
      ? `${renewal.keyAlgorithm} ${renewal.keySize || ''}`.trim()
      : '';
  }
  return '';
}

/**
 * Confirmation for switching automatic renewal off.
 *
 * Turning renewal off means the certificate expires unless a human renews it,
 * which is a silent, delayed outage. Turning it back on needs no confirmation:
 * the safe direction should not be friction.
 */
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

  const certificateCount = Number(profile?.certificateCount || 0);

  return (
    <Modal isOpen={isOpen} onClose={onClose} isCentered size='lg'>
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame>
        <ModalHeader {...headerProps}>
          <DashboardModalTitle>
            Switch automatic renewal off?
          </DashboardModalTitle>
          <DashboardModalDescription>
            {certificateCount === 1
              ? 'The certificate using this profile will stop renewing automatically.'
              : `${certificateCount} certificates using this profile will stop renewing automatically.`}
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
  const muted = useColorModeValue('gray.600', 'gray.400');

  useEffect(() => {
    setValue(String(profile.renewBeforeDays ?? ''));
  }, [profile.renewBeforeDays]);

  if (!editing) {
    return (
      <HStack spacing={2}>
        <Text fontSize='sm'>
          {profile.renewBeforeDays == null
            ? 'Deployment default'
            : `${profile.renewBeforeDays} days`}
        </Text>
        {disabled ? null : (
          <Button size='xs' variant='ghost' onClick={() => setEditing(true)}>
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
      <Text fontSize='xs' color={valid ? muted : 'red.400'}>
        {valid
          ? 'Days before expiry to start renewing.'
          : 'Enter a whole number of days between 1 and 365.'}
      </Text>
    </VStack>
  );
}

export default function RenewalProfilesPanel({ refreshSignal, onChanged }) {
  const isAdmin = useCertOpsIsWorkspaceAdmin();
  // Both lists on this tab page independently, so each scopes its own search
  // params; sharing `offset` would move them together.
  const { limit, offset, setPage } = useCertOpsListUrlState({
    scope: 'profile',
  });
  const { profiles, pagination, loading, error, refresh } =
    useCertOpsRenewalProfiles(refreshSignal, { limit, offset });
  const {
    saving,
    error: saveError,
    clearError,
    save,
  } = useUpdateRenewalProfile();
  const [disableTarget, setDisableTarget] = useState(null);
  const [detailsTarget, setDetailsTarget] = useState(null);

  const titleColor = useColorModeValue('gray.700', 'gray.200');
  const muted = useColorModeValue('gray.600', 'gray.400');
  const tableStyles = useCertOpsResponsiveTableStyles();
  const [sort, setSort] = useState({ key: null, direction: 'asc' });
  const sortedProfiles = useMemo(
    () => sortCertOpsTableRows(profiles, sort, profileSortValue),
    [profiles, sort]
  );
  // The panel token is deliberately translucent, so it cannot serve as the
  // backdrop for a pinned cell: scrolled columns show through it. This is an
  // opaque approximation of the same surface.
  const pinnedBg = useColorModeValue('white', 'gray.800');
  const pinnedShadow = useColorModeValue(
    '-8px 0 8px -8px rgba(0, 0, 0, 0.25)',
    '-8px 0 8px -8px rgba(0, 0, 0, 0.6)'
  );

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
      <HStack justify='space-between' align='flex-start' mb={1} spacing={3}>
        <Text fontSize='md' fontWeight='bold' color={titleColor}>
          Renewal profiles
        </Text>
        {loading ? <Spinner size='sm' /> : null}
      </HStack>
      <Text fontSize='sm' color={muted} mb={3}>
        A profile is the renewal contract for the certificates that use it:
        which names to request, which key to generate, and which command and
        host deploy the result. Profiles are created automatically from a
        successful issuance, so the deployment details are fixed to what already
        worked and changing them means issuing again.
      </Text>

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
                A profile is created automatically the first time an agent
                issues a certificate for this workspace.
              </Text>
            </>
          )}
        </Box>
      ) : null}

      {!loading && profiles.length > 0 ? (
        <>
          {pagination ? (
            <Flex justify='flex-end' mb={4}>
              <DashboardPagination
                limit={pagination.limit || limit}
                offset={offset}
                total={pagination.total}
                pageSizeOptions={CERTOPS_PAGE_SIZE_OPTIONS}
                noun='renewal profiles'
                onChange={setPage}
              />
            </Flex>
          ) : null}
          <TableContainer {...tableStyles.tableContainerProps}>
            <Table {...tableStyles.tableProps}>
              <Thead {...tableStyles.theadProps}>
                <Tr>
                  {PROFILE_COLUMNS.map(([key, label]) => (
                    <CertOpsSortableHeader
                      key={key}
                      label={label}
                      sortKey={key}
                      sort={sort}
                      onSort={sortKey =>
                        setSort(current =>
                          nextCertOpsTableSort(current, sortKey)
                        )
                      }
                    />
                  ))}
                  <Th textAlign='right' {...stickyActions}>
                    Actions
                  </Th>
                </Tr>
              </Thead>
              <Tbody {...tableStyles.tbodyProps}>
                {sortedProfiles.map(profile => {
                  const badge = statusBadge(profile);
                  const renewal = profile.renewalProfile || {};
                  const rowSaving = saving === profile.id;
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
                              <Badge
                                colorScheme='blue'
                                variant='subtle'
                                textTransform='none'
                                fontWeight='medium'
                                fontSize='xs'
                              >
                                Derived
                              </Badge>
                            </Tooltip>
                          ) : null}
                          {renewal.dns?.provider ? (
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
                          Certificates
                        </CertOpsMobileFieldLabel>
                        <Text fontSize='sm'>{profile.certificateCount}</Text>
                      </Td>
                      <Td {...tableStyles.cellProps}>
                        <CertOpsMobileFieldLabel color={muted}>
                          Auto-renew
                        </CertOpsMobileFieldLabel>
                        <Badge
                          colorScheme={badge.scheme}
                          variant={badge.variant}
                          textTransform='none'
                          fontWeight='medium'
                          fontSize='xs'
                        >
                          {badge.label}
                        </Badge>
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
                          <Button
                            size='xs'
                            variant='ghost'
                            onClick={() => setDetailsTarget(profile)}
                          >
                            Details
                          </Button>
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
        saving={disableTarget ? saving === disableTarget.id : false}
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
      />
    </Box>
  );
}
