import { useEffect, useState } from 'react';
import {
  Badge,
  Box,
  Button,
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
import { showSuccess } from '../../utils/toast.js';
import { useCertOpsIsWorkspaceAdmin } from './useCertOps.js';
import {
  useCertOpsRenewalProfiles,
  useUpdateRenewalProfile,
} from './useCertOpsRenewals.js';
import { truncationSummary } from './certopsPagination';

/**
 * Renewal profiles (W8).
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
          <DashboardModalTitle>Switch automatic renewal off?</DashboardModalTitle>
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
  const { profiles, total, loading, error, refresh } =
    useCertOpsRenewalProfiles(refreshSignal);
  const { saving, error: saveError, clearError, save } =
    useUpdateRenewalProfile();
  const [disableTarget, setDisableTarget] = useState(null);

  const titleColor = useColorModeValue('gray.700', 'gray.200');
  const muted = useColorModeValue('gray.600', 'gray.400');

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

  const summary = truncationSummary({
    shown: profiles.length,
    pagination: { total },
    noun: 'profiles',
  });

  return (
    <Box>
      <HStack justify='space-between' align='flex-start' mb={1} spacing={3}>
        <Text fontSize='md' fontWeight='bold' color={titleColor}>
          Renewal profiles
        </Text>
        {loading ? <Spinner size='sm' /> : null}
      </HStack>
      <Text fontSize='sm' color={muted} mb={3}>
        A profile is the renewal contract for the certificates that use it: which
        names to request, which key to generate, and which command and host
        deploy the result. Profiles are created automatically from a successful
        issuance, so the deployment details are fixed to what already worked and
        changing them means issuing again.
      </Text>

      {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
      {saveError ? <DashboardErrorAlert>{saveError}</DashboardErrorAlert> : null}

      {loading ? (
        <HStack spacing={2} color={muted} py={4} justify='center'>
          <Spinner size='sm' />
          <Text fontSize='sm'>Loading renewal profiles...</Text>
        </HStack>
      ) : null}

      {!loading && !error && profiles.length === 0 ? (
        <Box py={6} textAlign='center'>
          <Text fontSize='sm' fontWeight='semibold' color={titleColor}>
            No renewal profiles yet.
          </Text>
          <Text fontSize='sm' color={muted} mt={1}>
            A profile is created automatically the first time an agent issues a
            certificate for this workspace.
          </Text>
        </Box>
      ) : null}

      {!loading && profiles.length > 0 ? (
        <>
          <TableContainer>
            <Table size='sm' variant='simple'>
              <Thead>
                <Tr>
                  <Th>Profile</Th>
                  <Th>Certificates</Th>
                  <Th>Automatic renewal</Th>
                  <Th>Lead time</Th>
                  <Th>Key</Th>
                  {isAdmin ? <Th textAlign='right'>Actions</Th> : null}
                </Tr>
              </Thead>
              <Tbody>
                {profiles.map(profile => {
                  const badge = statusBadge(profile);
                  const renewal = profile.renewalProfile || {};
                  const rowSaving = saving === profile.id;
                  const archived = profile.status === 'archived';
                  return (
                    <Tr key={profile.id}>
                      <Td>
                        <Text fontSize='sm' fontWeight='medium'>
                          {profile.name}
                        </Text>
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
                            <Text fontSize='xs' color={muted}>
                              {renewal.dns.provider}
                            </Text>
                          ) : null}
                        </HStack>
                      </Td>
                      <Td>
                        <Text fontSize='sm'>{profile.certificateCount}</Text>
                      </Td>
                      <Td>
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
                      <Td>
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
                      <Td>
                        <Text fontSize='sm'>
                          {renewal.keyAlgorithm
                            ? `${String(renewal.keyAlgorithm).toUpperCase()} ${renewal.keySize || ''}`.trim()
                            : '--'}
                        </Text>
                      </Td>
                      {isAdmin ? (
                        <Td textAlign='right'>
                          {archived ? (
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
                          )}
                        </Td>
                      ) : null}
                    </Tr>
                  );
                })}
              </Tbody>
            </Table>
          </TableContainer>
          {summary ? (
            <Text fontSize='xs' color={muted} mt={2}>
              {summary}
            </Text>
          ) : null}
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
    </Box>
  );
}
