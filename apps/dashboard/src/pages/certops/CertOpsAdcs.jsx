import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Box,
  Collapse,
  Flex,
  FormControl,
  FormLabel,
  HStack,
  Icon,
  Input,
  Select,
  SimpleGrid,
  Stack,
  Text,
  VStack,
} from '@chakra-ui/react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { useOutletContext } from 'react-router';
import CopyableId from '../../components/CopyableId.jsx';
import { listAgents } from '../../components/certops/certopsAgentsApi';
import CertOpsBadge from '../../components/certops/CertOpsBadge.jsx';
import {
  abandonEnrollment,
  confirmIssuerKey,
  createIssuer,
  dispatchIssuerPreflight,
  enrollmentStateLabel,
  listEnrollments,
  listIssuers,
  proposeEnrollmentRequestId,
} from '../../components/certops/certopsEnrollmentsApi';
import { useCertOpsWorkspaceAdminState } from '../../components/certops/useCertOps.js';
import {
  DashboardActionButton,
  DashboardErrorAlert,
  DashboardPanel,
  DashboardPanelHeader,
  DashboardState,
} from '../../components/DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { showError, showSuccess } from '../../utils/toast.js';

const PREFLIGHT_POLL_MS = 3000;
const PREFLIGHT_POLL_ATTEMPTS = 8;

function errorText(err, fallback) {
  return err?.response?.data?.error || fallback;
}

function preflightSignature(preflight) {
  if (!preflight) return '';
  const certs = (preflight.caCertificates || [])
    .map(cert => cert.keySha256)
    .join(',');
  return [
    preflight.caConfig,
    preflight.template,
    preflight.templateCheck?.verdict,
    preflight.caCheck?.verdict,
    certs,
  ].join('|');
}

function verdictScheme(verdict) {
  if (verdict === 'safe') return 'green';
  if (verdict === 'unsafe') return 'red';
  return 'gray';
}

function enrollmentScheme(state) {
  if (state === 'issued' || state === 'validated' || state === 'installed') {
    return 'green';
  }
  if (
    state === 'denied' ||
    state === 'rejected_invalid' ||
    state === 'refused' ||
    state === 'abandoned' ||
    state === 'expired' ||
    state === 'cancelled' ||
    state === 'install_failed' ||
    state === 'validation_expired'
  ) {
    return 'red';
  }
  if (
    state === 'pending_issuance' ||
    state === 'submission_uncertain' ||
    state === 'validation_deferred'
  ) {
    return 'orange';
  }
  return 'blue';
}

function checkReasons(check) {
  return Array.isArray(check?.reasons) ? check.reasons.filter(Boolean) : [];
}

function checkSummary(check) {
  const verdict = check?.verdict || 'unknown';
  const reasons = checkReasons(check);
  if (verdict === 'safe' || reasons.length === 0) return verdict;
  return `${verdict} (${reasons.join(', ')})`;
}

function Notice({ children }) {
  return (
    <Alert status='warning' variant='left-accent' borderRadius='md' py={2}>
      <AlertIcon />
      <AlertDescription fontSize='sm'>{children}</AlertDescription>
    </Alert>
  );
}

function IssuerNotices({ issuer }) {
  if (!issuer?.revalidationRequired) return null;
  return (
    <Notice>
      The CA key changed. Run preflight again and confirm the new key before
      creating enrollments.
    </Notice>
  );
}

function EnrollmentNotices({ enrollment }) {
  const notes = [];
  if (
    enrollment.revalidationRequired ||
    enrollment.lastErrorCode === 'ADCS_CA_KEY_CHANGED'
  ) {
    notes.push(
      'The CA key changed. New enrollments wait until an admin confirms a new key.'
    );
  }
  if (enrollment.snapshotStale) {
    notes.push(
      `This enrollment stays on issuer version ${enrollment.issuerVersion}. The issuer is now version ${enrollment.issuerCurrentVersion}. It keeps the CA and template from that version.`
    );
  }
  if (notes.length === 0) return null;
  return (
    <Stack spacing={2}>
      {notes.map(note => (
        <Notice key={note}>{note}</Notice>
      ))}
    </Stack>
  );
}

const PAGE_LIMIT = 100;

function actionProps(busyKey, key, blocked) {
  return {
    isLoading: busyKey === key,
    isDisabled: Boolean(blocked) || (Boolean(busyKey) && busyKey !== key),
  };
}

function requestIdLine(enrollment) {
  if (enrollment.requestId) return `RequestId ${enrollment.requestId}`;
  if (enrollment.operatorRequestId) {
    return `Recorded RequestId ${enrollment.operatorRequestId}, waiting for the CA to confirm it`;
  }
  return 'RequestId none';
}

function shortId(id) {
  const text = String(id || '');
  return text.length > 8 ? text.slice(0, 8) : text;
}

function enrollmentMeta(enrollment) {
  const idLine = requestIdLine(enrollment);
  if (!enrollment.caKeySha256) return idLine;
  return `${idLine} · key prefix ${enrollment.caKeySha256.slice(0, 12)}`;
}

function keyStatus(issuer) {
  if (issuer.revalidationRequired) return 'Key changed';
  if (issuer.currentVersion > 0 && issuer.confirmedKeySha256) {
    return 'Confirmed';
  }
  return 'Unconfirmed';
}

function keyScheme(issuer) {
  if (issuer.revalidationRequired) return 'orange';
  if (issuer.currentVersion > 0 && issuer.confirmedKeySha256) return 'green';
  return 'gray';
}

const fieldLabelProps = {
  fontSize: 'xs',
  fontWeight: 'medium',
  mb: 1,
};

function ConfirmKeys({ issuer, busyKey, paused, onConfirm }) {
  const certs = issuer.lastPreflight?.caCertificates || [];
  const alreadyPinned =
    !issuer.revalidationRequired && issuer.currentVersion > 0;
  const pending = certs.filter(
    cert => !alreadyPinned || cert.keySha256 !== issuer.confirmedKeySha256
  );
  if (pending.length === 0) {
    return (
      <Text fontSize='sm'>
        This CA key is already confirmed on version {issuer.currentVersion}.
      </Text>
    );
  }
  return (
    <Flex gap={2} wrap='wrap'>
      {pending.map(cert => {
        const prefix = cert.keySha256?.slice(0, 12);
        return (
          <DashboardActionButton
            key={cert.keySha256}
            variant='outline'
            {...actionProps(
              busyKey,
              `confirm:${issuer.id}:${cert.keySha256}`,
              paused
            )}
            aria-label={`Confirm key ${prefix} for ${issuer.name}`}
            onClick={() =>
              onConfirm(issuer.id, cert.keySha256, issuer.lastPreflight)
            }
          >
            Confirm key {prefix}
          </DashboardActionButton>
        );
      })}
    </Flex>
  );
}

function VerdictBadge({ label, verdict }) {
  return (
    <CertOpsBadge colorScheme={verdictScheme(verdict)}>
      {label} {verdict || 'none'}
    </CertOpsBadge>
  );
}

function IssuerWork({
  issuer,
  agents,
  busyKey,
  paused,
  muted,
  onPreflight,
  onConfirm,
}) {
  const safe =
    issuer.lastPreflight?.templateCheck?.verdict === 'safe' &&
    issuer.lastPreflight?.caCheck?.verdict === 'safe';
  return (
    <Stack spacing={3}>
      <IssuerNotices issuer={issuer} />
      {issuer.lastPreflight ? (
        <Text fontSize='sm' color={muted} overflowWrap='anywhere'>
          Preflight {issuer.lastPreflight.caConfig} /{' '}
          {issuer.lastPreflight.template}: template{' '}
          {checkSummary(issuer.lastPreflight.templateCheck)}, CA{' '}
          {checkSummary(issuer.lastPreflight.caCheck)}.
        </Text>
      ) : (
        <Text fontSize='sm' color={muted}>
          No preflight yet.
        </Text>
      )}
      <form onSubmit={event => onPreflight(event, issuer.id)}>
        <SimpleGrid columns={{ base: 1, lg: 4 }} spacing={3}>
          <FormControl isRequired>
            <FormLabel {...fieldLabelProps}>Agent</FormLabel>
            <Select
              name='agentId'
              size='sm'
              aria-label={`Agent for ${issuer.name}`}
              required
              isDisabled={paused}
            >
              <option value=''>Select an agent</option>
              {agents.map(agent => (
                <option key={agent.id} value={agent.id}>
                  {agent.name || agent.agentId}
                </option>
              ))}
            </Select>
          </FormControl>
          <FormControl isRequired>
            <FormLabel {...fieldLabelProps}>CA config</FormLabel>
            <Input
              name='caConfig'
              size='sm'
              aria-label={`CA config for ${issuer.name}`}
              placeholder={'host\\CA Name'}
              required
              isDisabled={paused}
            />
          </FormControl>
          <FormControl isRequired>
            <FormLabel {...fieldLabelProps}>Template</FormLabel>
            <Input
              name='template'
              size='sm'
              aria-label={`Template for ${issuer.name}`}
              placeholder='Template common name'
              required
              isDisabled={paused}
            />
          </FormControl>
          <Flex align='flex-end'>
            <DashboardActionButton
              type='submit'
              variant='outline'
              {...actionProps(busyKey, `preflight:${issuer.id}`, paused)}
              aria-label={`Run preflight for ${issuer.name}`}
            >
              Run preflight
            </DashboardActionButton>
          </Flex>
        </SimpleGrid>
      </form>
      {safe ? (
        <ConfirmKeys
          issuer={issuer}
          busyKey={busyKey}
          paused={paused}
          onConfirm={onConfirm}
        />
      ) : null}
    </Stack>
  );
}

function IssuerRow({
  issuer,
  isOpen,
  onToggle,
  agents,
  busyKey,
  paused,
  muted,
  rowHoverBg,
  expandedBg,
  onPreflight,
  onConfirm,
}) {
  const preflightLine = issuer.lastPreflight
    ? `${issuer.lastPreflight.caConfig} / ${issuer.lastPreflight.template}`
    : '';
  if (issuer.kind !== 'adcs') {
    return (
      <Box px={2} py={2}>
        <HStack spacing={2} align='center'>
          <Box boxSize={3.5} flexShrink={0} />
          <Text fontSize='sm' fontWeight='semibold' noOfLines={1}>
            {issuer.name}
          </Text>
          <CertOpsBadge>ACME</CertOpsBadge>
          <Text fontSize='xs' color={muted}>
            v{issuer.currentVersion || 0}
          </Text>
        </HStack>
        <Text ml={6} mt={1} fontSize='xs' color={muted}>
          This issuer uses ACME. Preflight on this page is only for AD CS.
        </Text>
      </Box>
    );
  }

  return (
    <Box>
      <Box
        px={2}
        py={2}
        borderRadius='md'
        cursor='pointer'
        _hover={{ bg: rowHoverBg }}
        role='button'
        tabIndex={0}
        aria-expanded={isOpen}
        aria-label={`${isOpen ? 'Collapse' : 'Expand'} ${issuer.name}`}
        onClick={onToggle}
        onKeyDown={event => {
          if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            onToggle();
          }
        }}
      >
        <HStack
          spacing={2}
          align='center'
          flexWrap={{ base: 'wrap', md: 'nowrap' }}
        >
          <Icon
            as={isOpen ? ChevronDown : ChevronRight}
            boxSize={3.5}
            color={muted}
            flexShrink={0}
          />
          <Text
            fontSize='sm'
            fontWeight='semibold'
            noOfLines={1}
            flexShrink={0}
          >
            {issuer.name}
          </Text>
          <Text fontSize='xs' color={muted} flexShrink={0}>
            v{issuer.currentVersion || 0}
          </Text>
          {issuer.lastPreflight ? (
            <>
              <VerdictBadge
                label='Template'
                verdict={issuer.lastPreflight.templateCheck?.verdict}
              />
              <VerdictBadge
                label='CA'
                verdict={issuer.lastPreflight.caCheck?.verdict}
              />
            </>
          ) : null}
          <CertOpsBadge colorScheme={keyScheme(issuer)}>
            {keyStatus(issuer)}
          </CertOpsBadge>
        </HStack>
        {preflightLine ? (
          <Text
            ml={6}
            mt={1}
            fontSize='xs'
            color={muted}
            noOfLines={1}
            title={preflightLine}
          >
            {preflightLine}
          </Text>
        ) : (
          <Text ml={6} mt={1} fontSize='xs' color={muted}>
            No preflight yet.
          </Text>
        )}
      </Box>
      <Collapse in={isOpen} animateOpacity unmountOnExit>
        <Box
          mt={1}
          mb={2}
          ml={5}
          pl={3}
          py={3}
          bg={expandedBg}
          borderRadius='md'
        >
          <IssuerWork
            issuer={issuer}
            agents={agents}
            busyKey={busyKey}
            paused={paused}
            muted={muted}
            onPreflight={onPreflight}
            onConfirm={onConfirm}
          />
        </Box>
      </Collapse>
    </Box>
  );
}

function EnrollmentRow({
  enrollment,
  busyKey,
  paused,
  muted,
  rowHoverBg,
  confirmingAbandon,
  onReconcile,
  onAbandon,
  onAskAbandon,
  onKeep,
}) {
  const target = `${enrollment.caConfig || ''} / ${enrollment.template || ''}`;
  const names = enrollment.authorizedDnsNames || [];
  return (
    <Flex
      px={2}
      py={2}
      borderRadius='md'
      align={{ base: 'stretch', lg: 'flex-start' }}
      direction={{ base: 'column', lg: 'row' }}
      gap={3}
      _hover={{ bg: rowHoverBg }}
    >
      <Box flex='1' minW={0}>
        <HStack spacing={2} align='center'>
          <CertOpsBadge colorScheme={enrollmentScheme(enrollment.state)}>
            {enrollmentStateLabel(enrollment.state)}
          </CertOpsBadge>
          <Text fontSize='sm' fontWeight='semibold'>
            {shortId(enrollment.id)}
          </Text>
          {enrollment.snapshotStale ? (
            <CertOpsBadge colorScheme='orange'>Stale version</CertOpsBadge>
          ) : null}
        </HStack>
        <Text mt={1} fontSize='xs' color={muted} noOfLines={1} title={target}>
          {target}
        </Text>
        <HStack mt={1} spacing={2} align='center' flexWrap='wrap'>
          <Text fontSize='xs' color={muted} overflowWrap='anywhere'>
            {enrollmentMeta(enrollment)}
          </Text>
          {enrollment.caKeySha256 ? (
            <CopyableId
              id={enrollment.caKeySha256}
              label='Copy key'
              display=''
            />
          ) : null}
        </HStack>
        {names.length > 0 ? (
          <Text
            mt={1}
            fontSize='xs'
            color={muted}
            noOfLines={1}
            title={names.join(', ')}
          >
            Names {names.join(', ')}
          </Text>
        ) : null}
        {enrollment.attempt > 0 ? (
          <Text mt={1} fontSize='xs' color={muted}>
            Attempt {enrollment.attempt}
          </Text>
        ) : null}
        {enrollment.lastErrorCode &&
        enrollment.lastErrorCode !== 'ADCS_CA_KEY_CHANGED' ? (
          <Text mt={1} fontSize='xs' color={muted}>
            Last error {enrollment.lastErrorCode}
          </Text>
        ) : null}
        <Box mt={2}>
          <EnrollmentNotices enrollment={enrollment} />
        </Box>
      </Box>
      {enrollment.state === 'submission_uncertain' ? (
        <Stack spacing={2} align='flex-start' flexShrink={0}>
          <form onSubmit={event => onReconcile(event, enrollment.id)}>
            <Flex gap={2} align='center' wrap='wrap'>
              <Input
                name='requestId'
                size='sm'
                w='140px'
                aria-label={`RequestId for ${shortId(enrollment.id)}`}
                placeholder='RequestId'
                inputMode='numeric'
                min={1}
                max={4294967295}
                required
              />
              <DashboardActionButton
                type='submit'
                {...actionProps(busyKey, `reconcile:${enrollment.id}`, paused)}
                aria-label={`Reconcile ${shortId(enrollment.id)}`}
              >
                Reconcile
              </DashboardActionButton>
            </Flex>
          </form>
          {confirmingAbandon ? (
            <Flex gap={2} wrap='wrap'>
              <DashboardActionButton
                colorScheme='red'
                {...actionProps(busyKey, `abandon:${enrollment.id}`, paused)}
                aria-label={`Confirm abandon ${shortId(enrollment.id)}`}
                onClick={() => onAbandon(enrollment.id)}
              >
                Free the key
              </DashboardActionButton>
              <DashboardActionButton
                variant='outline'
                isDisabled={Boolean(busyKey)}
                onClick={onKeep}
              >
                Keep
              </DashboardActionButton>
            </Flex>
          ) : (
            <DashboardActionButton
              variant='outline'
              colorScheme='red'
              {...actionProps(busyKey, `abandon:${enrollment.id}`, paused)}
              aria-label={`Abandon ${shortId(enrollment.id)}`}
              onClick={() => onAskAbandon(enrollment.id)}
            >
              Abandon
            </DashboardActionButton>
          )}
        </Stack>
      ) : null}
    </Flex>
  );
}

export default function CertOpsAdcs() {
  const {
    status: adminStatus,
    isAdmin,
    retry: retryAdmin,
  } = useCertOpsWorkspaceAdminState();
  const outlet = useOutletContext();
  const pauseResolved = !outlet || outlet.killSwitchResolved === true;
  const paused = !pauseResolved || Boolean(outlet?.certOpsPaused);
  const { workspaceId } = useWorkspace();
  const { muted, dashboard } = useDashboardTheme();
  const rowHoverBg = dashboard.table.rowHover;
  const expandedBg = dashboard.bg.nested;
  const [issuers, setIssuers] = useState([]);
  const [enrollments, setEnrollments] = useState([]);
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState('');
  const [kind, setKind] = useState('adcs');
  const [busyKey, setBusyKey] = useState(null);
  const [waitingForPreflight, setWaitingForPreflight] = useState(null);
  const [preflightNote, setPreflightNote] = useState('');
  const [loadError, setLoadError] = useState('');
  const [issuerTotal, setIssuerTotal] = useState(0);
  const [enrollmentTotal, setEnrollmentTotal] = useState(0);
  const [pendingAbandonId, setPendingAbandonId] = useState(null);
  const [openIssuerId, setOpenIssuerId] = useState(null);
  const pollRef = useRef(null);
  const issuerListReady = useRef(false);

  const stopPreflightPoll = useCallback(() => {
    const poll = pollRef.current;
    if (!poll) return;
    poll.cancelled = true;
    clearInterval(poll.timer);
    poll.controller.abort();
    pollRef.current = null;
    setWaitingForPreflight(false);
  }, []);

  const reload = useCallback(async () => {
    if (!workspaceId || !isAdmin) return;
    const [issuerPage, enrollmentPage, agentPage] = await Promise.all([
      listIssuers(workspaceId, { limit: PAGE_LIMIT }),
      listEnrollments(workspaceId, { limit: PAGE_LIMIT }),
      listAgents(workspaceId),
    ]);
    setIssuers(issuerPage.items || []);
    setEnrollments(enrollmentPage.items || []);
    setAgents(agentPage.items || []);
    setIssuerTotal(Number(issuerPage.pagination?.total || 0));
    setEnrollmentTotal(Number(enrollmentPage.pagination?.total || 0));
    setLoadError('');
  }, [workspaceId, isAdmin]);

  useEffect(() => {
    if (!isAdmin) {
      setLoading(false);
      return undefined;
    }
    let cancelled = false;
    setLoading(true);
    reload()
      .catch(err => {
        if (!cancelled) {
          setLoadError(errorText(err, 'Could not load AD CS issuers.'));
          showError(errorText(err, 'Could not load AD CS issuers.'));
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [isAdmin, reload]);

  useEffect(() => () => stopPreflightPoll(), [workspaceId, stopPreflightPoll]);

  useEffect(() => {
    issuerListReady.current = false;
    setOpenIssuerId(null);
  }, [workspaceId]);

  useEffect(() => {
    if (issuerListReady.current || issuers.length === 0) return;
    issuerListReady.current = true;
    const first = issuers.find(item => item.kind === 'adcs');
    setOpenIssuerId(first ? first.id : null);
  }, [issuers]);

  const startPreflightPoll = useCallback(
    (issuerId, issuerName, previousSignature) => {
      stopPreflightPoll();
      setPreflightNote('');
      const poll = {
        cancelled: false,
        controller: new AbortController(),
        timer: null,
        attempts: 0,
      };
      pollRef.current = poll;
      setWaitingForPreflight(issuerName || 'the issuer');
      poll.timer = setInterval(async () => {
        if (poll.cancelled || pollRef.current !== poll) return;
        poll.attempts += 1;
        const attempt = poll.attempts;
        try {
          const page = await listIssuers(workspaceId, {
            signal: poll.controller.signal,
            limit: PAGE_LIMIT,
          });
          if (poll.cancelled || pollRef.current !== poll) return;
          const items = page.items || [];
          setIssuers(items);
          const current = items.find(item => item.id === issuerId);
          const changed =
            preflightSignature(current?.lastPreflight) !== previousSignature;
          if (
            (changed || attempt >= PREFLIGHT_POLL_ATTEMPTS) &&
            pollRef.current === poll
          ) {
            poll.cancelled = true;
            clearInterval(poll.timer);
            pollRef.current = null;
            setWaitingForPreflight(null);
            if (!changed) {
              setPreflightNote(
                `${issuerName || 'The issuer'} has not reported a preflight verdict yet. Use Refresh after the agent finishes.`
              );
            }
          }
        } catch (err) {
          if (poll.cancelled || pollRef.current !== poll) return;
          if (err?.code === 'ERR_CANCELED' || err?.name === 'CanceledError') {
            return;
          }
          poll.cancelled = true;
          clearInterval(poll.timer);
          pollRef.current = null;
          setWaitingForPreflight(false);
          showError(errorText(err, 'Could not refresh the preflight verdict.'));
        }
      }, PREFLIGHT_POLL_MS);
    },
    [stopPreflightPoll, workspaceId]
  );

  if (adminStatus === 'loading') {
    return (
      <DashboardState type='loading' title='Checking your workspace role...' />
    );
  }

  if (adminStatus === 'error') {
    return (
      <DashboardState
        title='Could not check your workspace role'
        description='The issuer page stays closed until the role lookup succeeds.'
        action={
          <DashboardActionButton onClick={retryAdmin}>
            Try again
          </DashboardActionButton>
        }
      />
    );
  }

  if (!isAdmin) {
    return (
      <DashboardState
        title='AD CS issuer management is limited to workspace admins'
        description='Viewers and managers can still see jobs. Confirming a CA key and reconciling an enrollment require an admin.'
      />
    );
  }

  async function handleCreate(event) {
    event.preventDefault();
    setBusyKey('create');
    try {
      await createIssuer(workspaceId, { kind, name: name.trim() });
      setName('');
      showSuccess(
        'Issuer created. Enrollment runs only for a CA and template named by an agent enrollment rule.'
      );
      await reload();
    } catch (err) {
      showError(errorText(err, 'Could not create the issuer.'));
    } finally {
      setBusyKey(null);
    }
  }

  async function handlePreflight(event, issuerId) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const previous = issuers.find(item => item.id === issuerId);
    const previousSignature = preflightSignature(previous?.lastPreflight);
    setBusyKey(`preflight:${issuerId}`);
    try {
      await dispatchIssuerPreflight(workspaceId, issuerId, {
        agentId: data.get('agentId'),
        caConfig: String(data.get('caConfig') || ''),
        template: String(data.get('template') || ''),
      });
      showSuccess(
        'Preflight dispatched. The verdict appears after the agent reports.'
      );
      await reload();
      startPreflightPoll(issuerId, previous?.name, previousSignature);
    } catch (err) {
      showError(errorText(err, 'Could not dispatch preflight.'));
    } finally {
      setBusyKey(null);
    }
  }

  async function handleConfirm(issuerId, keySha256, preflight) {
    setBusyKey(`confirm:${issuerId}:${keySha256}`);
    try {
      await confirmIssuerKey(workspaceId, issuerId, {
        caKeySha256: keySha256,
        caConfig: preflight?.caConfig,
        template: preflight?.template,
      });
      showSuccess('CA key confirmed on a new issuer version.');
      await reload();
    } catch (err) {
      showError(errorText(err, 'Could not confirm the CA key.'));
    } finally {
      setBusyKey(null);
    }
  }

  async function handleReconcile(event, enrollmentId) {
    event.preventDefault();
    const raw = String(
      new FormData(event.currentTarget).get('requestId') || ''
    ).trim();
    const requestId = Number(raw);
    if (
      !/^[0-9]+$/.test(raw) ||
      !Number.isInteger(requestId) ||
      requestId < 1 ||
      requestId > 4294967295
    ) {
      showError('RequestId must be an integer from 1 to 4294967295.');
      return;
    }
    setBusyKey(`reconcile:${enrollmentId}`);
    try {
      await proposeEnrollmentRequestId(workspaceId, enrollmentId, requestId);
      showSuccess(
        'RequestId recorded. A reconciliation continuation is scheduled.'
      );
      await reload();
    } catch (err) {
      showError(errorText(err, 'Could not record the RequestId.'));
    } finally {
      setBusyKey(null);
    }
  }

  async function handleAbandon(enrollmentId) {
    setBusyKey(`abandon:${enrollmentId}`);
    try {
      await abandonEnrollment(workspaceId, enrollmentId);
      showSuccess('Enrollment abandoned. A final continuation frees the key.');
      await reload();
    } catch (err) {
      showError(errorText(err, 'Could not abandon the enrollment.'));
    } finally {
      setBusyKey(null);
    }
  }

  return (
    <Stack spacing={4}>
      <DashboardPanel>
        <DashboardPanelHeader
          title='Issuers'
          description='Preflight checks a CA and template. It does not issue a certificate, and enrollment stays off.'
          action={
            <DashboardActionButton
              variant='outline'
              {...actionProps(busyKey, 'refresh', paused)}
              onClick={() =>
                reload().catch(err =>
                  showError(errorText(err, 'Could not refresh AD CS issuers.'))
                )
              }
            >
              Refresh
            </DashboardActionButton>
          }
        />
        {waitingForPreflight ? (
          <Text fontSize='sm' color={muted} mb={3}>
            Waiting for {waitingForPreflight} to report the preflight verdict.
          </Text>
        ) : null}
        {preflightNote ? (
          <Text fontSize='sm' color={muted} mb={3}>
            {preflightNote}
          </Text>
        ) : null}
        <Flex
          as='form'
          onSubmit={handleCreate}
          direction={{ base: 'column', md: 'row' }}
          align={{ md: 'flex-end' }}
          gap={3}
          mb={issuers.length > 0 || !loading ? 4 : 0}
        >
          <FormControl maxW={{ md: '160px' }}>
            <FormLabel {...fieldLabelProps}>Kind</FormLabel>
            <Select
              size='sm'
              value={kind}
              onChange={event => setKind(event.target.value)}
              aria-label='Issuer kind'
            >
              <option value='adcs'>AD CS</option>
              <option value='acme'>ACME</option>
            </Select>
          </FormControl>
          <FormControl flex='1'>
            <FormLabel {...fieldLabelProps}>Name</FormLabel>
            <Input
              size='sm'
              value={name}
              onChange={event => setName(event.target.value)}
              placeholder='Issuer name'
              aria-label='Issuer name'
              maxLength={128}
              required
            />
          </FormControl>
          <DashboardActionButton
            type='submit'
            {...actionProps(busyKey, 'create', paused)}
          >
            Create issuer
          </DashboardActionButton>
        </Flex>
        {loading ? (
          <DashboardState
            type='loading'
            title='Loading issuers and enrollments...'
            py={6}
          />
        ) : issuers.length === 0 ? (
          <Text fontSize='sm' color={muted}>
            No issuers yet.
          </Text>
        ) : (
          <VStack align='stretch' spacing={1}>
            {issuers.map(issuer => (
              <IssuerRow
                key={issuer.id}
                issuer={issuer}
                isOpen={openIssuerId === issuer.id}
                onToggle={() =>
                  setOpenIssuerId(current =>
                    current === issuer.id ? null : issuer.id
                  )
                }
                agents={agents}
                busyKey={busyKey}
                paused={paused}
                muted={muted}
                rowHoverBg={rowHoverBg}
                expandedBg={expandedBg}
                onPreflight={handlePreflight}
                onConfirm={handleConfirm}
              />
            ))}
          </VStack>
        )}
        {issuerTotal > issuers.length ? (
          <Text fontSize='sm' color={muted} mt={3}>
            Showing {issuers.length} of {issuerTotal} issuers.
          </Text>
        ) : null}
      </DashboardPanel>

      {!loading ? (
        <DashboardPanel>
          <DashboardPanelHeader
            title='Enrollments'
            description='Pending approval waits for the CA. An uncertain submission needs the RequestId before it can be reconciled.'
          />
          {enrollmentTotal > enrollments.length ? (
            <Text fontSize='sm' color={muted} mb={3}>
              Showing {enrollments.length} of {enrollmentTotal} enrollments.
            </Text>
          ) : null}
          {loadError ? (
            <DashboardErrorAlert>{loadError}</DashboardErrorAlert>
          ) : enrollments.length === 0 ? (
            <DashboardState
              py={6}
              title='No enrollments yet'
              description='Enrollment stays off. This list will show requests after that gate passes.'
            />
          ) : (
            <VStack align='stretch' spacing={1}>
              {enrollments.map(enrollment => (
                <EnrollmentRow
                  key={enrollment.id}
                  enrollment={enrollment}
                  busyKey={busyKey}
                  paused={paused}
                  muted={muted}
                  rowHoverBg={rowHoverBg}
                  confirmingAbandon={pendingAbandonId === enrollment.id}
                  onReconcile={handleReconcile}
                  onAbandon={handleAbandon}
                  onAskAbandon={setPendingAbandonId}
                  onKeep={() => setPendingAbandonId(null)}
                />
              ))}
            </VStack>
          )}
        </DashboardPanel>
      ) : null}
    </Stack>
  );
}
