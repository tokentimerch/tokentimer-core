import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Box,
  Checkbox,
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
import { formatDate } from '../../components/certops/certopsFormat.js';
import {
  abandonEnrollment,
  cancelEnrollment,
  confirmIssuerKey,
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
import AdcsIssuerWizard from '../../components/certops/AdcsIssuerWizard.jsx';
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
      The CA key changed. Run the check again and choose the new certificate
      before creating enrollments. The CA and template stay the same.
    </Notice>
  );
}

function pinnedPair(issuer) {
  return {
    caConfig: issuer?.caConfig || issuer?.lastPreflight?.caConfig || '',
    template: issuer?.template || issuer?.lastPreflight?.template || '',
  };
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

// Refreshing the first page keeps any extra pages the operator already loaded.
function refreshPage(fresh, previous) {
  const seen = new Set(fresh.map(item => item.id));
  return [
    ...fresh,
    ...previous.slice(PAGE_LIMIT).filter(item => !seen.has(item.id)),
  ];
}

function appendPage(previous, page) {
  const seen = new Set(previous.map(item => item.id));
  return [...previous, ...page.filter(item => !seen.has(item.id))];
}

const FINISHED_ENROLLMENT_STATES = new Set([
  'cancelled',
  'denied',
  'refused',
  'rejected_invalid',
  'validation_expired',
  'abandoned',
  'expired',
  'installed',
]);

const PARKED_ENROLLMENT_STATES = new Set(['requested', 'install_failed']);

function enrollmentIsFinished(enrollment) {
  return FINISHED_ENROLLMENT_STATES.has(enrollment?.state);
}

function enrollmentIsParked(enrollment) {
  return PARKED_ENROLLMENT_STATES.has(enrollment?.state);
}

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
  // Approval waits on a specific CA, so name it on the same line as the RequestId.
  const line =
    enrollment.state === 'pending_issuance' && enrollment.caConfig
      ? `CA ${enrollment.caConfig} · ${idLine}`
      : idLine;
  if (!enrollment.caKeySha256) return line;
  return `${line} · key prefix ${enrollment.caKeySha256.slice(0, 12)}`;
}

function preflightIsSafe(issuer) {
  return (
    issuer.lastPreflight?.templateCheck?.verdict === 'safe' &&
    issuer.lastPreflight?.caCheck?.verdict === 'safe'
  );
}

function isConfiguredIssuer(issuer) {
  return issuer.kind !== 'adcs' || Number(issuer.currentVersion) > 0;
}

function isUnsafeRejectedIssuer(issuer) {
  if (issuer.kind !== 'adcs' || Number(issuer.currentVersion) > 0) return false;
  const preflight = issuer.lastPreflight;
  if (!preflight) return false;
  return (
    preflight.templateCheck?.verdict === 'unsafe' ||
    preflight.caCheck?.verdict === 'unsafe'
  );
}

function keyStatus(issuer) {
  if (issuer.revalidationRequired) return 'New certificate';
  if (issuer.currentVersion > 0 && issuer.confirmedKeySha256) {
    return 'Certificate chosen';
  }
  if (preflightIsSafe(issuer)) return 'Choose a certificate';
  return null;
}

function keyScheme(issuer) {
  if (issuer.revalidationRequired) return 'orange';
  if (issuer.currentVersion > 0 && issuer.confirmedKeySha256) return 'green';
  return 'blue';
}

function certTime(value) {
  const time = new Date(value).getTime();
  return Number.isNaN(time) ? 0 : time;
}

function groupCaCertificates(certs) {
  const groups = [];
  const indexByKey = new Map();
  certs.forEach((cert, index) => {
    const keySha256 = cert?.keySha256;
    if (!keySha256) return;
    let group = indexByKey.get(keySha256);
    if (!group) {
      group = { keySha256, certificates: [], firstIndex: index };
      indexByKey.set(keySha256, group);
      groups.push(group);
    }
    group.certificates.push(cert);
  });
  for (const group of groups) {
    group.certificates.sort(
      (a, b) => certTime(b.notBefore) - certTime(a.notBefore)
    );
    group.newestNotBefore = certTime(group.certificates[0]?.notBefore);
    group.thumbprintSha1 = group.certificates.find(
      cert => cert.thumbprintSha1
    )?.thumbprintSha1;
  }
  groups.sort(
    (a, b) =>
      b.newestNotBefore - a.newestNotBefore || a.firstIndex - b.firstIndex
  );
  return groups;
}

function validityLine(cert) {
  if (!cert?.notBefore && !cert?.notAfter) return 'Validity was not reported';
  const end = certTime(cert.notAfter);
  const state = end > 0 && end < Date.now() ? 'Expired' : 'Valid';
  return `${state} ${formatDate(cert.notBefore)} to ${formatDate(cert.notAfter)}`;
}

const fieldLabelProps = {
  fontSize: 'xs',
  fontWeight: 'medium',
  mb: 1,
};

function ConfirmKeys({ issuer, busyKey, paused, muted, onConfirm }) {
  const { border } = useDashboardTheme();
  const groups = groupCaCertificates(
    issuer.lastPreflight?.caCertificates || []
  );
  const chosenKey =
    !issuer.revalidationRequired && issuer.currentVersion > 0
      ? issuer.confirmedKeySha256
      : null;
  if (groups.length === 0) {
    return (
      <Text fontSize='sm' color={muted}>
        Preflight did not return a CA certificate to choose.
      </Text>
    );
  }
  return (
    <Stack spacing={3}>
      <Text fontSize='sm'>
        Choose the CA certificate that should sign new enrollments. A CA keeps
        older certificates after a renewal, so the newest is listed first.
        Choosing one pins that public key. A later renewal that uses a different
        key stops enrollments until you choose the new certificate.
      </Text>
      <Stack spacing={2}>
        {groups.map((group, index) => {
          const inUse = chosenKey === group.keySha256;
          const title =
            groups.length === 1
              ? 'CA certificate'
              : index === 0
                ? 'Newest CA certificate'
                : 'Earlier CA certificate';
          return (
            <Flex
              key={group.keySha256}
              direction={{ base: 'column', md: 'row' }}
              align={{ md: 'center' }}
              justify='space-between'
              gap={3}
              p={3}
              borderWidth='1px'
              borderColor={border}
              borderRadius='md'
            >
              <Box minW={0}>
                <HStack spacing={2} mb={1}>
                  <Text fontSize='sm' fontWeight='semibold'>
                    {title}
                  </Text>
                  {inUse ? (
                    <CertOpsBadge colorScheme='green'>In use</CertOpsBadge>
                  ) : null}
                </HStack>
                {group.certificates.map(cert => (
                  <Text
                    key={`${cert.thumbprintSha1 || ''}:${cert.notBefore || ''}:${cert.notAfter || ''}`}
                    fontSize='xs'
                    color={muted}
                  >
                    {validityLine(cert)}
                  </Text>
                ))}
                {group.thumbprintSha1 ? (
                  <Box mt={1}>
                    <CopyableId
                      id={group.thumbprintSha1}
                      label='Thumbprint'
                      display={`${group.thumbprintSha1.slice(0, 8)}…${group.thumbprintSha1.slice(-8)}`}
                      size='xs'
                    />
                  </Box>
                ) : null}
              </Box>
              {inUse ? null : (
                <DashboardActionButton
                  variant='outline'
                  flexShrink={0}
                  {...actionProps(
                    busyKey,
                    `confirm:${issuer.id}:${group.keySha256}`,
                    paused
                  )}
                  aria-label={`Use this certificate ${group.keySha256.slice(0, 12)} for ${issuer.name}`}
                  onClick={() =>
                    onConfirm(issuer.id, group.keySha256, issuer.lastPreflight)
                  }
                >
                  Use this certificate
                </DashboardActionButton>
              )}
            </Flex>
          );
        })}
      </Stack>
    </Stack>
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
  const pinned = pinnedPair(issuer);
  const [checkVersion, setCheckVersion] = useState(null);
  const [checkBaseline, setCheckBaseline] = useState(null);
  const checking =
    issuer.revalidationRequired || checkVersion === issuer.currentVersion;
  const safe = preflightIsSafe(issuer);
  const freshResult =
    checkBaseline != null &&
    preflightSignature(issuer.lastPreflight) !== checkBaseline;
  const showResult = issuer.revalidationRequired || freshResult;
  return (
    <Stack spacing={3}>
      <IssuerNotices issuer={issuer} />
      <Stack spacing={1}>
        <Text fontSize='sm' overflowWrap='anywhere'>
          {pinned.caConfig || 'CA not recorded'} /{' '}
          {pinned.template || 'template not recorded'}
        </Text>
        <Text fontSize='xs' color={muted}>
          The CA and template stay with this issuer. A different pair is a new
          issuer.
        </Text>
      </Stack>
      {issuer.lastPreflight ? (
        <Text fontSize='sm' color={muted} overflowWrap='anywhere'>
          Last check: template{' '}
          {checkSummary(issuer.lastPreflight.templateCheck)}, CA{' '}
          {checkSummary(issuer.lastPreflight.caCheck)}.
        </Text>
      ) : null}
      {checking ? (
        <form
          onSubmit={event => {
            setCheckBaseline(preflightSignature(issuer.lastPreflight));
            onPreflight(event, issuer.id);
          }}
        >
          <input type='hidden' name='caConfig' value={pinned.caConfig} />
          <input type='hidden' name='template' value={pinned.template} />
          <SimpleGrid columns={{ base: 1, md: 2 }} spacing={3}>
            <FormControl isRequired>
              <FormLabel {...fieldLabelProps}>
                Agent that reads the CA
              </FormLabel>
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
              <Text mt={1} fontSize='xs' color={muted}>
                Pick a Windows agent that can reach this CA and already allows
                this template. The choice is only for this read. It is not
                saved, and it does not decide who renews later.
              </Text>
            </FormControl>
            <Flex align='flex-end'>
              <DashboardActionButton
                type='submit'
                variant='outline'
                {...actionProps(busyKey, `preflight:${issuer.id}`, paused)}
                aria-label={`Run check for ${issuer.name}`}
              >
                Run check
              </DashboardActionButton>
            </Flex>
          </SimpleGrid>
        </form>
      ) : (
        <Box>
          <DashboardActionButton
            variant='outline'
            isDisabled={paused || !pinned.caConfig || !pinned.template}
            onClick={() => setCheckVersion(issuer.currentVersion)}
          >
            Check again
          </DashboardActionButton>
        </Box>
      )}
      {showResult && safe ? (
        <ConfirmKeys
          issuer={issuer}
          busyKey={busyKey}
          paused={paused}
          muted={muted}
          onConfirm={onConfirm}
        />
      ) : showResult && issuer.lastPreflight && !safe ? (
        <Text fontSize='sm' color={muted}>
          Both checks have to be safe before you can choose a CA certificate.
        </Text>
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
          {keyStatus(issuer) ? (
            <CertOpsBadge colorScheme={keyScheme(issuer)}>
              {keyStatus(issuer)}
            </CertOpsBadge>
          ) : null}
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
  onCancel,
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
        {enrollment.jobErrorMessage ? (
          <Text mt={1} fontSize='xs' color={muted}>
            Last attempt: {enrollment.jobErrorMessage}
          </Text>
        ) : null}
        <Box mt={2}>
          <EnrollmentNotices enrollment={enrollment} />
          {enrollment.state === 'requested' ||
          enrollment.state === 'prepared' ? (
            <Notice>
              The CA has not accepted this request, so the 14-day limit has not
              started. Cancel the enrollment to take it off this list.
            </Notice>
          ) : null}
        </Box>
      </Box>
      {enrollment.state === 'requested' || enrollment.state === 'prepared' ? (
        enrollment.jobStatus === 'claimed' ||
        enrollment.jobStatus === 'running' ? (
          <Text fontSize='xs' color={muted} maxW='280px'>
            An attempt is running. Wait for it to finish before cancelling.
          </Text>
        ) : (
          <DashboardActionButton
            variant='outline'
            {...actionProps(busyKey, `cancel:${enrollment.id}`, paused)}
            aria-label={`Cancel enrollment ${shortId(enrollment.id)}`}
            onClick={() => onCancel(enrollment.id)}
          >
            Cancel enrollment
          </DashboardActionButton>
        )
      ) : enrollment.state === 'submission_uncertain' ? (
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
  const [wizardOpen, setWizardOpen] = useState(false);
  const [busyKey, setBusyKey] = useState(null);
  const [waitingForPreflight, setWaitingForPreflight] = useState(null);
  const [preflightNote, setPreflightNote] = useState('');
  const [loadError, setLoadError] = useState('');
  const [issuerTotal, setIssuerTotal] = useState(0);
  const [enrollmentTotal, setEnrollmentTotal] = useState(0);
  const [loadingMore, setLoadingMore] = useState('');
  const [pendingAbandonId, setPendingAbandonId] = useState(null);
  const [showFinished, setShowFinished] = useState(false);
  // Not started and install-failed enrollments need an operator, so they start visible.
  const [showParked, setShowParked] = useState(true);
  const [showRejectedIssuers, setShowRejectedIssuers] = useState(false);
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
      listIssuers(workspaceId, {
        limit: PAGE_LIMIT,
        includeUnconfigured: true,
      }),
      listEnrollments(workspaceId, { limit: PAGE_LIMIT }),
      listAgents(workspaceId),
    ]);
    setIssuers(previous => refreshPage(issuerPage.items || [], previous));
    setEnrollments(previous =>
      refreshPage(enrollmentPage.items || [], previous)
    );
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

  const loadMoreIssuers = useCallback(async () => {
    setLoadingMore('issuers');
    try {
      const page = await listIssuers(workspaceId, {
        limit: PAGE_LIMIT,
        offset: issuers.length,
        includeUnconfigured: true,
      });
      setIssuers(previous => appendPage(previous, page.items || []));
      setIssuerTotal(Number(page.pagination?.total || 0));
    } catch (err) {
      showError(errorText(err, 'Could not load more issuers.'));
    } finally {
      setLoadingMore('');
    }
  }, [workspaceId, issuers.length]);

  const loadMoreEnrollments = useCallback(async () => {
    setLoadingMore('enrollments');
    try {
      const page = await listEnrollments(workspaceId, {
        limit: PAGE_LIMIT,
        offset: enrollments.length,
      });
      setEnrollments(previous => appendPage(previous, page.items || []));
      setEnrollmentTotal(Number(page.pagination?.total || 0));
    } catch (err) {
      showError(errorText(err, 'Could not load more enrollments.'));
    } finally {
      setLoadingMore('');
    }
  }, [workspaceId, enrollments.length]);

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
          setIssuers(previous => refreshPage(items, previous));
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

  async function handleCancel(enrollmentId) {
    setBusyKey(`cancel:${enrollmentId}`);
    try {
      await cancelEnrollment(workspaceId, enrollmentId);
      showSuccess('Enrollment cancelled. The CA was not contacted.');
      await reload();
    } catch (err) {
      showError(errorText(err, 'Could not cancel the enrollment.'));
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

  const finishedEnrollmentCount =
    enrollments.filter(enrollmentIsFinished).length;
  const parkedEnrollmentCount = enrollments.filter(enrollmentIsParked).length;
  const visibleEnrollments = enrollments.filter(enrollment => {
    if (enrollmentIsParked(enrollment)) return showParked;
    if (enrollmentIsFinished(enrollment)) return showFinished;
    return true;
  });

  return (
    <Stack spacing={4}>
      <DashboardPanel>
        <DashboardPanelHeader
          title='Issuers'
          description='Preflight checks a CA and template. It does not issue a certificate. Enrollment runs when an agent rule names that pair.'
          action={
            <HStack spacing={2}>
              <DashboardActionButton
                {...actionProps(busyKey, 'create', paused)}
                onClick={() => setWizardOpen(true)}
              >
                New issuer
              </DashboardActionButton>
              <DashboardActionButton
                variant='outline'
                {...actionProps(busyKey, 'refresh', false)}
                onClick={() =>
                  reload().catch(err =>
                    showError(
                      errorText(err, 'Could not refresh AD CS issuers.')
                    )
                  )
                }
              >
                Refresh
              </DashboardActionButton>
            </HStack>
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
        <AdcsIssuerWizard
          isOpen={wizardOpen}
          onClose={() => setWizardOpen(false)}
          workspaceId={workspaceId}
          agents={agents}
          paused={paused}
          onChanged={reload}
        />
        {(() => {
          const rejectedIssuers = issuers.filter(isUnsafeRejectedIssuer);
          const visibleIssuers = issuers.filter(
            item =>
              isConfiguredIssuer(item) ||
              (showRejectedIssuers && isUnsafeRejectedIssuer(item))
          );
          if (loading) {
            return (
              <DashboardState
                type='loading'
                title='Loading issuers and enrollments...'
                py={6}
              />
            );
          }
          return (
            <>
              {rejectedIssuers.length > 0 ? (
                <Checkbox
                  size='sm'
                  mb={3}
                  isChecked={showRejectedIssuers}
                  onChange={event =>
                    setShowRejectedIssuers(event.target.checked)
                  }
                >
                  {`Show ${rejectedIssuers.length} unsafe ${rejectedIssuers.length === 1 ? 'issuer' : 'issuers'}`}
                </Checkbox>
              ) : null}
              {visibleIssuers.length === 0 ? (
                <Text fontSize='sm' color={muted}>
                  No issuers yet.
                </Text>
              ) : (
                <VStack align='stretch' spacing={1}>
                  {visibleIssuers.map(issuer => (
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
            </>
          );
        })()}
        {issuerTotal > issuers.length ? (
          <HStack justify='space-between' mt={3}>
            <Text fontSize='sm' color={muted}>
              Showing {issuers.length} of {issuerTotal} issuers.
            </Text>
            <DashboardActionButton
              variant='outline'
              onClick={loadMoreIssuers}
              isDisabled={loadingMore !== ''}
            >
              {loadingMore === 'issuers' ? 'Loading...' : 'Load more issuers'}
            </DashboardActionButton>
          </HStack>
        ) : null}
      </DashboardPanel>

      {!loading ? (
        <DashboardPanel>
          <DashboardPanelHeader
            title='Enrollments'
            description='Pending approval waits for the CA. An uncertain submission needs the RequestId before it can be reconciled.'
            action={
              finishedEnrollmentCount > 0 || parkedEnrollmentCount > 0 ? (
                <HStack spacing={4}>
                  {parkedEnrollmentCount > 0 ? (
                    <Checkbox
                      isChecked={showParked}
                      onChange={event => setShowParked(event.target.checked)}
                      size='sm'
                    >
                      {`Show not started or install failed (${parkedEnrollmentCount})`}
                    </Checkbox>
                  ) : null}
                  {finishedEnrollmentCount > 0 ? (
                    <Checkbox
                      isChecked={showFinished}
                      onChange={event => setShowFinished(event.target.checked)}
                      size='sm'
                    >
                      Show finished ({finishedEnrollmentCount})
                    </Checkbox>
                  ) : null}
                </HStack>
              ) : null
            }
          />
          {enrollmentTotal > enrollments.length ? (
            <HStack justify='space-between' mb={3}>
              <Text fontSize='sm' color={muted}>
                Showing {enrollments.length} of {enrollmentTotal} enrollments.
              </Text>
              <DashboardActionButton
                variant='outline'
                onClick={loadMoreEnrollments}
                isDisabled={loadingMore !== ''}
              >
                {loadingMore === 'enrollments'
                  ? 'Loading...'
                  : 'Load more enrollments'}
              </DashboardActionButton>
            </HStack>
          ) : null}
          {loadError ? (
            <DashboardErrorAlert>{loadError}</DashboardErrorAlert>
          ) : visibleEnrollments.length === 0 ? (
            <DashboardState
              py={6}
              title={
                enrollments.length === 0
                  ? 'No enrollments yet'
                  : 'No enrollments in progress'
              }
              description={
                enrollments.length === 0
                  ? 'A renew job creates an enrollment when an agent rule names the CA and template.'
                  : parkedEnrollmentCount > 0 && finishedEnrollmentCount > 0
                    ? 'Finished enrollments, and ones that never started or failed to install, are hidden.'
                    : parkedEnrollmentCount > 0
                      ? 'Enrollments that never started or failed to install are hidden.'
                      : 'Finished enrollments are hidden. Show finished to see cancelled, failed, and completed requests.'
              }
            />
          ) : (
            <VStack align='stretch' spacing={1}>
              {visibleEnrollments.map(enrollment => (
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
                  onCancel={handleCancel}
                />
              ))}
            </VStack>
          )}
        </DashboardPanel>
      ) : null}
    </Stack>
  );
}
