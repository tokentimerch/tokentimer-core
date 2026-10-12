import { useCallback, useEffect, useRef, useState } from 'react';
import { Input, Select, Stack, Text } from '@chakra-ui/react';
import { useOutletContext } from 'react-router';
import { listAgents } from '../../components/certops/certopsAgentsApi';
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
  DashboardPanel,
  DashboardPanelHeader,
  DashboardState,
} from '../../components/DashboardPrimitives';
import { useDashboardThemeColors } from '../../hooks/useDashboardTheme';
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

function IssuerNotices({ issuer }) {
  if (!issuer?.revalidationRequired) return null;
  return (
    <Text fontSize='sm'>
      The CA key changed. Run preflight again and confirm the new key before
      creating enrollments.
    </Text>
  );
}

function checkSummary(check) {
  const verdict = check?.verdict || 'unknown';
  const reasons = Array.isArray(check?.reasons)
    ? check.reasons.filter(Boolean)
    : [];
  if (verdict === 'safe' || reasons.length === 0) return verdict;
  return `${verdict} (${reasons.join(', ')})`;
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
    <Stack spacing={1}>
      {notes.map(note => (
        <Text key={note} fontSize='sm'>
          {note}
        </Text>
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

function ConfirmKeys({ issuer, busyKey, paused, onConfirm }) {
  const certs = issuer.lastPreflight?.caCertificates || [];
  const alreadyPinned =
    !issuer.revalidationRequired && issuer.currentVersion > 0;
  const pending = certs.filter(
    cert => !alreadyPinned || cert.keySha256 !== issuer.confirmedKeySha256
  );
  if (pending.length === 0) {
    return (
      <Text fontSize='sm' mt={3}>
        This CA key is already confirmed on version {issuer.currentVersion}.
      </Text>
    );
  }
  return (
    <Stack spacing={2} mt={3}>
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
    </Stack>
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
  const { muted } = useDashboardThemeColors();
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
  const pollRef = useRef(null);

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
          if (err?.code === 'ERR_CANCELED' || err?.name === 'CanceledError')
            return;
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
        'Issuer created. AD CS enrollment stays disabled until the release gate passes.'
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
          description='Creating an AD CS issuer does not enable enrollment. The agent still refuses adcs until the release gate passes. Preflight is read-only and only runs when the agent allowlists that CA and template.'
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
        <form onSubmit={handleCreate}>
          <Stack spacing={2} maxW='md'>
            <Select
              value={kind}
              onChange={event => setKind(event.target.value)}
              aria-label='Issuer kind'
            >
              <option value='adcs'>AD CS</option>
              <option value='acme'>ACME</option>
            </Select>
            <Input
              value={name}
              onChange={event => setName(event.target.value)}
              placeholder='Issuer name'
              aria-label='Issuer name'
              maxLength={128}
              required
            />
            <DashboardActionButton
              type='submit'
              {...actionProps(busyKey, 'create', paused)}
              alignSelf='flex-start'
            >
              Create issuer
            </DashboardActionButton>
          </Stack>
        </form>
      </DashboardPanel>

      {loading ? (
        <DashboardState
          type='loading'
          title='Loading issuers and enrollments...'
        />
      ) : (
        <>
          {issuers.map(issuer => (
            <DashboardPanel key={issuer.id}>
              <DashboardPanelHeader
                title={issuer.name}
                description={`${issuer.kind} · version ${issuer.currentVersion || 0}`}
              />
              <IssuerNotices issuer={issuer} />
              {issuer.lastPreflight ? (
                <Text fontSize='sm' color={muted} overflowWrap='anywhere'>
                  Preflight {issuer.lastPreflight.caConfig} /{' '}
                  {issuer.lastPreflight.template}: template{' '}
                  {checkSummary(issuer.lastPreflight.templateCheck)}, CA{' '}
                  {checkSummary(issuer.lastPreflight.caCheck)}.
                </Text>
              ) : null}
              {issuer.kind === 'adcs' ? (
                <form onSubmit={event => handlePreflight(event, issuer.id)}>
                  <Stack spacing={2} maxW='lg' mt={3}>
                    <Select
                      name='agentId'
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
                    <Input
                      name='caConfig'
                      aria-label={`CA config for ${issuer.name}`}
                      placeholder={'host\\CA Name'}
                      required
                      isDisabled={paused}
                    />
                    <Input
                      name='template'
                      aria-label={`Template for ${issuer.name}`}
                      placeholder='Template common name'
                      required
                      isDisabled={paused}
                    />
                    <DashboardActionButton
                      type='submit'
                      variant='outline'
                      {...actionProps(
                        busyKey,
                        `preflight:${issuer.id}`,
                        paused
                      )}
                      aria-label={`Run preflight for ${issuer.name}`}
                      alignSelf='flex-start'
                    >
                      Run preflight
                    </DashboardActionButton>
                  </Stack>
                </form>
              ) : (
                <Text fontSize='sm' mt={3}>
                  This issuer uses ACME. Preflight on this page is only for AD
                  CS.
                </Text>
              )}
              {issuer.kind === 'adcs' &&
              issuer.lastPreflight?.templateCheck?.verdict === 'safe' &&
              issuer.lastPreflight?.caCheck?.verdict === 'safe' ? (
                <ConfirmKeys
                  issuer={issuer}
                  busyKey={busyKey}
                  paused={paused}
                  onConfirm={handleConfirm}
                />
              ) : null}
            </DashboardPanel>
          ))}

          {issuerTotal > issuers.length ? (
            <Text fontSize='sm' color={muted}>
              Showing {issuers.length} of {issuerTotal} issuers.
            </Text>
          ) : null}

          <DashboardPanel>
            <DashboardPanelHeader
              title='Enrollments'
              description='Awaiting CA approval stays pending until a continuation retrieves the certificate. An uncertain submission needs the RequestId from the CA.'
            />
            {enrollmentTotal > enrollments.length ? (
              <Text fontSize='sm' color={muted} mb={3}>
                Showing {enrollments.length} of {enrollmentTotal} enrollments.
              </Text>
            ) : null}
            {loadError ? (
              <Text fontSize='sm' color={muted}>
                {loadError}
              </Text>
            ) : enrollments.length === 0 ? (
              <Text fontSize='sm' color={muted}>
                No enrollments yet. This page does not start one. AD CS
                enrollment stays off until the release gate passes.
              </Text>
            ) : (
              <Stack spacing={4}>
                {enrollments.map(enrollment => (
                  <Stack key={enrollment.id} spacing={2} align='flex-start'>
                    <Text fontWeight='medium' overflowWrap='anywhere'>
                      {enrollmentStateLabel(enrollment.state)} ·{' '}
                      {shortId(enrollment.id)} · {enrollment.caConfig} /{' '}
                      {enrollment.template}
                    </Text>
                    <Text fontSize='sm' color={muted} overflowWrap='anywhere'>
                      {requestIdLine(enrollment)}
                      {enrollment.caKeySha256
                        ? ` · key prefix ${enrollment.caKeySha256.slice(0, 12)}`
                        : ''}
                    </Text>
                    <EnrollmentNotices enrollment={enrollment} />
                    {enrollment.state === 'submission_uncertain' ? (
                      <form
                        onSubmit={event =>
                          handleReconcile(event, enrollment.id)
                        }
                      >
                        <Stack
                          direction={{ base: 'column', sm: 'row' }}
                          spacing={2}
                        >
                          <Input
                            name='requestId'
                            aria-label={`RequestId for ${shortId(enrollment.id)}`}
                            placeholder='RequestId'
                            inputMode='numeric'
                            min={1}
                            max={4294967295}
                            required
                          />
                          <DashboardActionButton
                            type='submit'
                            {...actionProps(
                              busyKey,
                              `reconcile:${enrollment.id}`,
                              paused
                            )}
                            aria-label={`Reconcile ${shortId(enrollment.id)}`}
                          >
                            Reconcile
                          </DashboardActionButton>
                        </Stack>
                      </form>
                    ) : null}
                    {enrollment.state === 'submission_uncertain' ? (
                      pendingAbandonId === enrollment.id ? (
                        <Stack direction='row' spacing={2}>
                          <DashboardActionButton
                            {...actionProps(
                              busyKey,
                              `abandon:${enrollment.id}`,
                              paused
                            )}
                            aria-label={`Confirm abandon ${shortId(enrollment.id)}`}
                            onClick={() => handleAbandon(enrollment.id)}
                          >
                            Free the key
                          </DashboardActionButton>
                          <DashboardActionButton
                            variant='outline'
                            isDisabled={Boolean(busyKey)}
                            onClick={() => setPendingAbandonId(null)}
                          >
                            Keep
                          </DashboardActionButton>
                        </Stack>
                      ) : (
                        <DashboardActionButton
                          variant='outline'
                          {...actionProps(
                            busyKey,
                            `abandon:${enrollment.id}`,
                            paused
                          )}
                          aria-label={`Abandon ${shortId(enrollment.id)}`}
                          onClick={() => setPendingAbandonId(enrollment.id)}
                        >
                          Abandon
                        </DashboardActionButton>
                      )
                    ) : null}
                  </Stack>
                ))}
              </Stack>
            )}
          </DashboardPanel>
        </>
      )}
    </Stack>
  );
}
