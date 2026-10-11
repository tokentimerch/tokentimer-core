import { useCallback, useEffect, useState } from 'react';
import { Input, Select, Stack, Text } from '@chakra-ui/react';
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
import { useCertOpsIsWorkspaceAdmin } from '../../components/certops/useCertOps.js';
import {
  DashboardActionButton,
  DashboardPanel,
  DashboardPanelHeader,
  DashboardState,
} from '../../components/DashboardPrimitives';
import { useDashboardThemeColors } from '../../hooks/useDashboardTheme';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import { showError, showSuccess } from '../../utils/toast.js';

function errorText(err, fallback) {
  return err?.response?.data?.error || fallback;
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
      `This enrollment is frozen at issuer version ${enrollment.issuerVersion}. The issuer is now version ${enrollment.issuerCurrentVersion}. Cancel and re-enroll to pick up the new version.`
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

export default function CertOpsAdcs() {
  const isAdmin = useCertOpsIsWorkspaceAdmin();
  const { workspaceId } = useWorkspace();
  const { muted } = useDashboardThemeColors();
  const [issuers, setIssuers] = useState([]);
  const [enrollments, setEnrollments] = useState([]);
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState('');
  const [kind, setKind] = useState('adcs');
  const [busy, setBusy] = useState(false);

  const reload = useCallback(async () => {
    if (!workspaceId || !isAdmin) return;
    const [issuerPage, enrollmentPage, agentPage] = await Promise.all([
      listIssuers(workspaceId),
      listEnrollments(workspaceId),
      listAgents(workspaceId),
    ]);
    setIssuers(issuerPage.items || []);
    setEnrollments(enrollmentPage.items || []);
    setAgents(agentPage.items || []);
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
        if (!cancelled)
          showError(errorText(err, 'Could not load AD CS issuers.'));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [isAdmin, reload]);

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
    setBusy(true);
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
      setBusy(false);
    }
  }

  async function handlePreflight(event, issuerId) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    setBusy(true);
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
    } catch (err) {
      showError(errorText(err, 'Could not dispatch preflight.'));
    } finally {
      setBusy(false);
    }
  }

  async function handleConfirm(issuerId, keySha256, preflight) {
    setBusy(true);
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
      setBusy(false);
    }
  }

  async function handleReconcile(event, enrollmentId) {
    event.preventDefault();
    const requestId = Number(
      new FormData(event.currentTarget).get('requestId')
    );
    setBusy(true);
    try {
      await proposeEnrollmentRequestId(workspaceId, enrollmentId, requestId);
      showSuccess(
        'RequestId recorded. A reconciliation continuation is scheduled.'
      );
      await reload();
    } catch (err) {
      showError(errorText(err, 'Could not record the RequestId.'));
    } finally {
      setBusy(false);
    }
  }

  async function handleAbandon(enrollmentId) {
    setBusy(true);
    try {
      await abandonEnrollment(workspaceId, enrollmentId);
      showSuccess('Enrollment abandoned. A final continuation frees the key.');
      await reload();
    } catch (err) {
      showError(errorText(err, 'Could not abandon the enrollment.'));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Stack spacing={4}>
      <DashboardPanel>
        <DashboardPanelHeader
          title='Issuers'
          description='Creating an AD CS issuer does not enable enrollment. The agent still refuses adcs until the release gate passes. Preflight is read-only and only runs when the agent allowlists that CA and template.'
        />
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
              isLoading={busy}
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
                <Text fontSize='sm' color={muted}>
                  Preflight {issuer.lastPreflight.caConfig} /{' '}
                  {issuer.lastPreflight.template}: template{' '}
                  {issuer.lastPreflight.templateCheck?.verdict || 'unknown'}, CA{' '}
                  {issuer.lastPreflight.caCheck?.verdict || 'unknown'}.
                </Text>
              ) : null}
              <form onSubmit={event => handlePreflight(event, issuer.id)}>
                <Stack spacing={2} maxW='lg' mt={3}>
                  <Select
                    name='agentId'
                    aria-label={`Agent for ${issuer.name}`}
                    required
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
                    aria-label='CA config'
                    placeholder='host\CA Name'
                    required
                  />
                  <Input
                    name='template'
                    aria-label='Template'
                    placeholder='Template common name'
                    required
                  />
                  <DashboardActionButton
                    type='submit'
                    variant='outline'
                    isLoading={busy}
                    alignSelf='flex-start'
                  >
                    Run preflight
                  </DashboardActionButton>
                </Stack>
              </form>
              {issuer.lastPreflight?.templateCheck?.verdict === 'safe' &&
              issuer.lastPreflight?.caCheck?.verdict === 'safe' ? (
                <Stack spacing={2} mt={3}>
                  {(issuer.lastPreflight.caCertificates || []).map(cert => (
                    <DashboardActionButton
                      key={cert.keySha256}
                      variant='outline'
                      isLoading={busy}
                      onClick={() =>
                        handleConfirm(
                          issuer.id,
                          cert.keySha256,
                          issuer.lastPreflight
                        )
                      }
                    >
                      Confirm key {cert.keySha256?.slice(0, 12)}
                    </DashboardActionButton>
                  ))}
                </Stack>
              ) : null}
            </DashboardPanel>
          ))}

          <DashboardPanel>
            <DashboardPanelHeader
              title='Enrollments'
              description='Awaiting CA approval stays pending until a continuation retrieves the certificate. An uncertain submission needs the RequestId from the CA.'
            />
            {enrollments.length === 0 ? (
              <Text fontSize='sm' color={muted}>
                No enrollments yet.
              </Text>
            ) : (
              <Stack spacing={4}>
                {enrollments.map(enrollment => (
                  <Stack key={enrollment.id} spacing={2} align='flex-start'>
                    <Text fontWeight='medium'>
                      {enrollmentStateLabel(enrollment.state)} ·{' '}
                      {enrollment.caConfig} / {enrollment.template}
                    </Text>
                    <Text fontSize='sm' color={muted}>
                      RequestId {enrollment.requestId || 'none'}
                      {enrollment.operatorRequestId
                        ? ` · operator ${enrollment.operatorRequestId}`
                        : ''}
                      {enrollment.caKeySha256
                        ? ` · key ${enrollment.caKeySha256.slice(0, 12)}`
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
                            aria-label='RequestId'
                            placeholder='RequestId'
                            inputMode='numeric'
                            required
                          />
                          <DashboardActionButton type='submit' isLoading={busy}>
                            Reconcile
                          </DashboardActionButton>
                        </Stack>
                      </form>
                    ) : null}
                    {enrollment.state !== 'abandoned' &&
                    enrollment.state !== 'installed' ? (
                      <DashboardActionButton
                        variant='outline'
                        isLoading={busy}
                        onClick={() => handleAbandon(enrollment.id)}
                      >
                        Abandon
                      </DashboardActionButton>
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
