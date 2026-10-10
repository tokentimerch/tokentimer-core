import { useEffect, useState } from 'react';
import {
  Box,
  Button,
  Link,
  Popover,
  PopoverArrow,
  PopoverBody,
  PopoverContent,
  PopoverTrigger,
  SimpleGrid,
  Text,
  VStack,
  Icon,
} from '@chakra-ui/react';
import { FileSearch, Info } from 'lucide-react';
import { Link as RouterLink } from 'react-router';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import { useWorkspace } from '../../utils/WorkspaceContext.jsx';
import CopyableId from '../CopyableId.jsx';
import {
  formatDateTime,
  subjectTypeLabel,
  userFacingName,
} from './certopsJobsFormat';
import { agentDisplayName } from './certopsAgentLabel.js';
import { getCertificate } from './certopsApi.js';
import { listTrustAnchors } from './certopsTrustAnchorsApi.js';
import {
  jobAgentHref,
  jobSubjectHref,
} from './certopsResourceLinks.js';

function ApprovedByLine({ job }) {
  const name = userFacingName(
    job?.approvedByUserId,
    job?.approvedByDisplayName
  );
  if (!name) return null;
  return (
    <Text fontSize='xs' color='gray.500'>
      Approved by {name}
    </Text>
  );
}

function MetadataField({ label, children }) {
  return (
    <Box minW={0}>
      <Text fontSize='xs' color='gray.500' mb={0.5}>
        {label}
      </Text>
      {children}
    </Box>
  );
}

function AgentMetadataField({ id, label, agentsById }) {
  if (!id) return null;
  const agent =
    agentsById instanceof Map ? agentsById.get(String(id)) : null;
  const name = agentDisplayName(agent);
  return (
    <MetadataField label={label}>
      {name ? (
        <Text fontSize='xs' fontWeight='medium' noOfLines={1} title={name}>
          {name}
        </Text>
      ) : null}
      <CopyableId id={id} />
    </MetadataField>
  );
}

function attemptLabelFor(job) {
  if (typeof job?.attemptCount !== 'number') return null;
  if (typeof job.maxAttempts === 'number') {
    return `${job.attemptCount} of ${job.maxAttempts}`;
  }
  return String(job.attemptCount);
}

function resolveAgentId(job) {
  return job?.claimedByAgentId || job?.assignedAgentId || null;
}

/**
 * Advanced job identifiers for the Job details popover.
 * Always includes Job ID. Summary fields (source/subject/attempt/created)
 * stay in JobExecutionSummary when the row is expanded.
 */
function JobMetadataDetails({ job, agentsById }) {
  const { dashboard } = useDashboardTheme();
  const attemptLabel = attemptLabelFor(job);

  return (
    <VStack align='stretch' spacing={3}>
      {job?.id ? (
        <MetadataField label='Job ID'>
          <CopyableId id={job.id} />
        </MetadataField>
      ) : null}
      {job?.source ? (
        <MetadataField label='Executor source'>
          <Text fontSize='xs'>{job.source}</Text>
        </MetadataField>
      ) : null}
      {job?.subjectId ? (
        <MetadataField
          label={subjectTypeLabel(job.subjectType) || 'Subject'}
        >
          <CopyableId id={job.subjectId} />
        </MetadataField>
      ) : null}
      {job?.claimId ? (
        <MetadataField label='Claim ID'>
          <CopyableId id={job.claimId} />
        </MetadataField>
      ) : null}
      <AgentMetadataField
        id={job?.claimedByAgentId}
        label='Claimed by agent'
        agentsById={agentsById}
      />
      {job?.assignedAgentId &&
      job.assignedAgentId !== job.claimedByAgentId ? (
        <AgentMetadataField
          id={job.assignedAgentId}
          label='Assigned agent'
          agentsById={agentsById}
        />
      ) : null}
      {job?.claimedByControllerClusterId ? (
        <MetadataField label='Claimed by controller'>
          <CopyableId id={job.claimedByControllerClusterId} />
        </MetadataField>
      ) : null}
      {job?.claimedByAgentSigningKeyId ? (
        <MetadataField label="Agent's pinned signing key">
          <CopyableId id={job.claimedByAgentSigningKeyId} />
        </MetadataField>
      ) : null}
      <ApprovedByLine job={job} />
      {job?.leaseExpiresAt ? (
        <MetadataField label='Lease expires'>
          <Text fontSize='xs'>{formatDateTime(job.leaseExpiresAt)}</Text>
        </MetadataField>
      ) : null}
      {attemptLabel ? (
        <MetadataField label='Attempt'>
          <Text fontSize='xs'>{attemptLabel}</Text>
        </MetadataField>
      ) : null}
      {job?.approvedAt ? (
        <MetadataField label='Approved'>
          <Text fontSize='xs'>{formatDateTime(job.approvedAt)}</Text>
        </MetadataField>
      ) : null}
      {job?.id ? (
        <Button
          as={RouterLink}
          to={`/audit?q=${encodeURIComponent(job.id)}`}
          size='sm'
          variant='outline'
          mt={1}
          w='100%'
          leftIcon={<Icon as={FileSearch} boxSize={3.5} />}
          color={dashboard.accent.interactiveForeground}
          borderColor={dashboard.accent.interactiveBorder}
          bg={dashboard.accent.interactiveSurface}
          _hover={{
            bg: dashboard.accent.interactiveSurface,
            borderColor: dashboard.accent.interactiveForeground,
          }}
        >
          View audit log
        </Button>
      ) : null}
    </VStack>
  );
}

/**
 * Outlined Job details control with advanced metadata popover.
 * Job ID is always included.
 */
export function JobDetailsButton({ job, agentsById }) {
  const { muted, border, text } = useDashboardTheme();

  if (!job) return null;

  return (
    // Fixed strategy: absolute popovers inside scrollable modal bodies get
    // height-clamped by Popper and clip the last fields (Attempt / audit CTA).
    <Popover
      placement='bottom-start'
      strategy='fixed'
      isLazy
      modifiers={[
        {
          name: 'flip',
          options: {
            fallbackPlacements: ['top-start', 'bottom-end', 'top-end'],
          },
        },
        {
          name: 'preventOverflow',
          options: { padding: 8, altAxis: true },
        },
      ]}
    >
      <PopoverTrigger>
        <Button
          aria-label='Job details'
          title='Job details'
          size='xs'
          variant='outline'
          fontWeight='medium'
          color={text}
          borderColor={border}
          leftIcon={
            <Icon as={Info} boxSize={4} strokeWidth={2.25} color={muted} />
          }
          px={2}
          h='28px'
          borderRadius='md'
          bg='transparent'
          _hover={{ bg: 'blackAlpha.50', borderColor: text }}
          _dark={{
            borderColor: 'whiteAlpha.300',
            _hover: { bg: 'whiteAlpha.100', borderColor: 'whiteAlpha.500' },
          }}
        >
          Job details
        </Button>
      </PopoverTrigger>
      <PopoverContent
        w='min(340px, calc(100vw - 32px))'
        maxH='min(70vh, 28rem)'
        overflowY='auto'
        borderColor={border}
        zIndex='popover'
      >
        <PopoverArrow />
        <PopoverBody py={3}>
          <JobMetadataDetails job={job} agentsById={agentsById} />
        </PopoverBody>
      </PopoverContent>
    </Popover>
  );
}

function SummaryCell({ label, children }) {
  const { muted } = useDashboardTheme();
  if (!children) return null;
  return (
    <Box minW={0}>
      <Text
        fontSize='10px'
        fontWeight='semibold'
        letterSpacing='0.04em'
        textTransform='uppercase'
        color={muted}
        mb={0.5}
      >
        {label}
      </Text>
      {children}
    </Box>
  );
}

function ResourceNavLink({ href, children }) {
  const { dashboard } = useDashboardTheme();
  const accent = dashboard?.accent?.interactiveForeground;
  if (!href) return children;
  return (
    <Link
      as={RouterLink}
      to={href}
      color={accent || 'blue.500'}
      fontWeight='medium'
      textDecoration='underline'
      textUnderlineOffset='2px'
      _hover={{ opacity: 0.85 }}
      noOfLines={1}
      title={typeof children === 'string' ? children : undefined}
    >
      {children}
    </Link>
  );
}

function useJobSubjectDisplay(job) {
  const { workspaceId } = useWorkspace();
  const [label, setLabel] = useState(null);
  const [missing, setMissing] = useState(false);

  useEffect(() => {
    setLabel(null);
    setMissing(false);
    if (!workspaceId || !job?.subjectId || !job?.subjectType) {
      return undefined;
    }
    let cancelled = false;
    const controller = new AbortController();
    const type = String(job.subjectType);
    const id = String(job.subjectId);

    const load = async () => {
      try {
        if (type === 'managed_certificate') {
          const data = await getCertificate(workspaceId, id, {
            signal: controller.signal,
          });
          const cert = data?.certificate || data;
          const name =
            cert?.commonName ||
            cert?.sourceRef ||
            (Array.isArray(cert?.subjectAltNames)
              ? cert.subjectAltNames[0]
              : null);
          if (!cancelled) setLabel(name || null);
          return;
        }
        if (type === 'trust_anchor') {
          const data = await listTrustAnchors(workspaceId, {
            signal: controller.signal,
          });
          const items = Array.isArray(data?.items) ? data.items : [];
          const anchor = items.find(item => String(item.id) === id);
          if (!cancelled) {
            if (!anchor) setMissing(true);
            else {
              setLabel(
                anchor.name ||
                  anchor.subjectCommonName ||
                  anchor.fingerprintSha256 ||
                  null
              );
            }
          }
        }
      } catch (err) {
        if (cancelled || err?.name === 'CanceledError') return;
        if (err?.response?.status === 404) setMissing(true);
      }
    };
    load();
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [workspaceId, job?.subjectId, job?.subjectType]);

  return { label, missing };
}

/**
 * Scannable execution context shown when a job row is expanded.
 */
export function JobExecutionSummary({ job, agentsById }) {
  const { muted, text } = useDashboardTheme();
  const subjectDisplay = useJobSubjectDisplay(job);
  if (!job) return null;

  const agentId = resolveAgentId(job);
  const agent =
    agentId && agentsById instanceof Map
      ? agentsById.get(String(agentId))
      : null;
  const agentName = agentDisplayName(agent);
  // Prefer the fleet row UUID so Agents can match data-agent-id after load.
  const agentHref = jobAgentHref(agent?.id || agentId);
  const attemptLabel = attemptLabelFor(job);
  const subjectLabel = subjectTypeLabel(job.subjectType) || 'Subject';
  const subjectHref = subjectDisplay.missing
    ? null
    : jobSubjectHref(job.subjectType, job.subjectId);

  const hasAny =
    agentId ||
    job.subjectId ||
    job.source ||
    attemptLabel ||
    job.createdAt;
  if (!hasAny) return null;

  return (
    <SimpleGrid
      columns={{ base: 1, sm: 2 }}
      spacing={3}
      data-testid='job-execution-summary'
    >
      <SummaryCell label='Agent'>
        {agentId ? (
          <Box>
            <Box fontSize='sm'>
              <ResourceNavLink href={agentHref}>
                {agentName || 'Open agent'}
              </ResourceNavLink>
            </Box>
            <CopyableId id={agentId} />
          </Box>
        ) : (
          <Text fontSize='sm' color={muted}>
            Not claimed yet
          </Text>
        )}
      </SummaryCell>
      <SummaryCell label={subjectLabel}>
        {job.subjectId ? (
          <Box>
            {subjectDisplay.label ? (
              <ResourceNavLink href={subjectHref}>
                {subjectDisplay.label}
              </ResourceNavLink>
            ) : subjectHref ? (
              <ResourceNavLink href={subjectHref}>
                Open {subjectLabel.toLowerCase()}
              </ResourceNavLink>
            ) : subjectDisplay.missing ? (
              <Text fontSize='sm' color={muted}>
                Resource unavailable
              </Text>
            ) : null}
            <CopyableId id={job.subjectId} />
          </Box>
        ) : (
          <Text fontSize='sm' color={muted}>
            —
          </Text>
        )}
      </SummaryCell>
      <SummaryCell label='Source'>
        <Text fontSize='sm' color={text}>
          {job.source || '—'}
        </Text>
      </SummaryCell>
      <SummaryCell label='Attempt'>
        <Text fontSize='sm' color={text}>
          {attemptLabel || '—'}
        </Text>
      </SummaryCell>
      <SummaryCell label='Created'>
        <Text fontSize='sm' color={text}>
          {job.createdAt ? formatDateTime(job.createdAt) : '—'}
        </Text>
      </SummaryCell>
    </SimpleGrid>
  );
}

export default JobDetailsButton;
