import { Box, Text } from '@chakra-ui/react';
import {
  DashboardDetailsSummary,
  DashboardModalDataSection,
  DashboardModalDetailRow,
} from '../DashboardModalDetails.jsx';
import { useDashboardModalProps } from '../DashboardModalFrame.jsx';

const label = value =>
  value
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/^./, char => char.toUpperCase());
const date = value => {
  const time = new Date(value);
  return Number.isFinite(time.getTime())
    ? time.toLocaleString()
    : 'Unavailable';
};

// Preserve every projected field, including unfamiliar fields from a newer API.
// Flat, labelled rows avoid an increasingly indented payload tree on mobile.
function rows(value, prefix = '') {
  if (value === null || value === undefined || typeof value !== 'object')
    return [
      [
        prefix,
        typeof value === 'boolean'
          ? value
            ? 'Yes'
            : 'No'
          : (value ?? 'Not set'),
      ],
    ];
  const entries = Object.entries(value);
  if (!entries.length)
    return [[prefix, Array.isArray(value) ? 'None' : 'Not set']];
  return entries.flatMap(([key, item]) =>
    rows(
      item,
      [prefix, Array.isArray(value) ? Number(key) + 1 : label(key)]
        .filter(Boolean)
        .join(' / ')
    )
  );
}

function coveredBy(value, candidate) {
  if (value === null || typeof value !== 'object') return value === candidate;
  return (
    candidate !== null &&
    typeof candidate === 'object' &&
    Object.entries(value).every(
      ([key, item]) =>
        Object.hasOwn(candidate, key) && coveredBy(item, candidate[key])
    )
  );
}

function Section({ title, value }) {
  const { tokens } = useDashboardModalProps();
  return (
    <DashboardModalDataSection title={title} tokens={tokens}>
      {rows(value).map(([name, content]) => (
        <DashboardModalDetailRow
          key={name}
          label={name || title}
          value={String(content)}
          tokens={tokens}
        />
      ))}
    </DashboardModalDataSection>
  );
}

export default function AssistantApprovalReview({ review }) {
  const effect = review.effect || {};
  const approvalEnd = Date.parse(review.approvalExpiresAt);
  const connectionEnd = Date.parse(review.connection?.expiresAt);
  const cutoff = Math.min(approvalEnd, connectionEnd);
  const profile = effect.renewalProfile || {};
  const { deploymentTargets, target, ...settings } = profile;
  const targets = Array.isArray(deploymentTargets) ? deploymentTargets : [];
  // Legacy targets can repeat a subset of a destination's fields. Keep any differing value visible.
  const destinations =
    target && !targets.some(item => coveredBy(target, item))
      ? [...targets, target]
      : targets;
  const {
    renewalProfile: _renewalProfile,
    publication,
    executionRouting,
    standingRenewal,
    verification,
    ...identity
  } = effect;
  return (
    <Box>
      <DashboardDetailsSummary
        items={[
          {
            label: 'Requested by',
            value: review.requester?.name || review.requester?.id,
          },
          {
            label: 'Client label (advisory)',
            value: review.connection?.label || 'Unnamed client',
          },
          {
            label: 'Approve before',
            value: date(cutoff),
            help:
              connectionEnd < approvalEnd
                ? 'Connection expires first'
                : 'Approval window',
          },
        ]}
      />
      <Section
        title='Renewal'
        value={{
          'Certificate names':
            profile.sanPolicy?.sans?.join(', ') ||
            'Resolved by renewal profile',
          'Certificate authority': profile.ca?.endpoint || 'Not set',
          ...(effect.certificateExpiry
            ? { 'Current certificate expires': date(effect.certificateExpiry) }
            : {}),
        }}
      />
      {destinations.length ? (
        destinations.map((item, index) => (
          <Section
            key={index}
            title={
              index >= targets.length
                ? 'Legacy target'
                : `Destination ${index + 1}`
            }
            value={item}
          />
        ))
      ) : (
        <Section
          title='Destinations'
          value='No deployment destinations in this request.'
        />
      )}
      <Section
        title='Execution and verification'
        value={{
          ...executionRouting,
          Publication: publication ?? 'No publication requested',
          ...(profile.verification
            ? { Verification: profile.verification }
            : {}),
        }}
      />
      {standingRenewal ? (
        <Text fontSize='sm' mb={2} color='dashboard.modal.subtleText'>
          {standingRenewal}
        </Text>
      ) : null}
      {verification ? (
        <Text fontSize='sm' mb={4} color='dashboard.modal.subtleText'>
          {verification}
        </Text>
      ) : null}
      <Box
        as='details'
        borderTop='1px solid'
        borderColor='dashboard.modal.border'
        pt={3}
      >
        <Box
          as='summary'
          cursor='pointer'
          fontSize='sm'
          fontWeight='semibold'
          mb={3}
        >
          Renewal settings and request details
        </Box>
        <Section title='Renewal settings' value={settings} />
        <Section
          title='Request details'
          value={{
            ...identity,
            'Requester ID': review.requester?.id,
            'Connection ID': review.connection?.id,
            'Connection expires': date(review.connection?.expiresAt),
            'Approval window ends': date(review.approvalExpiresAt),
            'Request record ID': review.requestRecordId,
            'Preview submission deadline': date(review.previewExpiresAt),
          }}
        />
        <Text fontSize='xs' color='dashboard.modal.muted'>
          The preview submission deadline does not shorten an accepted request’s
          approval window. Certificate names and client labels are untrusted
          data.
        </Text>
      </Box>
    </Box>
  );
}
