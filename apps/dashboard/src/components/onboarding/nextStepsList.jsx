import { Box, Flex, HStack, Icon, Text, VStack } from '@chakra-ui/react';
import { Link as RouterLink } from 'react-router';
import {
  FiBell,
  FiCheckCircle,
  FiCompass,
  FiGlobe,
  FiLayers,
  FiMail,
  FiMonitor,
  FiRefreshCw,
  FiServer,
  FiSliders,
  FiUploadCloud,
} from 'react-icons/fi';
import { DashboardActionButton } from '../DashboardPrimitives';
import {
  useDashboardTheme,
  useDashboardThemeColors,
} from '../../hooks/useDashboardTheme';
import { DocsLink } from '../LearnMorePanel';
import { StatusTag } from './panels.jsx';

// The suggestions stay plain sentences in the data, so editions can add their
// own. This layer only decorates the ones it knows by their opening words; any
// other sentence gets a neutral icon and its own text, with no action.
const KNOWN = [
  {
    starts: 'Import many assets at once',
    title: 'Import assets in bulk',
    icon: FiUploadCloud,
    action: { to: '/dashboard', label: 'Open inventory' },
  },
  {
    starts: 'Adjust alert thresholds',
    title: 'Tune alert thresholds',
    icon: FiSliders,
    action: { to: '/workspace-preferences', label: 'Workspace preferences' },
  },
  {
    starts: 'Set up an endpoint monitor',
    title: 'Monitor the sites you depend on',
    icon: FiMonitor,
    action: { to: '/dashboard', label: 'Open inventory' },
  },
  {
    starts: 'Group assets into sections',
    title: 'Organize your inventory',
    icon: FiLayers,
    action: { to: '/dashboard', label: 'Open inventory' },
  },
  {
    starts: 'Add or import assets',
    title: 'Give alerts something to watch',
    icon: FiUploadCloud,
    action: { to: '/dashboard', label: 'Open inventory' },
  },
  {
    starts: 'Add Slack, Teams or WhatsApp',
    title: 'Add more alert channels',
    icon: FiBell,
    action: { to: '/workspace-preferences', label: 'Workspace preferences' },
  },
  {
    starts: 'Set up automatic renewal',
    title: 'Automate a renewal',
    icon: FiRefreshCw,
    action: { to: '/certops/certificates', label: 'Open Certificates' },
  },
  {
    starts: 'Install agents on more servers',
    title: 'Cover more servers',
    icon: FiServer,
    action: { to: '/certops/agents', label: 'Open Agents' },
  },
  {
    starts: 'Add a real DNS provider',
    title: 'Switch to a real domain and the production CA',
    icon: FiGlobe,
    action: { doc: 'certops.dns', label: 'DNS providers' },
  },
  {
    starts: 'Issue your first certificate',
    title: 'Issue your first certificate',
    icon: FiCompass,
  },
  {
    starts: 'Check renewals in the Certificates page',
    title: 'Check the issued certificate',
    icon: FiCheckCircle,
    action: { to: '/certops/certificates', label: 'Open Certificates' },
  },
  {
    starts: 'Set up renewal-failure alerts',
    title: 'Get told when a renewal fails',
    icon: FiBell,
    action: { to: '/workspace-preferences', label: 'Workspace preferences' },
  },
  {
    starts: 'Attach the profile to your certificate',
    title: 'Attach the profile and watch the first enrollment',
    icon: FiCheckCircle,
    action: { to: '/certops/renewals', label: 'Open Renewals' },
  },
  {
    starts: 'Your setup is only proven',
    title: 'Confirm the first enrollment',
    icon: FiCheckCircle,
  },
  {
    starts: 'Assign more consumers',
    title: 'Roll the certificate out to more hosts',
    icon: FiServer,
    action: { to: '/certops/renewals', label: 'Open Renewals' },
  },
  {
    starts: 'Run a verified rollout',
    title: 'Run a verified rollout',
    icon: FiServer,
    action: { doc: 'certops.vault', label: 'Vault distribution' },
  },
  {
    starts: 'Email delivery is not confirmed',
    title: 'Confirm email delivery',
    icon: FiMail,
    tone: 'warning',
  },
];

// "Title. Detail." or "Title: detail" gives a title; otherwise there is none.
function deriveTitle(text) {
  const match = /^(.{8,90}?)(?:\. |: )(.+)$/.exec(text);
  return match ? { title: match[1], detail: match[2] } : null;
}

/**
 * Maps one suggestion sentence to { title, description, icon, action, tone }.
 * Unknown sentences fall back to their own text and no action.
 */
export function describeNextStep(text) {
  const known = KNOWN.find(entry => text.startsWith(entry.starts));
  if (known) {
    return {
      title: known.title,
      description: text,
      icon: known.icon,
      action: known.action || null,
      tone: known.tone || 'info',
    };
  }
  const derived = deriveTitle(text);
  return {
    title: derived ? derived.title : '',
    description: derived ? derived.detail : text,
    icon: FiCompass,
    action: null,
    tone: 'info',
  };
}

function Action({ action, docs }) {
  if (!action) return null;
  if (action.doc) {
    const link = (docs?.(action.doc, action.label) || [])[0];
    return link ? <DocsLink href={link.url}>{link.label}</DocsLink> : null;
  }
  return (
    <DashboardActionButton
      as={RouterLink}
      to={action.to}
      size='sm'
      variant='outline'
      flexShrink={0}
    >
      {action.label}
    </DashboardActionButton>
  );
}

/**
 * The closing card's optional follow-ups as a short list of cards.
 * @param {{ items: string[], docs?: (key: string, label: string) => Array }} props
 */
export default function NextStepsList({ items, docs }) {
  const { muted, border } = useDashboardTheme();
  const { dashboard } = useDashboardThemeColors();
  const rows = (items || []).filter(Boolean);
  if (rows.length === 0) return null;
  return (
    <VStack
      align='stretch'
      spacing={3}
      as='section'
      aria-labelledby='next-steps'
    >
      <HStack spacing={2} align='center'>
        <Text as='h3' id='next-steps' fontSize='sm' fontWeight='bold'>
          Suggested next steps
        </Text>
        <StatusTag tone='gray'>All optional</StatusTag>
      </HStack>
      <Box
        as='ul'
        listStyleType='none'
        m={0}
        p={0}
        display='flex'
        flexDirection='column'
        gap={2}
        data-testid='next-steps'
      >
        {rows.map(text => {
          const step = describeNextStep(text);
          return (
            <Flex
              as='li'
              key={text}
              gap={3}
              align='flex-start'
              borderWidth='1px'
              borderColor={
                step.tone === 'warning' ? dashboard.state.warning : border
              }
              borderRadius='md'
              p={3}
              direction={{ base: 'column', sm: 'row' }}
              data-tone={step.tone}
            >
              <Flex gap={3} align='flex-start' flex='1' minW={0}>
                <Flex
                  aria-hidden
                  flexShrink={0}
                  w='28px'
                  h='28px'
                  borderRadius='full'
                  borderWidth='1px'
                  borderColor={border}
                  align='center'
                  justify='center'
                >
                  <Icon as={step.icon} boxSize={3.5} />
                </Flex>
                <Box minW={0}>
                  {step.title ? (
                    <Text fontSize='sm' fontWeight='semibold'>
                      {step.title}
                    </Text>
                  ) : null}
                  <Text
                    fontSize='sm'
                    color={step.title ? muted : 'inherit'}
                    overflowWrap='anywhere'
                  >
                    {step.description}
                  </Text>
                </Box>
              </Flex>
              <Action action={step.action} docs={docs} />
            </Flex>
          );
        })}
      </Box>
    </VStack>
  );
}
