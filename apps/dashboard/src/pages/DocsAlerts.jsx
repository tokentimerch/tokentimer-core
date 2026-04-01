import {
  Box,
  Heading,
  Text,
  VStack,
  List,
  ListItem,
  Link as ChakraLink,
  useColorModeValue,
  Grid,
  GridItem,
  Button,
  Flex,
  Image,
  Divider,
} from '@chakra-ui/react';
import { FiArrowLeft } from 'react-icons/fi';
import { useNavigate } from 'react-router-dom';
import { AccessibleButton } from '../components/Accessibility';

import SEO from '../components/SEO.jsx';

function TemplateExampleCard({
  title,
  templateBody,
  sampleValues,
  borderColor,
  codeBlockBg,
  bodyColor,
}) {
  return (
    <Box
      border='1px solid'
      borderColor={borderColor}
      borderRadius='md'
      p={4}
      mb={4}
    >
      <Heading as='h4' size='xs' mb={2}>
        {title}
      </Heading>
      <Text fontSize='sm' color={bodyColor} mb={1}>
        Template body
      </Text>
      <Box
        as='pre'
        whiteSpace='pre-wrap'
        fontFamily='mono'
        fontSize='xs'
        p={3}
        borderRadius='md'
        border='1px solid'
        borderColor={borderColor}
        bg={codeBlockBg}
        color={bodyColor}
      >
        {templateBody}
      </Box>
      <Divider my={3} borderColor={borderColor} />
      <Text fontSize='sm' color={bodyColor} mb={1}>
        Example sample values
      </Text>
      {sampleValues ? (
        <Box
          as='pre'
          whiteSpace='pre-wrap'
          fontFamily='mono'
          fontSize='xs'
          p={3}
          borderRadius='md'
          border='1px solid'
          borderColor={borderColor}
          bg={codeBlockBg}
          color={bodyColor}
        >
          {sampleValues}
        </Box>
      ) : (
        <Text fontSize='sm' color={bodyColor}>
          No sample values required. This template is static.
        </Text>
      )}
    </Box>
  );
}

export default function DocsAlerts() {
  const navigate = useNavigate();
  const cardBg = useColorModeValue('rgba(255, 255, 255, 0.95)', 'gray.800');
  const borderColor = useColorModeValue('gray.400', 'gray.600');
  const bodyColor = useColorModeValue('gray.700', 'gray.300');
  const linkColor = useColorModeValue('blue.600', 'blue.300');
  const primaryHoverBg = useColorModeValue('primary.50', 'primary.900');
  const textColor = useColorModeValue('gray.900', 'gray.100');
  const codeBlockBg = useColorModeValue('gray.50', 'gray.900');

  return (
    <>
      <SEO
        title='Docs – Alerts & Preferences'
        description='Configure alert thresholds, channels, recipients, and delivery behavior in TokenTimer.'
        noindex
      />

      <Box
        maxW='1200px'
        mx='auto'
        px={{ base: 4, md: 6 }}
        pt={{ base: 12, md: 10 }}
        pb={{ base: 6, md: 10 }}
        overflowX='hidden'
      >
        <Box display={{ base: 'flex', lg: 'none' }} mb={2}>
          <Button
            onClick={() => navigate('/docs')}
            cursor='pointer'
            variant='ghost'
            size='sm'
            leftIcon={<FiArrowLeft />}
          >
            Back to Docs Home
          </Button>
        </Box>
        <Grid
          templateColumns={{ base: '1fr', lg: '280px minmax(0, 760px) 1fr' }}
          gap={{ base: 6, lg: 8 }}
          alignItems='start'
          w='full'
          overflowX='hidden'
        >
          <GridItem display={{ base: 'none', lg: 'block' }}>
            <Box
              position='sticky'
              top='90px'
              borderWidth='1px'
              borderColor={borderColor}
              borderRadius='md'
              p={4}
              bg={cardBg}
              backdropFilter='blur(6px)'
            >
              <Flex align='center' justify='center' mb={3}>
                <AccessibleButton
                  onClick={() => navigate('/')}
                  variant='ghost'
                  size='sm'
                  fontWeight='bold'
                  fontSize={{ base: 'lg', md: 'xl' }}
                  color={textColor}
                  display='inline-flex'
                  alignItems='center'
                  px={0}
                  py={0}
                  h={{ base: '40px', md: '48px' }}
                  minW='auto'
                  lineHeight='1'
                  bg='transparent'
                  _hover={{
                    bg: primaryHoverBg,
                  }}
                  _focus={{
                    boxShadow: 'none',
                    bg: 'transparent',
                  }}
                  _active={{ bg: 'transparent' }}
                  aria-label='Go to homepage'
                >
                  <Box
                    as={Image}
                    src='/Branding/app-icon.svg'
                    alt='TokenTimer'
                    h='inherit'
                    w='auto'
                    objectFit='contain'
                    filter={useColorModeValue('none', 'invert(1)')}
                    display='block'
                  />
                </AccessibleButton>
              </Flex>
              <Divider my={3} borderColor={borderColor} />
              <ChakraLink
                onClick={() => navigate('/docs')}
                cursor='pointer'
                fontSize='sm'
                color={linkColor}
              >
                ← Back to Docs
              </ChakraLink>
              <Heading as='h2' size='sm' mt={3} mb={3}>
                On this page
              </Heading>
              <List
                spacing={2}
                styleType='disc'
                pl={4}
                fontSize='sm'
                color={bodyColor}
              >
                <ListItem>
                  <ChakraLink href='#overview' color={linkColor}>
                    Overview
                  </ChakraLink>
                </ListItem>
                <ListItem>
                  <ChakraLink href='#thresholds' color={linkColor}>
                    Default Workspace Thresholds
                  </ChakraLink>
                </ListItem>
                <ListItem>
                  <ChakraLink href='#delivery-window' color={linkColor}>
                    Delivery Window
                  </ChakraLink>
                </ListItem>
                <ListItem>
                  <ChakraLink href='#channels' color={linkColor}>
                    Channels & webhooks
                  </ChakraLink>
                </ListItem>
                <ListItem>
                  <ChakraLink href='#whatsapp' color={linkColor}>
                    WhatsApp & Contacts
                  </ChakraLink>
                </ListItem>
                <ListItem>
                  <ChakraLink href='#whatsapp-templates' color={linkColor}>
                    WhatsApp Templates Setup
                  </ChakraLink>
                </ListItem>
                <ListItem>
                  <ChakraLink href='#contact-groups' color={linkColor}>
                    Contact Groups
                  </ChakraLink>
                </ListItem>
                <ListItem>
                  <ChakraLink href='#weekly-digest' color={linkColor}>
                    Weekly Digest
                  </ChakraLink>
                </ListItem>
                <ListItem>
                  <ChakraLink href='#endpoint-health' color={linkColor}>
                    Endpoint Health Alerts
                  </ChakraLink>
                </ListItem>
              </List>
            </Box>
          </GridItem>

          <GridItem minW={0}>
            <VStack align='stretch' spacing={6} w='full' minW={0}>
              <Heading size='lg'>
                Alerts <span style={{ fontFamily: 'Montserrat' }}>&</span>{' '}
                Preferences
              </Heading>

              <Box
                id='overview'
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={2}>
                  Overview
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={3}>
                  Alerts are configured per workspace. You define threshold days
                  (for example 30, 14, 7, 1, 0), and choose channels and
                  recipients via contact groups. Each token delivers to its
                  assigned contact group, or the workspace default contact group
                  when none is assigned. When a token approaches or passes an
                  expiration threshold (once per threshold), TokenTimer queues
                  notifications and delivers the alert to the configured
                  channels.
                </Text>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    <strong>Scope</strong>: settings apply to all tokens inside
                    the workspace.
                  </ListItem>
                  <ListItem>
                    <strong>Delivery</strong>: high available delivery system
                    resilient to failures. Any queued alerts are visible in the
                    alert queue and usage metrics.
                  </ListItem>
                  <ListItem>
                    <strong>Channels</strong>: Email, Webhooks (Slack, Teams,
                    Discord, PagerDuty, Generic), and WhatsApp with workspace
                    contacts.
                  </ListItem>
                  <ListItem>
                    <strong>Core behavior</strong>: role-based access applies,
                    and usage counters are informational in OSS.
                  </ListItem>
                </List>
              </Box>

              <Box
                id='delivery-window'
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={2}>
                  Workspace Delivery Window
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={3}>
                  Configure when alerts and weekly digests can be delivered
                  across ALL channels (email, webhooks, WhatsApp). This is the
                  preferred time for sending notifications. Alerts and digests
                  are sent only during this delivery window; those outside the
                  window are deferred until the next window opens. Defaults to
                  00:00-23:59 UTC (all day, effectively disabled).
                </Text>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    <strong>Start/End time</strong>: HH:mm format (e.g., 08:00,
                    18:00)
                  </ListItem>
                  <ListItem>
                    <strong>Timezone</strong>: Select from 40+ IANA timezones
                    (e.g., Europe/Zurich, America/New_York)
                  </ListItem>
                  <ListItem>
                    <strong>Applies to</strong>: All alert channels (email,
                    webhooks, WhatsApp)
                  </ListItem>
                  <ListItem>
                    <strong>Validation</strong>: Strict HH:mm format enforced;
                    invalid values are rejected
                  </ListItem>
                  <ListItem>
                    <strong>Midnight wrapping</strong>: If start {'>'} end
                    (e.g., 22:00 to 06:00), window wraps overnight
                  </ListItem>
                  <ListItem>
                    <strong>Deferral</strong>: Alerts outside window are retried
                    ~1 hour later (configurable)
                  </ListItem>
                </List>
              </Box>

              <Box
                id='thresholds'
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={2}>
                  Default Workspace Thresholds
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={3}>
                  Thresholds define on which days relative to
                  <strong> expiresAt</strong> a notification is sent. Common
                  values are 30, 14, 7, 1, 0 (day of expiry) and optionally +1
                  or +7 for post‑expiry follow‑ups.
                </Text>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    <strong>Pre‑expiry</strong>: reminders before the date help
                    schedule renewals.
                  </ListItem>
                  <ListItem>
                    <strong>Day 0</strong>: final day‑of‑expiry notification.
                  </ListItem>
                  <ListItem>
                    <strong>Post‑expiry</strong>: optional follow‑ups to keep
                    expired tokens visible until remediation.
                  </ListItem>
                  <ListItem>
                    <strong>Overrides</strong>: contact groups may define their
                    own thresholds policy. A token assigned to such a group uses
                    the group thresholds instead of the workspace defaults.
                  </ListItem>
                  <ListItem>
                    <strong>Change impact</strong>: updating workspace defaults
                    affects tokens without a group thresholds override.
                  </ListItem>
                </List>
              </Box>

              <Box
                id='channels'
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={2}>
                  Channels <span style={{ fontFamily: 'Montserrat' }}>&</span>{' '}
                  webhooks
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={3}>
                  Choose which channels to enable and where to deliver
                  notifications. Webhooks support Slack, Microsoft Teams,
                  Discord, PagerDuty, and generic HTTPS endpoints.
                </Text>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    <strong>Email</strong>: recipients come from the selected
                    contact group.
                  </ListItem>
                  <ListItem>
                    <strong>Webhooks</strong>: create and verify webhooks with a
                    required name; groups may reference one or many named
                    webhooks to route alerts.
                  </ListItem>
                  <ListItem>
                    <strong>Delivery visibility</strong>: see successes and
                    failures in the alert queue; retry failed webhooks from the
                    queue view.
                  </ListItem>
                  <ListItem>
                    <strong>Usage</strong>: each successful send counts toward
                    monthly delivery counters (see Usage & Limits).
                  </ListItem>
                </List>
              </Box>

              <Box
                id='whatsapp'
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={2}>
                  WhatsApp <span style={{ fontFamily: 'Montserrat' }}>&</span>{' '}
                  Contacts
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={3}>
                  Add workspace contacts with names and phone numbers, then
                  select them in contact groups to receive WhatsApp
                  notifications.
                </Text>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    <strong>Add contacts</strong>: First name, last name, and at
                    least a valid email or E.164 phone (e.g., +14155550100).
                    Optional details: department, title, note.
                  </ListItem>
                  <ListItem>
                    <strong>Test contacts</strong>: Use Test button to send a
                    test WhatsApp message (2-minute cooldown per number)
                  </ListItem>
                  <ListItem>
                    <strong>Select in groups</strong>: In contact group editor,
                    check which contacts should receive alerts
                  </ListItem>
                  <ListItem>
                    <strong>No fallback</strong>: If a contact group has no
                    contacts selected, WhatsApp alerts will NOT be sent
                  </ListItem>
                  <ListItem>
                    <strong>Operational limits</strong>: provider throttling and
                    delivery backoff still apply to protect reliability.
                  </ListItem>
                </List>
              </Box>

              <Box
                id='whatsapp-templates'
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={2}>
                  WhatsApp Templates Setup
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={3}>
                  This section is the exact setup contract between TokenTimer
                  and Twilio Content Templates. If a template uses placeholders
                  that TokenTimer does not send, Twilio will reject delivery.
                </Text>

                <Heading as='h3' size='sm' mt={4} mb={2}>
                  Step 1: Create templates in Twilio
                </Heading>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  mb={4}
                >
                  <ListItem>
                    Twilio Console {'>'} Messaging {'>'} Content Template
                    Builder
                    {'>'} Create template.
                  </ListItem>
                  <ListItem>
                    <strong>Content type</strong>: Text.
                  </ListItem>
                  <ListItem>
                    <strong>Channel</strong>: WhatsApp.
                  </ListItem>
                  <ListItem>
                    <strong>Category</strong>: Utility (recommended for alerts
                    and digests).
                  </ListItem>
                  <ListItem>
                    Create one template per use case below. Save and submit for
                    approval. Copy the generated <strong>HX...</strong> SID.
                  </ListItem>
                </List>

                <Heading as='h3' size='sm' mt={4} mb={2}>
                  Step 2: Map each SID in System Settings
                </Heading>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  mb={4}
                >
                  <ListItem>
                    <strong>TWILIO_WHATSAPP_ALERT_CONTENT_SID_EXPIRES</strong>:
                    template used for upcoming expirations.
                  </ListItem>
                  <ListItem>
                    <strong>TWILIO_WHATSAPP_ALERT_CONTENT_SID_EXPIRED</strong>:
                    template used for already expired items.
                  </ListItem>
                  <ListItem>
                    <strong>TWILIO_WHATSAPP_TEST_CONTENT_SID</strong>: template
                    used by System Settings test send and contact test send.
                  </ListItem>
                  <ListItem>
                    <strong>TWILIO_WHATSAPP_WEEKLY_DIGEST_CONTENT_SID</strong>:
                    template used for weekly digest channel.
                  </ListItem>
                  <ListItem>
                    <strong>
                      TWILIO_WHATSAPP_ALERT_CONTENT_SID_ENDPOINT_DOWN
                    </strong>
                    : deployment-level template used for endpoint down alerts.
                  </ListItem>
                  <ListItem>
                    <strong>
                      TWILIO_WHATSAPP_ALERT_CONTENT_SID_ENDPOINT_RECOVERED
                    </strong>
                    : deployment-level template used for endpoint recovered
                    alerts.
                  </ListItem>
                </List>

                <Text fontSize='sm' color={bodyColor} mb={4}>
                  Admin note: the Expires, Expired, Test, and Weekly Digest
                  template SIDs are configured in{' '}
                  <strong>System Settings</strong>. Endpoint health WhatsApp
                  template SIDs are configured at deployment level and require a
                  delivery worker restart after changes.
                </Text>

                <Heading as='h3' size='sm' mt={4} mb={2}>
                  Placeholder contracts by template
                </Heading>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  mb={4}
                >
                  <ListItem>
                    <strong>EXPIRES template</strong>: recipient_name,
                    token_type, token_name, days_text, expiration_date, details.
                  </ListItem>
                  <ListItem>
                    <strong>EXPIRED template</strong>: recipient_name,
                    token_type, token_name, days_text, expiration_date, details.
                  </ListItem>
                  <ListItem>
                    <strong>TEST template</strong>: no placeholders required.
                  </ListItem>
                  <ListItem>
                    <strong>WEEKLY_DIGEST template</strong>: recipient_name,
                    workspace_name, contact_group_name, tokens_count,
                    tokens_list.
                  </ListItem>
                  <ListItem>
                    <strong>ENDPOINT_DOWN template</strong>: recipient_name,
                    endpoint_name, endpoint_url, token_name, detected_at.
                  </ListItem>
                  <ListItem>
                    <strong>ENDPOINT_RECOVERED template</strong>:
                    recipient_name, endpoint_name, endpoint_url, token_name,
                    detected_at.
                  </ListItem>
                </List>

                <Text fontSize='sm' color={bodyColor} mb={2}>
                  Rule: only use placeholders listed for that template. Extra
                  placeholders are not populated by TokenTimer.
                </Text>

                <Heading as='h3' size='sm' mt={4} mb={2}>
                  Copy ready template examples
                </Heading>
                <TemplateExampleCard
                  title='EXPIRES'
                  templateBody={`ALERT: Token Expiring Soon

Hello {{recipient_name}}, your {{token_type}} token "{{token_name}}" is expiring in {{days_text}} day(s) on {{expiration_date}}.

Details: {{details}}

Please plan the renewal to avoid service disruption.

TokenTimer Expiration Management`}
                  sampleValues={`recipient_name = Operations Team
token_type = Certificate
token_name = production-api-cert
days_text = 7
expiration_date = 2025-10-10
details = DigiCert, Location: eu-west-1 (AWS), Used By: API Gateway, Domains: api.example.com, www.example.com, Algorithm: RSA, Key Size: 2048 bits`}
                  borderColor={borderColor}
                  codeBlockBg={codeBlockBg}
                  bodyColor={bodyColor}
                />

                <TemplateExampleCard
                  title='EXPIRED'
                  templateBody={`URGENT: Token Expired

Hello {{recipient_name}}, your {{token_type}} token "{{token_name}}" expired {{days_text}} day(s) ago on {{expiration_date}}.

Details: {{details}}

This token has expired and may cause service outages. Please renew immediately.

TokenTimer Expiration Management`}
                  sampleValues={`recipient_name = Operations Team
token_type = Certificate
token_name = production-api-cert
days_text = 3
expiration_date = 2025-10-10
details = DigiCert, Location: eu-west-1 (AWS), Used By: API Gateway, Domains: api.example.com, www.example.com, Algorithm: RSA, Key Size: 2048 bits`}
                  borderColor={borderColor}
                  codeBlockBg={codeBlockBg}
                  bodyColor={bodyColor}
                />

                <TemplateExampleCard
                  title='TEST'
                  templateBody={`TokenTimer WhatsApp Test

Hello, this is a test to confirm WhatsApp alerts are working for your workspace.

If you receive this, WhatsApp delivery is configured correctly.

TokenTimer Expiration Management`}
                  sampleValues={null}
                  borderColor={borderColor}
                  codeBlockBg={codeBlockBg}
                  bodyColor={bodyColor}
                />

                <TemplateExampleCard
                  title='WEEKLY_DIGEST'
                  templateBody={`📊 Weekly Digest: {{tokens_count}} token(s) Expiring Soon

Hello {{recipient_name}},

Your workspace "{{workspace_name}}" has {{tokens_count}} token(s) expiring soon in the contact group "{{contact_group_name}}".

Expiring tokens
{{tokens_list}}

Please review and renew these tokens to avoid service disruptions.

TokenTimer Expiration Management`}
                  sampleValues={`tokens_count = 10
recipient_name = On-call Team
workspace_name = Production
contact_group_name = Primary On-call
tokens_list = SSL Certificate: 2025-10-10 (90d); API Key: 2025-11-29 (75d); Database Password: 2025-11-19 (71d)`}
                  borderColor={borderColor}
                  codeBlockBg={codeBlockBg}
                  bodyColor={bodyColor}
                />

                <TemplateExampleCard
                  title='ENDPOINT_DOWN'
                  templateBody={`⚠️ Endpoint Down

Hello {{recipient_name}},

TokenTimer detected that endpoint "{{endpoint_name}}" is DOWN.
URL: {{endpoint_url}}
Linked token: {{token_name}}
Detected at: {{detected_at}}

Please check the affected service.

TokenTimer Endpoint Monitoring`}
                  sampleValues={`recipient_name = On-call Team
endpoint_name = staging-api
endpoint_url = https://staging.example.com/health
token_name = staging-api-cert
detected_at = Mar 16, 2026, 18:00 UTC`}
                  borderColor={borderColor}
                  codeBlockBg={codeBlockBg}
                  bodyColor={bodyColor}
                />

                <TemplateExampleCard
                  title='ENDPOINT_RECOVERED'
                  templateBody={`✅ Endpoint Recovered

Hello {{recipient_name}},

TokenTimer detected that endpoint "{{endpoint_name}}" has RECOVERED.
URL: {{endpoint_url}}
Linked token: {{token_name}}
Detected at: {{detected_at}}

The endpoint is responding normally again.

TokenTimer Endpoint Monitoring`}
                  sampleValues={`recipient_name = On-call Team
endpoint_name = staging-api
endpoint_url = https://staging.example.com/health
token_name = staging-api-cert
detected_at = Mar 16, 2026, 18:12 UTC`}
                  borderColor={borderColor}
                  codeBlockBg={codeBlockBg}
                  bodyColor={bodyColor}
                />
              </Box>

              <Box
                id='contact-groups'
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={2}>
                  Contact Groups
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={3}>
                  Define named groups per workspace with per-contact channels
                  and webhooks. Groups can override workspace threshold
                  defaults. Assign a group per token or use the workspace
                  default group.
                </Text>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    <strong>Per-contact channels</strong>: Select Email and/or
                    WhatsApp for each contact from the workspace contacts list.
                    Email uses the contact{"'"}s email; WhatsApp uses the
                    contact{"'"}s phone number.
                  </ListItem>
                  <ListItem>
                    <strong>Webhooks</strong>: Select named webhooks from the
                    workspace webhook list
                  </ListItem>
                  <ListItem>
                    <strong>Thresholds override</strong>: Optionally set
                    group-specific thresholds that override workspace defaults
                  </ListItem>
                  <ListItem>
                    <strong>Scale</strong>: design groups around ownership and
                    escalation paths for maintainability.
                  </ListItem>
                  <ListItem>
                    <strong>Default group</strong>: Set a workspace default;
                    tokens without explicit group use the default
                  </ListItem>
                  <ListItem>
                    <strong>Per-token assignment</strong>: Assign a contact
                    group when creating/editing a token
                  </ListItem>
                </List>
              </Box>

              <Box
                id='weekly-digest'
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={2}>
                  Weekly Digest
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={3}>
                  Weekly digest sends a summary of all tokens close to expiring
                  (within your thresholds) once per week per contact group. This
                  gives you a consolidated view instead of individual alerts for
                  each token.
                </Text>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    <strong>Enable per group</strong>: In contact group
                    settings, check {'"'}Email weekly digest{'"'}, {'"'}WhatsApp
                    weekly digest{'"'}, or {'"'}Webhook weekly digest{'"'}
                  </ListItem>
                  <ListItem>
                    <strong>Frequency</strong>: Sent once per week (on Mondays)
                    per contact group, automatically scheduled with your
                    preferred delivery window.
                  </ListItem>
                  <ListItem>
                    <strong>Token selection</strong>: Includes all tokens within
                    your highest alert threshold (e.g., if thresholds are
                    1,7,30,60 days, digest shows tokens expiring in ≤60 days).
                    Excludes already expired tokens.
                  </ListItem>
                  <ListItem>
                    <strong>Channels</strong>: Email, WhatsApp, and Webhooks
                    (Slack, Discord, Teams, Generic). PagerDuty is not supported
                    for digests.
                  </ListItem>
                </List>
              </Box>

              <Box
                id='endpoint-health'
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={2}>
                  Endpoint Health Alerts
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={3}>
                  When you add an endpoint monitor with health checking enabled,
                  TokenTimer tracks the health status of that URL and can alert
                  you when it goes down or recovers. Alerts are triggered on{' '}
                  <strong>state transitions only</strong>, not on every check.
                </Text>

                <Heading as='h3' size='sm' mt={4} mb={2}>
                  How it works
                </Heading>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    <strong>First check</strong>: The very first health check
                    establishes a baseline. No alert is sent regardless of the
                    result.
                  </ListItem>
                  <ListItem>
                    <strong>Healthy to unhealthy</strong>: When an endpoint
                    transitions from healthy to unhealthy (HTTP error, timeout,
                    etc.), a {'"'}down{'"'} alert is queued.
                  </ListItem>
                  <ListItem>
                    <strong>Unhealthy to healthy</strong>: When an endpoint
                    recovers, a {'"'}recovered{'"'} alert is sent, but only if
                    you were previously notified it was down.
                  </ListItem>
                  <ListItem>
                    <strong>No change</strong>: If the status stays the same
                    between checks (still healthy, or still unhealthy), no new
                    alert is created.
                  </ListItem>
                </List>

                <Heading as='h3' size='sm' mt={4} mb={2}>
                  Alert after failures
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={2}>
                  To avoid false alarms from brief network glitches, you can
                  configure how many consecutive failures must occur before you
                  are actually notified. This is the{' '}
                  <strong>
                    {'"'}Alert after failures{'"'}
                  </strong>{' '}
                  setting on each endpoint.
                </Text>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    Default is <strong>2 consecutive failures</strong>.
                  </ListItem>
                  <ListItem>
                    The {'"'}down{'"'} alert is queued immediately on the first
                    failure transition, but the delivery worker waits until the
                    failure count reaches the threshold before actually sending
                    the notification.
                  </ListItem>
                  <ListItem>
                    If the endpoint recovers before the threshold is reached,
                    the queued alert is silently discarded and you receive
                    nothing.
                  </ListItem>
                  <ListItem>
                    Recovery alerts are always sent immediately (no threshold
                    gate) if a {'"'}down{'"'} notification was previously
                    delivered.
                  </ListItem>
                </List>

                <Heading as='h3' size='sm' mt={4} mb={2}>
                  No spam guarantee
                </Heading>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    Only{' '}
                    <strong>
                      one {'"'}down{'"'} alert
                    </strong>{' '}
                    is sent per outage, no matter how long the endpoint stays
                    unhealthy.
                  </ListItem>
                  <ListItem>
                    Only{' '}
                    <strong>
                      one {'"'}recovered{'"'} alert
                    </strong>{' '}
                    is sent when the endpoint comes back online.
                  </ListItem>
                  <ListItem>
                    If an endpoint was never healthy (e.g., misconfigured URL),
                    the first check produces no baseline transition. A {'"'}down
                    {'"'}
                    alert will fire only after it eventually becomes healthy and
                    then goes unhealthy again.
                  </ListItem>
                  <ListItem>
                    Recovery alerts are never sent if the user was not
                    previously informed of the outage.
                  </ListItem>
                </List>

                <Heading as='h3' size='sm' mt={4} mb={2}>
                  Delivery channels and contact groups
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={2}>
                  Endpoint health alerts use the same delivery channels
                  configured in your workspace alert settings (email, webhooks,
                  WhatsApp). They respect your delivery window configuration.
                </Text>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    When adding an endpoint, you can select a{' '}
                    <strong>contact group</strong> to receive alerts. This is
                    set on the auto-created SSL token.
                  </ListItem>
                  <ListItem>
                    If no contact group is selected, the{' '}
                    <strong>workspace default</strong> contact group is used
                    automatically.
                  </ListItem>
                  <ListItem>
                    You can change the contact group later by editing the SSL
                    token directly.
                  </ListItem>
                </List>
              </Box>
            </VStack>
          </GridItem>
          <GridItem display={{ base: 'none', lg: 'block' }} />
        </Grid>
      </Box>
    </>
  );
}
