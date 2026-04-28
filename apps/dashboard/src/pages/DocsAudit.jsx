import {
  Box,
  Container,
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

export default function DocsAudit() {
  const navigate = useNavigate();
  const cardBg = useColorModeValue('rgba(255, 255, 255, 0.95)', 'gray.800');
  const borderColor = useColorModeValue('gray.400', 'gray.600');
  const bodyColor = useColorModeValue('gray.700', 'gray.300');
  const linkColor = useColorModeValue('blue.600', 'blue.300');
  const primaryHoverBg = useColorModeValue('primary.50', 'primary.900');
  const textColor = useColorModeValue('gray.900', 'gray.100');

  return (
    <>
      <SEO
        title='Docs – Audit'
        description='Understand audit events, scopes, and retention in TokenTimer.'
        noindex
      />

      <Container
        maxW='1200px'
        pt={{ base: 12, md: 8 }}
        pb={8}
        px={{ base: 4, md: 6 }}
        position='relative'
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
                color={bodyColor}
                fontSize='sm'
              >
                <ListItem>
                  <ChakraLink href='#overview' color={linkColor}>
                    Overview
                  </ChakraLink>
                </ListItem>
                <ListItem>
                  <ChakraLink href='#workspace-scope' color={linkColor}>
                    Workspace scope
                  </ChakraLink>
                </ListItem>
                <ListItem>
                  <ChakraLink href='#org-scope' color={linkColor}>
                    Organization scope
                  </ChakraLink>
                </ListItem>
                <ListItem>
                  <ChakraLink href='#event-catalog' color={linkColor}>
                    Event catalog
                  </ChakraLink>
                  <List
                    spacing={1}
                    pl={4}
                    mt={1}
                    styleType='circle'
                    fontSize='xs'
                  >
                    <ListItem>
                      <ChakraLink href='#authentication' color={linkColor}>
                        Authentication
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink href='#workspace-rbac' color={linkColor}>
                        Workspace & RBAC
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink href='#tokens' color={linkColor}>
                        Tokens
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink href='#contacts-whatsapp' color={linkColor}>
                        Contacts & WhatsApp
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink href='#alert-delivery' color={linkColor}>
                        Alert delivery
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink href='#system-operations' color={linkColor}>
                        System operations
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        href='#user-settings-integrations'
                        color={linkColor}
                      >
                        User settings & integrations
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink href='#auto-sync-events' color={linkColor}>
                        Auto-Sync
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        href='#endpoint-monitoring-events'
                        color={linkColor}
                      >
                        Endpoint Monitoring
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        href='#domain-checker-events'
                        color={linkColor}
                      >
                        Domain Checker
                      </ChakraLink>
                    </ListItem>
                  </List>
                </ListItem>
              </List>
            </Box>
          </GridItem>

          <GridItem minW={0}>
            <VStack align='stretch' spacing={6} w='full' minW={0}>
              <Heading size='lg'>Audit</Heading>

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
                  Audit provides visibility into important security‑relevant
                  actions and alert delivery outcomes. Use it to investigate who
                  did what and when, and to prove compliance.
                </Text>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  wordBreak='break-word'
                  overflowWrap='anywhere'
                >
                  <ListItem>
                    <strong>Event types</strong>: authentication, token create /
                    update / delete, workspace membership changes, alert
                    delivery results (success/failure), weekly digest sends,
                    WhatsApp tests, settings updates, integrations, and imports.
                  </ListItem>
                  <ListItem>
                    <strong>Retention</strong>: depends on your deployment
                    policy and log storage configuration.
                  </ListItem>
                  <ListItem>
                    <strong>Export</strong>: audit logs can be exported as CSV
                    or JSON for compliance reporting and external analysis.
                  </ListItem>
                </List>
              </Box>

              <Box
                id='workspace-scope'
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={2}>
                  Workspace scope
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={3}>
                  View events tied to the currently selected workspace. Managers
                  and admins can filter by date and event type to focus on
                  relevant activity.
                </Text>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  wordBreak='break-word'
                  overflowWrap='anywhere'
                >
                  <ListItem>
                    Token changes, member invites/removals, settings updates.
                  </ListItem>
                  <ListItem>
                    Alert delivery outcomes for tokens in this workspace.
                  </ListItem>
                </List>
              </Box>

              <Box
                id='org-scope'
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={2}>
                  Organization scope
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={3}>
                  Admins can aggregate events across all admin‑owned workspaces
                  to spot trends and investigate cross‑workspace issues.
                </Text>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  wordBreak='break-word'
                  overflowWrap='anywhere'
                >
                  <ListItem>Organization‑wide filters and export.</ListItem>
                  <ListItem>
                    Combine with Usage to correlate incidents and thresholds.
                  </ListItem>
                </List>
              </Box>

              <Box
                id='event-catalog'
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={2}>
                  Event catalog
                </Heading>
                <Text
                  fontSize='sm'
                  color={bodyColor}
                  mb={3}
                  wordBreak='break-word'
                  overflowWrap='anywhere'
                >
                  Each event records {'"'}occurredAt{'"'}, {'"'}actor_user_id
                  {'"'},{'"'}subject_user_id{'"'}, {'"'}action{'"'}, {'"'}
                  target_type{'"'}, {'"'}target_id{'"'},{'"'}channel{'"'}, {'"'}
                  metadata{'"'}, and {'"'}workspace_id{'"'} (when applicable).
                </Text>

                <Heading as='h3' size='sm' mt={4} mb={2} id='authentication'>
                  Authentication
                </Heading>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  wordBreak='break-word'
                  overflowWrap='anywhere'
                >
                  <ListItem>
                    <strong>LOGIN_SUCCESS</strong> metadata: {'{ method }'}
                  </ListItem>
                  <ListItem>
                    <strong>LOGIN_SUCCESS_2FA</strong> metadata: {'{ method }'}
                  </ListItem>
                  <ListItem>
                    <strong>LOGIN_FAILED</strong> metadata:{' '}
                    {'{ email, reason }'}
                  </ListItem>
                  <ListItem>
                    <strong>LOGOUT</strong>
                  </ListItem>
                  <ListItem>
                    <strong>TWO_FACTOR_ENABLED</strong>
                  </ListItem>
                  <ListItem>
                    <strong>TWO_FACTOR_DISABLED</strong>
                  </ListItem>
                  <ListItem>
                    <strong>EMAIL_VERIFICATION_SENT</strong>
                  </ListItem>
                  <ListItem>
                    <strong>EMAIL_VERIFICATION_RESENT</strong>
                  </ListItem>
                  <ListItem>
                    <strong>EMAIL_VERIFICATION_FAILED</strong>
                  </ListItem>
                  <ListItem>
                    <strong>EMAIL_VERIFIED</strong>
                  </ListItem>
                  <ListItem>
                    <strong>PASSWORD_RESET_REQUESTED</strong>
                  </ListItem>
                  <ListItem>
                    <strong>PASSWORD_RESET_COMPLETED</strong>
                  </ListItem>
                  <ListItem>
                    <strong>PASSWORD_CHANGED</strong>
                  </ListItem>
                </List>

                <Heading as='h3' size='sm' mt={4} mb={2} id='workspace-rbac'>
                  Workspace <span style={{ fontFamily: 'Montserrat' }}>&</span>{' '}
                  RBAC
                </Heading>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  wordBreak='break-word'
                  overflowWrap='anywhere'
                >
                  <ListItem>
                    <strong>WORKSPACE_CREATED</strong> metadata:{' '}
                    {'{ name, kind }'}
                  </ListItem>
                  <ListItem>
                    <strong>WORKSPACE_RENAMED</strong> metadata:{' '}
                    {'{ before.name, after.name }'}
                  </ListItem>
                  <ListItem>
                    <strong>WORKSPACE_DELETED</strong>
                  </ListItem>
                  <ListItem>
                    <strong>MEMBER_INVITED_OR_UPDATED</strong> metadata:{' '}
                    {'{ role, email, workspace_name, recipient_type }'}. Emitted
                    synchronously when an invitation or direct membership is
                    created. {`recipient_type`} is {`"existing_user"`} when the
                    email already has a TokenTimer account (membership created
                    directly) or {`"invitation"`} when a pending invitation row
                    was written for a new email.
                  </ListItem>
                  <ListItem>
                    <strong>INVITE_EMAIL_SENT</strong> metadata:{' '}
                    {'{ role, email, workspace_name }'}. Emitted only after the
                    invitation email was handed off to the SMTP transport
                    successfully. Absence of this event after
                    MEMBER_INVITED_OR_UPDATED means the email step failed and
                    the operator should check mail logs.
                  </ListItem>
                  <ListItem>
                    <strong>INVITATION_CANCELLED</strong> metadata:{' '}
                    {'{ email, role, workspace_name, invitation_id }'}. Emitted
                    when a pending invitation is removed via{' '}
                    <code>
                      DELETE /api/v1/workspaces/:id/invitations/:invitationId
                    </code>
                    . Accepted invitations are never cancelled by this endpoint.
                  </ListItem>
                  <ListItem>
                    <strong>MEMBER_ROLE_CHANGED</strong> metadata: {'{ role }'}
                  </ListItem>
                  <ListItem>
                    <strong>MEMBER_REMOVED</strong>
                  </ListItem>
                  <ListItem>
                    <strong>WORKSPACE_MEMBERSHIP_ACCEPTED</strong>
                  </ListItem>
                  <ListItem>
                    <strong>WORKSPACE_ALERT_SETTINGS_UPDATED</strong>
                  </ListItem>
                </List>

                <Heading as='h3' size='sm' mt={4} mb={2} id='tokens'>
                  Tokens
                </Heading>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  wordBreak='break-word'
                  overflowWrap='anywhere'
                >
                  <ListItem>
                    <strong>TOKEN_CREATED</strong> metadata:{' '}
                    {'{ name, type, category }'}
                  </ListItem>
                  <ListItem>
                    <strong>TOKEN_UPDATED</strong> metadata:{' '}
                    {'{ fields, changes }'}
                  </ListItem>
                  <ListItem>
                    <strong>TOKEN_DELETED</strong> metadata:{' '}
                    {'{ name, reason }'}
                  </ListItem>
                  <ListItem>
                    <strong>TOKENS_TRANSFERRED_BETWEEN_WORKSPACES</strong>
                  </ListItem>
                  <ListItem>
                    <strong>TOKENS_REASSIGNED_CONTACT_GROUP</strong>
                  </ListItem>
                </List>

                <Heading as='h3' size='sm' mt={4} mb={2} id='contacts-whatsapp'>
                  Contacts <span style={{ fontFamily: 'Montserrat' }}>&</span>{' '}
                  WhatsApp
                </Heading>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  wordBreak='break-word'
                  overflowWrap='anywhere'
                >
                  <ListItem>
                    <strong>WORKSPACE_CONTACT_CREATED</strong> metadata:{' '}
                    {'{ contact_id, phone_masked }'}
                  </ListItem>
                  <ListItem>
                    <strong>WORKSPACE_CONTACT_UPDATED</strong> metadata:{' '}
                    {'{ contact_id, fields_updated }'}
                  </ListItem>
                  <ListItem>
                    <strong>WORKSPACE_CONTACT_DELETED</strong> metadata:{' '}
                    {'{ contact_id }'}
                  </ListItem>
                  <ListItem>
                    <strong>WHATSAPP_TEST_SENT</strong>
                  </ListItem>
                  <ListItem>
                    <strong>WHATSAPP_TEST_SENT_TEMPLATE</strong>
                  </ListItem>
                  <ListItem>
                    <strong>WHATSAPP_TEST_FAILED</strong>
                  </ListItem>
                  <ListItem>
                    <strong>WHATSAPP_TEST_FAILED_TEMPLATE</strong>
                  </ListItem>
                  <ListItem>
                    <strong>WHATSAPP_TEST_RATE_LIMITED</strong>
                  </ListItem>
                  <ListItem>
                    <strong>WHATSAPP_TEST_ERROR</strong>
                  </ListItem>
                </List>

                <Heading as='h3' size='sm' mt={4} mb={2} id='alert-delivery'>
                  Alert delivery
                </Heading>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  wordBreak='break-word'
                  overflowWrap='anywhere'
                >
                  <ListItem>
                    <strong>ALERT_QUEUED</strong> metadata:{' '}
                    {'{ daysUntil, threshold, dueDate }'}
                  </ListItem>
                  <ListItem>
                    <strong>ALERT_CHANNELS_UPDATED</strong> metadata:{' '}
                    {'{ alertKey, from, to }'}
                  </ListItem>
                  <ListItem>
                    <strong>ALERT_NOT_QUEUED_NO_CHANNEL</strong> metadata:{' '}
                    {'{ reason }'}
                  </ListItem>
                  <ListItem>
                    <strong>ALERT_SENT</strong> metadata: {'{ days, channels }'}
                  </ListItem>
                  <ListItem>
                    <strong>ALERT_SEND_FAILED</strong> metadata:{' '}
                    {'{ days, error, attempts }'}
                  </ListItem>
                  <ListItem>
                    <strong>ALERT_PARTIAL_SUCCESS</strong> metadata:{' '}
                    {'{ channel, errors }'}
                  </ListItem>
                  <ListItem>
                    <strong>ALERT_RETRY_SCHEDULED</strong> metadata:{' '}
                    {'{ days, next_attempt_at, remaining_channels }'}
                  </ListItem>
                  <ListItem>
                    <strong>ALERT_BLOCKED_MAX_ATTEMPTS</strong> metadata:{' '}
                    {
                      '{ days, attempts_email, attempts_webhooks, attempts_whatsapp }'
                    }
                  </ListItem>
                  <ListItem>
                    <strong>ALERT_BLOCKED_WHATSAPP_ERROR</strong> metadata:{' '}
                    {'{ days }'}
                  </ListItem>
                  <ListItem>
                    <strong>ALERT_MANUAL_RETRY</strong>
                  </ListItem>
                  <ListItem>
                    <strong>WEEKLY_DIGEST_SENT</strong> metadata:{' '}
                    {
                      '{ contact_group_id, contact_group_name, tokens_count, channels, week_start_date }'
                    }
                  </ListItem>
                </List>

                <Heading as='h3' size='sm' mt={4} mb={2} id='system-operations'>
                  System operations
                </Heading>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  wordBreak='break-word'
                  overflowWrap='anywhere'
                >
                  <ListItem>
                    <strong>ALERTS_BULK_REQUEUED</strong>
                  </ListItem>
                  <ListItem>
                    <strong>WHATSAPP_TEST_SENT</strong> and related test events
                  </ListItem>
                </List>

                <Heading
                  as='h3'
                  size='sm'
                  mt={4}
                  mb={2}
                  id='user-settings-integrations'
                >
                  User settings{' '}
                  <span style={{ fontFamily: 'Montserrat' }}>&</span>{' '}
                  integrations
                </Heading>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  wordBreak='break-word'
                  overflowWrap='anywhere'
                >
                  <ListItem>
                    <strong>ALERT_PREFS_UPDATED</strong> metadata:{' '}
                    {'{ fields_updated }'}
                  </ListItem>
                  <ListItem>
                    <strong>INTEGRATION_SCAN</strong> metadata:{' '}
                    {'{ provider, region, success, tokens_found }'}
                  </ListItem>
                  <ListItem>
                    <strong>INTEGRATION_DETECT_REGIONS</strong> metadata:{' '}
                    {'{ provider, regions_found }'}
                  </ListItem>
                  <ListItem>
                    <strong>TOKEN_IMPORTED</strong> metadata:{' '}
                    {'{ source, name, type }'}
                  </ListItem>
                  <ListItem>
                    <strong>TOKENS_IMPORTED</strong> metadata:{' '}
                    {'{ source, count, method }'}
                  </ListItem>
                </List>

                <Heading as='h3' size='sm' mt={4} mb={2} id='auto-sync-events'>
                  Auto-Sync
                </Heading>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  wordBreak='break-word'
                  overflowWrap='anywhere'
                >
                  <ListItem>
                    <strong>AUTO_SYNC_CREATED</strong> metadata:{' '}
                    {'{ provider, frequency, timezone }'}
                  </ListItem>
                  <ListItem>
                    <strong>AUTO_SYNC_UPDATED</strong> metadata:{' '}
                    {'{ provider, fields_updated }'}
                  </ListItem>
                  <ListItem>
                    <strong>AUTO_SYNC_DELETED</strong> metadata:{' '}
                    {'{ provider }'}
                  </ListItem>
                  <ListItem>
                    <strong>AUTO_SYNC_TRIGGERED</strong> metadata:{' '}
                    {'{ provider }'}
                  </ListItem>
                </List>

                <Heading
                  as='h3'
                  size='sm'
                  mt={4}
                  mb={2}
                  id='endpoint-monitoring-events'
                >
                  Endpoint Monitoring
                </Heading>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  wordBreak='break-word'
                  overflowWrap='anywhere'
                >
                  <ListItem>
                    <strong>DOMAIN_MONITOR_CREATED</strong> metadata:{' '}
                    {'{ url, ssl_detected }'}
                  </ListItem>
                  <ListItem>
                    <strong>DOMAIN_MONITOR_UPDATED</strong> metadata:{' '}
                    {'{ url, fields_updated }'}
                  </ListItem>
                  <ListItem>
                    <strong>DOMAIN_MONITOR_DELETED</strong> metadata:{' '}
                    {'{ url }'}
                  </ListItem>
                  <ListItem>
                    <strong>DOMAIN_MONITOR_HEALTH_CHECK</strong> metadata:{' '}
                    {'{ url, status, response_ms }'}
                  </ListItem>
                </List>

                <Heading
                  as='h3'
                  size='sm'
                  mt={4}
                  mb={2}
                  id='domain-checker-events'
                >
                  Domain Checker
                </Heading>
                <Text
                  fontSize='sm'
                  color={bodyColor}
                  mb={3}
                  wordBreak='break-word'
                  overflowWrap='anywhere'
                >
                  Emitted when a workspace member discovers publicly known
                  subdomains for a root domain using passive discovery
                  (subfinder), or imports selected hostnames into the workspace
                  as SSL tokens. Lookup is rate limited per workspace and user.
                </Text>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  wordBreak='break-word'
                  overflowWrap='anywhere'
                >
                  <ListItem>
                    <strong>DOMAIN_CHECKER_LOOKUP</strong> metadata:{' '}
                    {
                      '{ domain, source, results, partial, tools_succeeded, tools_failed, truncated }'
                    }
                    . {'"'}source{'"'} is {'"'}subfinder{'"'}. {'"'}partial{'"'}{' '}
                    is true when only some discovery tools completed. {'"'}
                    tools_failed{'"'}
                    lists any tool names that timed out or errored.
                  </ListItem>
                  <ListItem>
                    <strong>DOMAIN_CHECKER_IMPORT</strong> metadata:{' '}
                    {
                      '{ domain, source, submitted, imported, skipped, skipped_duplicate, skipped_invalid, skipped_unreachable, skipped_other_invalid, create_monitors, monitors_created, monitors_existing }'
                    }
                    . When {'"'}create_monitors{'"'} is true the event also
                    includes{' '}
                    {
                      '{ monitor_check_interval, monitor_health_check_enabled, monitor_alert_after_failures, monitor_contact_group_id }'
                    }
                    . {'"'}submitted{'"'} is the number of certificates the
                    client selected, {'"'}imported{'"'} counts newly created SSL
                    tokens, {'"'}skipped_unreachable{'"'} counts DNS failures
                    (no name or temporary resolver failure), {'"'}
                    skipped_other_invalid{'"'} is invalid skips excluding those
                    DNS cases, and {'"'}skipped_duplicate{'"'} / {'"'}
                    skipped_invalid{'"'} are aggregate skip counts.
                  </ListItem>
                </List>
              </Box>
            </VStack>
          </GridItem>
          <GridItem display={{ base: 'none', lg: 'block' }} />
        </Grid>
      </Container>
    </>
  );
}
