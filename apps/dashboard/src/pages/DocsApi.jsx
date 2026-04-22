import {
  Box,
  Container,
  Heading,
  Text,
  VStack,
  List,
  ListItem,
  Code,
  Divider,
  useColorModeValue,
  Link as ChakraLink,
  Grid,
  GridItem,
  Button,
  Icon,
  Flex,
  Image,
} from '@chakra-ui/react';
import {
  FiArrowLeft,
  FiKey,
  FiShield,
  FiBell,
  FiUser,
  FiUsers,
  FiRefreshCw,
  FiSettings,
  FiFileText,
  FiDatabase,
  FiGlobe,
} from 'react-icons/fi';
import { useNavigate } from 'react-router-dom';
import { AccessibleButton } from '../components/Accessibility';
import CopyableCodeBlock from '../components/CopyableCodeBlock.jsx';

import SEO from '../components/SEO.jsx';

export default function DocsApi() {
  const navigate = useNavigate();
  const cardBg = useColorModeValue('rgba(255, 255, 255, 0.95)', 'gray.800');
  const borderColor = useColorModeValue('gray.400', 'gray.600');
  const bodyColor = useColorModeValue('gray.700', 'gray.300');
  const linkColor = useColorModeValue('blue.600', 'blue.300');
  const primaryHoverBg = useColorModeValue('primary.50', 'primary.900');
  const textColor = useColorModeValue('gray.900', 'gray.100');

  const Anchor = ({ id }) => <Box id={id} position='relative' top='-80px' />;

  return (
    <>
      <SEO
        title='Docs – API Reference'
        description='TokenTimer API reference: authentication, tokens, alerts, audit, and usage endpoints.'
        noindex
      />

      <Container
        maxW='1200px'
        px={{ base: 4, md: 6 }}
        pt={{ base: 12, md: 10 }}
        pb={{ base: 6, md: 10 }}
        centerContent={false}
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
          {/* Left TOC (sticky on large screens) */}
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
                color={linkColor}
                fontSize='sm'
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
                  <ChakraLink href='#quick-start' color={linkColor}>
                    Quick start
                  </ChakraLink>
                </ListItem>
                <ListItem>
                  <ChakraLink href='#all-plans' color={linkColor}>
                    Core API
                  </ChakraLink>
                  <List
                    spacing={1}
                    pl={4}
                    styleType='circle'
                    mt={1}
                    fontSize='xs'
                  >
                    <ListItem>
                      <ChakraLink href='#all-plans-auth' color={linkColor}>
                        Authentication
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink href='#all-plans-tokens' color={linkColor}>
                        Tokens
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink href='#all-plans-alerts' color={linkColor}>
                        Alerts
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink href='#all-plans-usage' color={linkColor}>
                        Usage
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink href='#auto-sync-api' color={linkColor}>
                        Auto-Sync
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        href='#endpoint-monitor-api'
                        color={linkColor}
                      >
                        Endpoint Monitoring
                      </ChakraLink>
                    </ListItem>
                  </List>
                </ListItem>
                <ListItem>
                  <ChakraLink href='#workspace-management' color={linkColor}>
                    Workspace management
                  </ChakraLink>
                  <List
                    spacing={1}
                    pl={4}
                    styleType='circle'
                    mt={1}
                    fontSize='xs'
                  >
                    <ListItem>
                      <ChakraLink
                        href='#workspace-management-workspaces'
                        color={linkColor}
                      >
                        Workspaces
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        href='#workspace-management-transfer'
                        color={linkColor}
                      >
                        Token transfer
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        href='#workspace-management-members'
                        color={linkColor}
                      >
                        Members
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        href='#workspace-management-alert-settings'
                        color={linkColor}
                      >
                        Alert settings & Webhooks
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        href='#workspace-management-audit'
                        color={linkColor}
                      >
                        Audit
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        href='#workspace-management-audit-org'
                        color={linkColor}
                      >
                        Audit & Org usage
                      </ChakraLink>
                    </ListItem>
                  </List>
                </ListItem>
              </List>
            </Box>
          </GridItem>

          {/* Main content */}
          <GridItem
            minW='0'
            sx={{ code: { whiteSpace: 'pre-wrap', wordBreak: 'break-word' } }}
          >
            <VStack align='stretch' spacing={6} w='full'>
              <Heading size='lg'>API Reference</Heading>

              <Box
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Anchor id='quick-start' />
                <Heading size='md' mb={2}>
                  Quick start
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={3}>
                  Authenticate to obtain a session cookie, then call endpoints.
                  All workspace‑scoped operations must include{' '}
                  <Code>workspace_id</Code> either in the path or query/body.
                  Responses use standard pagination with <Code>limit</Code> and
                  <Code>offset</Code> when listing collections.
                </Text>
                <Divider my={4} borderColor={borderColor} />
                <CopyableCodeBlock
                  code={`# Login (creates session cookie)
curl -s -c cookies.txt -X POST <your-backend-url>/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"me@example.com","password":"StrongPass123!"}'

# List workspaces
curl -s -b cookies.txt '<your-backend-url>/api/v1/workspaces?limit=20&offset=0' | jq '.'

# Create a token
curl -s -b cookies.txt -X POST <your-backend-url>/api/tokens \
  -H 'Content-Type: application/json' \
  -d '{"name":"My cert","category":"cert","type":"ssl_cert","expiresAt":"2030-01-01","workspace_id":"00000000-0000-0000-0000-000000000000"}'`}
                />
                <Divider my={4} borderColor={borderColor} />
              </Box>

              {/* Core API */}
              <Box>
                <Anchor id='all-plans' />
                <Heading size='md' mb={4}>
                  Available in TokenTimer Core
                </Heading>
              </Box>

              {/* Authentication */}
              <Box
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Anchor id='all-plans-auth' />
                <Heading
                  as='h3'
                  size='sm'
                  mb={3}
                  display='flex'
                  alignItems='center'
                  gap={2}
                >
                  <Icon as={FiShield} boxSize={4} />
                  Authentication
                </Heading>
                <List
                  spacing={2}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  mb={4}
                >
                  <ListItem>
                    <strong>POST /auth/login</strong> — body: <Code>email</Code>
                    , <Code>password</Code>
                  </ListItem>
                  <ListItem>
                    <strong>POST /auth/register</strong> — create account
                  </ListItem>
                  <ListItem>
                    <strong>GET /api/session</strong> — current session
                  </ListItem>
                  <ListItem>
                    <strong>POST /api/logout</strong> — end session
                  </ListItem>
                </List>
                <CopyableCodeBlock
                  code={`# Check session
curl -s -b cookies.txt <your-backend-url>/api/session | jq '.'

# Logout
curl -s -b cookies.txt -X POST <your-backend-url>/api/logout`}
                />
              </Box>

              {/* Tokens */}
              <Box
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Anchor id='all-plans-tokens' />
                <Heading
                  as='h3'
                  size='sm'
                  mb={3}
                  display='flex'
                  alignItems='center'
                  gap={2}
                >
                  <Icon as={FiKey} boxSize={4} />
                  Tokens
                </Heading>
                <List
                  spacing={2}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  mb={4}
                >
                  <ListItem>
                    <strong>POST /api/tokens</strong> — create token
                    <Box
                      bg={useColorModeValue(
                        'rgba(255, 255, 255, 0.72)',
                        'gray.900'
                      )}
                      border='1px'
                      borderColor={borderColor}
                      borderRadius='md'
                      p={4}
                      mt={3}
                      ml={4}
                    >
                      <Text fontSize='xs' fontWeight='semibold' mb={2}>
                        Required Fields
                      </Text>
                      <List
                        spacing={1}
                        pl={4}
                        styleType='disc'
                        color={bodyColor}
                        fontSize='xs'
                        mb={3}
                      >
                        <ListItem>
                          <Code>workspace_id</Code>, <Code>name</Code> (3-100
                          chars), <Code>category</Code>, <Code>type</Code>
                        </ListItem>
                      </List>
                      <Text fontSize='xs' fontWeight='semibold' mb={2}>
                        Optional Fields
                      </Text>
                      <List
                        spacing={1}
                        pl={4}
                        styleType='disc'
                        color={bodyColor}
                        fontSize='xs'
                        mb={3}
                      >
                        <ListItem>
                          <Code>expiresAt</Code> (defaults to never expires if
                          omitted)
                        </ListItem>
                        <ListItem>
                          <Code>section</Code> (max 120 chars)
                        </ListItem>
                        <ListItem>
                          <Code>contact_group_id</Code>
                        </ListItem>
                        <ListItem>
                          <Code>domains</Code>
                        </ListItem>
                        <ListItem>
                          <Code>location</Code> (max 500 chars)
                        </ListItem>
                        <ListItem>
                          <Code>used_by</Code> (max 500 chars)
                        </ListItem>
                        <ListItem>
                          <Code>description</Code>
                        </ListItem>
                        <ListItem>
                          <Code>notes</Code>
                        </ListItem>
                        <ListItem>
                          <Code>contacts</Code> (max 500 chars)
                        </ListItem>
                        <ListItem>
                          <strong>Certificates:</strong> <Code>issuer</Code>,{' '}
                          <Code>serial_number</Code>, <Code>subject</Code>
                        </ListItem>
                        <ListItem>
                          <strong>Keys & Secrets:</strong> <Code>key_size</Code>
                          , <Code>algorithm</Code>
                        </ListItem>
                        <ListItem>
                          <strong>Licenses:</strong> <Code>license_type</Code>,{' '}
                          <Code>vendor</Code>, <Code>cost</Code>,{' '}
                          <Code>renewal_url</Code>, <Code>renewal_date</Code>
                        </ListItem>
                      </List>
                      <Text fontSize='xs' color={bodyColor} fontStyle='italic'>
                        Note: When a contact group defines{' '}
                        <Code>thresholds</Code> overrides, the token uses those
                        thresholds instead of the workspace defaults.
                      </Text>
                    </Box>
                  </ListItem>
                  <ListItem>
                    <strong>GET /api/tokens</strong> — list. Filters:{' '}
                    <Code>workspace_id</Code> (required for workspace scope),{' '}
                    <Code>section</Code> (string or <Code>__none__</Code> for no
                    section), supports <Code>limit</Code>, <Code>offset</Code>,{' '}
                    <Code>q</Code>, <Code>category</Code>, and <Code>sort</Code>
                    .
                  </ListItem>
                  <ListItem>
                    <strong>PUT /api/tokens/:id</strong> — update
                  </ListItem>
                  <ListItem>
                    <strong>DELETE /api/tokens/:id</strong> — delete
                  </ListItem>
                </List>
                <CopyableCodeBlock
                  code={`# List tokens for a workspace
curl -s -b cookies.txt '<your-backend-url>/api/tokens?workspace_id=00000000-0000-0000-0000-000000000000&limit=50&offset=0' | jq '.'

# Update a token
curl -s -b cookies.txt -X PUT <your-backend-url>/api/tokens/123 \
  -H 'Content-Type: application/json' \
  -d '{"name":"Renewed cert","expiresAt":"2031-01-01"}'`}
                />
                <Text
                  fontSize='sm'
                  color={bodyColor}
                  mt={4}
                  mb={2}
                  fontWeight='semibold'
                >
                  Section filtering examples:
                </Text>
                <CopyableCodeBlock
                  code={`# Filter tokens by section "prod"
curl -s -b cookies.txt '<your-backend-url>/api/tokens?workspace_id=00000000-0000-0000-0000-000000000000&section=prod&limit=50' | jq '.'

# Filter tokens with no section assigned
curl -s -b cookies.txt '<your-backend-url>/api/tokens?workspace_id=00000000-0000-0000-0000-000000000000&section=__none__&limit=50' | jq '.'`}
                />
              </Box>

              {/* Alerts */}
              <Box
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Anchor id='all-plans-alerts' />
                <Heading
                  as='h3'
                  size='sm'
                  mb={3}
                  display='flex'
                  alignItems='center'
                  gap={2}
                >
                  <Icon as={FiBell} boxSize={4} />
                  Alerts
                </Heading>
                <List
                  spacing={2}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  mb={4}
                >
                  <ListItem>
                    <strong>GET /api/alert-queue</strong> — queued alerts
                  </ListItem>
                  <ListItem>
                    <strong>GET /api/alert-stats</strong> — monthly stats (use{' '}
                    <Code>workspace_id</Code>); queue and stats endpoints
                    support pagination with <Code>limit</Code> and{' '}
                    <Code>offset</Code>.
                  </ListItem>
                </List>
                <CopyableCodeBlock
                  code={`# Queue & stats
curl -s -b cookies.txt '<your-backend-url>/api/alert-queue?limit=10&offset=0' | jq '.'
curl -s -b cookies.txt '<your-backend-url>/api/alert-stats?workspace_id=00000000-0000-0000-0000-000000000000' | jq '.'`}
                />
              </Box>

              {/* Usage */}
              <Box
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Anchor id='all-plans-usage' />
                <Heading
                  as='h3'
                  size='sm'
                  mb={3}
                  display='flex'
                  alignItems='center'
                  gap={2}
                >
                  <Icon as={FiUser} boxSize={4} />
                  Usage
                </Heading>
                <List
                  spacing={2}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  mb={4}
                >
                  <ListItem>
                    <strong>GET /api/organization/usage</strong> — organization
                    usage metrics
                  </ListItem>
                </List>
                <CopyableCodeBlock
                  code={`curl -s -b cookies.txt <your-backend-url>/api/organization/usage | jq '.'`}
                />
              </Box>

              {/* Auto-Sync API */}
              <Box
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Anchor id='auto-sync-api' />
                <Heading
                  as='h3'
                  size='sm'
                  mb={3}
                  display='flex'
                  alignItems='center'
                  gap={2}
                >
                  <Icon as={FiRefreshCw} boxSize={4} />
                  Auto-Sync
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={4}>
                  Manage scheduled recurring integration scans. Auto-sync stores
                  encrypted credentials and scan parameters, then runs scans on
                  a configurable schedule. Available for GitHub and GitLab
                  integrations.
                </Text>
                <List
                  spacing={2}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  mb={4}
                >
                  <ListItem>
                    <strong>GET /api/v1/workspaces/:id/auto-sync</strong> — list
                    all auto-sync configurations for the workspace
                  </ListItem>
                  <ListItem>
                    <strong>POST /api/v1/workspaces/:id/auto-sync</strong> —
                    create a new auto-sync configuration. Body:{' '}
                    <Code>{`{ provider, credentials, scan_params, frequency, preferred_time, timezone }`}</Code>
                  </ListItem>
                  <ListItem>
                    <strong>
                      PUT /api/v1/workspaces/:id/auto-sync/:configId
                    </strong>{' '}
                    — update an existing configuration (credentials, frequency,
                    etc.)
                  </ListItem>
                  <ListItem>
                    <strong>
                      DELETE /api/v1/workspaces/:id/auto-sync/:configId
                    </strong>{' '}
                    — delete a configuration (also deletes stored credentials)
                  </ListItem>
                  <ListItem>
                    <strong>
                      POST /api/v1/workspaces/:id/auto-sync/:configId/run
                    </strong>{' '}
                    — manually trigger an immediate sync run
                  </ListItem>
                </List>
                <CopyableCodeBlock
                  code={`# List auto-sync configs
curl -s -b cookies.txt \\
  '<your-backend-url>/api/v1/workspaces/WS_ID/auto-sync' | jq '.'

# Create auto-sync for GitHub
curl -s -b cookies.txt -X POST \\
  '<your-backend-url>/api/v1/workspaces/WS_ID/auto-sync' \\
  -H 'Content-Type: application/json' \\
  -d '{
    "provider": "github",
    "credentials": { "token": "ghp_xxx" },
    "scan_params": { "includeClassicPAT": true, "includeFineGrainedPAT": true },
    "frequency": "daily",
    "preferred_time": "02:00",
    "timezone": "Europe/Zurich"
  }' | jq '.'

# Manually trigger a sync
curl -s -b cookies.txt -X POST \\
  '<your-backend-url>/api/v1/workspaces/WS_ID/auto-sync/CONFIG_ID/run' | jq '.'

# Delete auto-sync config
curl -s -b cookies.txt -X DELETE \\
  '<your-backend-url>/api/v1/workspaces/WS_ID/auto-sync/CONFIG_ID' | jq '.'`}
                />
              </Box>

              {/* Endpoint (SSL) Monitoring API */}
              <Box
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Anchor id='endpoint-monitor-api' />
                <Heading
                  as='h3'
                  size='sm'
                  mb={3}
                  display='flex'
                  alignItems='center'
                  gap={2}
                >
                  <Icon as={FiGlobe} boxSize={4} />
                  Endpoint (SSL) Monitoring
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={4}>
                  Monitor HTTPS endpoints for SSL certificate expiration and
                  health status. Adding an endpoint automatically creates a
                  token tracking the SSL certificate. Health checks run on a
                  configurable interval.
                </Text>
                <List
                  spacing={2}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  mb={4}
                >
                  <ListItem>
                    <strong>GET /api/v1/workspaces/:id/domains</strong> — list
                    all monitored endpoints with SSL info, health status, and
                    response times
                  </ListItem>
                  <ListItem>
                    <strong>POST /api/v1/workspaces/:id/domains</strong> — add a
                    new endpoint. Body:{' '}
                    <Code>{`{ url, health_check_enabled, check_interval, alert_after_failures }`}</Code>
                  </ListItem>
                  <ListItem>
                    <strong>
                      PUT /api/v1/workspaces/:id/domains/:domainId
                    </strong>{' '}
                    — update settings (interval, health check toggle, alert
                    threshold)
                  </ListItem>
                  <ListItem>
                    <strong>
                      DELETE /api/v1/workspaces/:id/domains/:domainId
                    </strong>{' '}
                    — remove an endpoint monitor (does not delete the SSL token)
                  </ListItem>
                  <ListItem>
                    <strong>
                      POST /api/v1/workspaces/:id/domains/:domainId/check
                    </strong>{' '}
                    — trigger a manual health check, returns status, response
                    time, and any error
                  </ListItem>
                </List>
                <Text fontSize='sm' color={bodyColor} mb={2}>
                  <strong>Check intervals:</strong> <Code>1min</Code>,{' '}
                  <Code>5min</Code>, <Code>30min</Code>, <Code>hourly</Code>,{' '}
                  <Code>daily</Code>
                </Text>
                <Text fontSize='sm' color={bodyColor} mb={4}>
                  <strong>alert_after_failures:</strong> Number of consecutive
                  failures before a {'"'}down{'"'} notification is sent
                  (default: 2). See{' '}
                  <ChakraLink
                    href='/docs/alerts#endpoint-health'
                    color={linkColor}
                  >
                    Endpoint Health Alerts
                  </ChakraLink>
                  .
                </Text>
                <CopyableCodeBlock
                  code={`# List monitored endpoints
curl -s -b cookies.txt \\
  '<your-backend-url>/api/v1/workspaces/WS_ID/domains' | jq '.'

# Add an endpoint
curl -s -b cookies.txt -X POST \\
  '<your-backend-url>/api/v1/workspaces/WS_ID/domains' \\
  -H 'Content-Type: application/json' \\
  -d '{
    "url": "https://example.com",
    "health_check_enabled": true,
    "check_interval": "5min",
    "alert_after_failures": 3
  }' | jq '.'

# Manual health check
curl -s -b cookies.txt -X POST \\
  '<your-backend-url>/api/v1/workspaces/WS_ID/domains/DOMAIN_ID/check' | jq '.'

# Delete endpoint monitor
curl -s -b cookies.txt -X DELETE \\
  '<your-backend-url>/api/v1/workspaces/WS_ID/domains/DOMAIN_ID' | jq '.'`}
                />
              </Box>

              {/* Workspace management */}
              <Box>
                <Anchor id='workspace-management' />
                <Heading size='md' mb={4}>
                  Workspace management
                </Heading>
              </Box>

              {/* Workspaces */}
              <Box
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Anchor id='workspace-management-workspaces' />
                <Heading
                  as='h3'
                  size='sm'
                  mb={3}
                  display='flex'
                  alignItems='center'
                  gap={2}
                >
                  <Icon as={FiDatabase} boxSize={4} />
                  Workspaces
                </Heading>
                <List
                  spacing={2}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  mb={4}
                >
                  <ListItem>
                    <strong>POST /api/v1/workspaces</strong> — create
                  </ListItem>
                  <ListItem>
                    <strong>GET /api/v1/workspaces</strong> — list (includes
                    role)
                  </ListItem>
                  <ListItem>
                    <strong>GET /api/v1/workspaces/:id</strong> — details
                  </ListItem>
                  <ListItem>
                    <strong>PATCH /api/v1/workspaces/:id</strong> — rename
                  </ListItem>
                  <ListItem>
                    <strong>DELETE /api/v1/workspaces/:id</strong> — delete
                  </ListItem>
                </List>
                <CopyableCodeBlock
                  code={`# Create workspace
curl -s -b cookies.txt -X POST <your-backend-url>/api/v1/workspaces \
  -H 'Content-Type: application/json' \
  -d '{"name":"Platform","plan":"oss"}' | jq '.'`}
                />
              </Box>

              {/* Token Transfer */}
              <Box
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Anchor id='workspace-management-transfer' />
                <Heading
                  as='h3'
                  size='sm'
                  mb={3}
                  display='flex'
                  alignItems='center'
                  gap={2}
                >
                  <Icon as={FiRefreshCw} boxSize={4} />
                  Token Transfer
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={4}>
                  Move tokens across workspaces. Requires admin role on both
                  workspaces, or workspace_manager on both with at least two
                  workspaces attributed.
                </Text>
                <List
                  spacing={2}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  mb={4}
                >
                  <ListItem>
                    <strong>POST /api/v1/workspaces/:id/transfer-tokens</strong>{' '}
                    — body:{' '}
                    {`{ from_workspace_id: string, token_ids: number[] }`}
                  </ListItem>
                </List>
                <CopyableCodeBlock
                  code={`# Transfer selected tokens from one workspace to another
curl -s -b cookies.txt -X POST <your-backend-url>/api/v1/workspaces/11111111-1111-1111-1111-111111111111/transfer-tokens \
  -H 'Content-Type: application/json' \
  -d '{
    "from_workspace_id":"00000000-0000-0000-0000-000000000000",
    "token_ids":[101,102,103]
  }' | jq '.'`}
                />
              </Box>

              {/* Members */}
              <Box
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Anchor id='workspace-management-members' />
                <Heading
                  as='h3'
                  size='sm'
                  mb={3}
                  display='flex'
                  alignItems='center'
                  gap={2}
                >
                  <Icon as={FiUsers} boxSize={4} />
                  Members
                </Heading>
                <List
                  spacing={2}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  mb={4}
                >
                  <ListItem>
                    <strong>GET /api/v1/workspaces/:id/members</strong> — list
                  </ListItem>
                  <ListItem>
                    <strong>POST /api/v1/workspaces/:id/members</strong> —
                    invite {`{ email, role }`}
                  </ListItem>
                  <ListItem>
                    <strong>
                      PATCH /api/v1/workspaces/:id/members/:userId
                    </strong>{' '}
                    — change role
                  </ListItem>
                  <ListItem>
                    <strong>
                      DELETE /api/v1/workspaces/:id/members/:userId
                    </strong>{' '}
                    — remove
                  </ListItem>
                  <ListItem>
                    <strong>GET /api/v1/workspaces/:id/invitations</strong> —
                    list pending (unaccepted) invitations. Never returns the
                    invitation token.
                  </ListItem>
                  <ListItem>
                    <strong>
                      DELETE /api/v1/workspaces/:id/invitations/:invitationId
                    </strong>{' '}
                    — cancel a pending invitation (manager+). Responds 204 on
                    success and emits an INVITATION_CANCELLED audit event.
                  </ListItem>
                </List>
                <CopyableCodeBlock
                  code={`# Invite member (manager+)
curl -s -b cookies.txt -X POST <your-backend-url>/api/v1/workspaces/00000000-0000-0000-0000-000000000000/members \
  -H 'Content-Type: application/json' \
  -d '{"email":"teammate@example.com","role":"viewer"}' | jq '.'

# List pending invitations
curl -s -b cookies.txt <your-backend-url>/api/v1/workspaces/00000000-0000-0000-0000-000000000000/invitations | jq '.'

# Cancel a pending invitation (manager+)
curl -s -b cookies.txt -X DELETE <your-backend-url>/api/v1/workspaces/00000000-0000-0000-0000-000000000000/invitations/<invitation-id>`}
                />
              </Box>

              {/* Alert Settings & Webhooks */}
              <Box
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Anchor id='workspace-management-alert-settings' />
                <Heading
                  as='h3'
                  size='sm'
                  mb={3}
                  display='flex'
                  alignItems='center'
                  gap={2}
                >
                  <Icon as={FiSettings} boxSize={4} />
                  <Box as='span'>
                    Workspace Alert Settings{' '}
                    <span style={{ fontFamily: 'Montserrat' }}>&</span> Webhooks
                  </Box>
                </Heading>
                <List
                  spacing={2}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  mb={4}
                >
                  <ListItem>
                    <strong>GET /api/v1/workspaces/:id/alert-settings</strong> —
                    get settings
                  </ListItem>
                  <ListItem>
                    <strong>PUT /api/v1/workspaces/:id/alert-settings</strong> —
                    update settings
                  </ListItem>
                  <ListItem>
                    <strong>POST /api/test-webhook</strong> — send test message
                    (Slack, Discord, Teams, PagerDuty, Generic)
                  </ListItem>
                </List>
                <CopyableCodeBlock
                  code={`# Get alert settings (includes contact groups)
curl -s -b cookies.txt <your-backend-url>/api/v1/workspaces/00000000-0000-0000-0000-000000000000/alert-settings | jq '.'

# Example PUT payload (per-contact channels)
curl -s -b cookies.txt -X PUT <your-backend-url>/api/v1/workspaces/00000000-0000-0000-0000-000000000000/alert-settings \
  -H 'Content-Type: application/json' \
  -d '{
    "alert_thresholds": [30,14,7,1,0],
    "webhook_urls": [
      {"name":"On-call Slack","url":"https://hooks.slack.com/services/...","kind":"slack"}
    ],
    "email_alerts_enabled": true,
    "whatsapp_alerts_enabled": true,
    "delivery_window_start": "00:00",
    "delivery_window_end": "23:59",
    "delivery_window_tz": "UTC",
    "contact_groups": [
      {"id":"ops","name":"Ops Team","email_contact_ids":["uuid-1"],"whatsapp_contact_ids":["uuid-1","uuid-2"],"thresholds":[10,5],"webhook_names":["On-call Slack","Incident Discord"]},
      {"id":"finance","name":"Finance","email_contact_ids":["uuid-3"],"whatsapp_contact_ids":[]}
    ],
    "default_contact_group_id": "ops"
  }' | jq '.'

# Token create with contact group
curl -s -b cookies.txt -X POST <your-backend-url>/api/tokens \
  -H 'Content-Type: application/json' \
  -d '{
    "workspace_id":"00000000-0000-0000-0000-000000000000",
    "name":"API Key",
    "type":"api_key",
    "category":"key_secret",
    "expiresAt":"2026-01-01",
    "contact_group_id":"ops"
  }' | jq '.'`}
                />
                <Text
                  fontSize='sm'
                  color={bodyColor}
                  mt={4}
                  mb={2}
                  fontWeight='semibold'
                >
                  Test webhook:
                </Text>
                <CopyableCodeBlock
                  code={`# Test Slack webhook
curl -s -b cookies.txt -X POST <your-backend-url>/api/test-webhook \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://hooks.slack.com/services/...","kind":"slack"}' | jq '.'`}
                />
              </Box>

              {/* Audit */}
              <Box
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Anchor id='workspace-management-audit' />
                <Heading
                  as='h3'
                  size='sm'
                  mb={3}
                  display='flex'
                  alignItems='center'
                  gap={2}
                >
                  <Icon as={FiFileText} boxSize={4} />
                  Audit
                </Heading>
                <List
                  spacing={2}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  mb={4}
                >
                  <ListItem>
                    <strong>GET /api/audit-events</strong> — latest events for
                    current user
                  </ListItem>
                </List>
                <CopyableCodeBlock
                  code={`curl -s -b cookies.txt '<your-backend-url>/api/audit-events?limit=50&offset=0' | jq '.'`}
                />
              </Box>

              {/* Audit & Organization Usage */}
              <Box
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Anchor id='workspace-management-audit-org' />
                <Heading
                  as='h3'
                  size='sm'
                  mb={3}
                  display='flex'
                  alignItems='center'
                  gap={2}
                >
                  <Icon as={FiFileText} boxSize={4} />
                  <Box as='span'>
                    Audit <span style={{ fontFamily: 'Montserrat' }}>&</span>{' '}
                    Organization Usage
                  </Box>
                </Heading>
                <List
                  spacing={2}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                  mb={4}
                >
                  <ListItem>
                    <strong>GET /api/v1/workspaces/:id/audit-events</strong> —
                    workspace scope (manager/admin)
                  </ListItem>
                  <ListItem>
                    <strong>GET /api/audit-events?scope=organization</strong> —
                    organization scope (admin)
                  </ListItem>
                  <ListItem>
                    <strong>GET /api/organization/usage</strong> — aggregated
                    metrics (admin)
                  </ListItem>
                </List>
                <CopyableCodeBlock
                  code={`# Workspace scope
curl -s -b cookies.txt '<your-backend-url>/api/v1/workspaces/00000000-0000-0000-0000-000000000000/audit-events?limit=50' | jq '.'

# Organization scope (admin)
curl -s -b cookies.txt '<your-backend-url>/api/audit-events?scope=organization&limit=50' | jq '.'

# Organization usage (admin)
curl -s -b cookies.txt <your-backend-url>/api/organization/usage | jq '.'`}
                />
              </Box>
            </VStack>
          </GridItem>

          {/* Right spacer to center main content */}
          <GridItem display={{ base: 'none', lg: 'block' }} />
        </Grid>
      </Container>
    </>
  );
}
