import {
  Box,
  Heading,
  Text,
  VStack,
  List,
  ListItem,
  Link as ChakraLink,
  Code,
  useColorModeValue,
  Grid,
  GridItem,
  Button,
  Divider,
  Badge,
  Accordion,
  AccordionItem,
  AccordionButton,
  AccordionPanel,
  AccordionIcon,
  Alert,
  AlertIcon,
  Flex,
  Image,
} from '@chakra-ui/react';
import { FiArrowLeft } from 'react-icons/fi';
import { useNavigate } from 'react-router-dom';
import { AccessibleButton } from '../components/Accessibility';
import CopyableCodeBlock from '../components/CopyableCodeBlock.jsx';

import SEO from '../components/SEO.jsx';

export default function DocsTokens() {
  const navigate = useNavigate();
  const cardBg = useColorModeValue('rgba(255, 255, 255, 0.95)', 'gray.800');
  const borderColor = useColorModeValue('gray.400', 'gray.600');
  const bodyColor = useColorModeValue('gray.800', 'gray.300');
  const linkColor = useColorModeValue('gray.900', 'blue.300');
  const primaryHoverBg = useColorModeValue('primary.50', 'primary.900');
  const textColor = useColorModeValue('gray.900', 'gray.100');

  return (
    <>
      <SEO
        title='Docs – Tokens'
        description='Learn how TokenTimer models tokens, fields, categories, and workspace scoping.'
      />

      <Box
        maxW='1200px'
        mx='auto'
        px={{ base: 4, md: 6 }}
        pt={{ base: 12, md: 10 }}
        pb={{ base: 6, md: 10 }}
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
              <List spacing={2} styleType='none' pl={0}>
                <ListItem>
                  <ChakraLink
                    href='#overview'
                    fontWeight='medium'
                    color={linkColor}
                  >
                    Overview
                  </ChakraLink>
                </ListItem>
                <ListItem>
                  <ChakraLink
                    href='#fields'
                    fontWeight='medium'
                    color={linkColor}
                  >
                    Fields & categories
                  </ChakraLink>
                </ListItem>
                <ListItem>
                  <ChakraLink
                    href='#scoping'
                    fontWeight='medium'
                    color={linkColor}
                  >
                    Workspace scoping
                  </ChakraLink>
                </ListItem>
                <ListItem mt={3}>
                  <ChakraLink
                    href='#import'
                    fontWeight='semibold'
                    color={linkColor}
                  >
                    Import tokens
                  </ChakraLink>
                  <List
                    spacing={1}
                    pl={4}
                    styleType='none'
                    mt={1}
                    fontSize='sm'
                  >
                    <ListItem>
                      <ChakraLink href='#import-integrations' color={linkColor}>
                        Platform Integrations
                      </ChakraLink>
                    </ListItem>
                    <ListItem pl={3}>
                      <ChakraLink href='#import-hashicorp' color={linkColor}>
                        • Vault (HashiCorp)
                      </ChakraLink>
                    </ListItem>
                    <ListItem pl={3}>
                      <ChakraLink href='#import-gitlab' color={linkColor}>
                        • GitLab
                      </ChakraLink>
                    </ListItem>
                    <ListItem pl={3}>
                      <ChakraLink href='#import-github' color={linkColor}>
                        • GitHub
                      </ChakraLink>
                    </ListItem>
                    <ListItem pl={3}>
                      <ChakraLink href='#import-aws' color={linkColor}>
                        • AWS
                      </ChakraLink>
                    </ListItem>
                    <ListItem pl={3}>
                      <ChakraLink href='#import-azure' color={linkColor}>
                        • Azure KV
                      </ChakraLink>
                    </ListItem>
                    <ListItem pl={3}>
                      <ChakraLink href='#import-azure-ad' color={linkColor}>
                        • Azure AD
                      </ChakraLink>
                    </ListItem>
                    <ListItem pl={3}>
                      <ChakraLink href='#import-gcp' color={linkColor}>
                        • GCP
                      </ChakraLink>
                    </ListItem>
                    <ListItem mt={1}>
                      <ChakraLink href='#import-file' color={linkColor}>
                        File Import
                      </ChakraLink>
                    </ListItem>
                  </List>
                </ListItem>
                <ListItem>
                  <ChakraLink
                    href='#endpoint-monitoring'
                    fontWeight='medium'
                    color={linkColor}
                  >
                    Endpoint & SSL monitoring
                  </ChakraLink>
                </ListItem>
              </List>
            </Box>
          </GridItem>

          <GridItem>
            <VStack align='stretch' spacing={6} w='full' minW={0}>
              <Heading size='lg'>Tokens</Heading>

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
                  Tokens represent any asset with an expiration date that you
                  cannot afford to miss (for example: certificates, API keys,
                  secrets, contracts, licenses, memberships). Each token lives
                  inside a specific workspace. Alerts use the workspace defaults
                  (thresholds and enabled channels). Recipients and, optionally,
                  thresholds can be overridden per token by selecting a contact
                  group.
                </Text>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    <strong>Lifecycle</strong>: create the token with an
                    expiration date, TokenTimer tracks status and sends alerts
                    as thresholds are reached, then marks it expired if the date
                    passes.
                  </ListItem>
                  <ListItem>
                    <strong>Visibility</strong>: color‑coded status in the
                    dashboard and usage views to prioritize renewals.
                  </ListItem>
                  <ListItem>
                    <strong>Ownership</strong>: who receives alerts comes from
                    the token{"'"}s <em>contact group</em>. By default, the
                    workspace{"'"}s initial contact group is used (owner{"'"}s
                    email).
                  </ListItem>
                </List>
              </Box>

              <Box
                id='fields'
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={2}>
                  Fields <span style={{ fontFamily: 'Montserrat' }}>&</span>{' '}
                  categories
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={4}>
                  Every token needs a name, category, and type. You can also add
                  an expiration date, organize tokens into sections, and include
                  additional details to help you manage them better.
                </Text>

                <Text
                  fontSize='sm'
                  fontWeight='semibold'
                  color={bodyColor}
                  mb={2}
                >
                  What you need to provide:
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
                    <strong>Name</strong> — A descriptive name for your token
                    (3-100 characters)
                  </ListItem>
                  <ListItem>
                    <strong>Category</strong> — Choose from: Certificates, Keys
                    & Secrets, Licenses, or General
                  </ListItem>
                  <ListItem>
                    <strong>Type</strong> — The specific type within the
                    category (e.g., SSL certificate, API key, software license)
                  </ListItem>
                </List>

                <Text
                  fontSize='sm'
                  fontWeight='semibold'
                  color={bodyColor}
                  mb={2}
                >
                  Additional information you can add:
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
                    <strong>Expiration date</strong> — When the token expires
                    (if left empty, it will be marked as {'"'}never expires{'"'}
                    )
                  </ListItem>
                  <ListItem>
                    <strong>Section</strong> — Group related tokens together
                    (e.g., {'"'}Production{'"'}, {'"'}Development{'"'})
                  </ListItem>
                  <ListItem>
                    <strong>Description & Notes</strong> — Add any helpful
                    context or reminders
                  </ListItem>
                  <ListItem>
                    <strong>Contacts</strong> — People to notify about this
                    token
                  </ListItem>
                </List>

                <Text
                  fontSize='sm'
                  fontWeight='semibold'
                  color={bodyColor}
                  mb={2}
                >
                  Category-specific details:
                </Text>
                <List
                  spacing={2}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    <strong>Certificates</strong> — Add domains, issuer
                    information, and certificate details
                  </ListItem>
                  <ListItem>
                    <strong>Keys & Secrets</strong> — Include where they{"'"}re
                    stored and rotation instructions
                  </ListItem>
                  <ListItem>
                    <strong>Licenses</strong> — Add vendor name, number of
                    seats, renewal dates, and costs
                  </ListItem>
                </List>
              </Box>

              <Box
                id='scoping'
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={2}>
                  Workspace scoping
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={3}>
                  Default thresholds and channels are configured at the
                  workspace level. Recipients and (optionally) thresholds may be
                  overridden by assigning a token to a contact group. Role‑based
                  access means only members of the workspace can view or manage
                  its tokens.
                </Text>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    Changing <em>workspace default</em> thresholds affects
                    tokens that do not use a group thresholds override.
                  </ListItem>
                  <ListItem>
                    Use sections to reflect environments or teams (e.g.,
                    Production vs. Staging) and filter views.
                  </ListItem>
                  <ListItem>
                    Assign a contact group to route alerts to a team and, if
                    needed, apply a different thresholds policy.
                  </ListItem>
                </List>
              </Box>

              <Box
                id='import'
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={3}>
                  Import tokens
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={4}>
                  Import tokens directly from secret management platforms
                  (Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret
                  Manager), source control systems (GitLab, GitHub), or from
                  files (CSV, XLSX, JSON, YAML).
                </Text>

                <Box
                  bg={useColorModeValue('blue.50', 'blue.900')}
                  border='1px solid'
                  borderColor={useColorModeValue('blue.400', 'blue.700')}
                  borderRadius='md'
                  p={4}
                  mb={6}
                >
                  <Heading size='xs' mb={3}>
                    🔒 Security{' '}
                    <span style={{ fontFamily: 'Montserrat' }}>&</span> Privacy
                  </Heading>
                  <List
                    spacing={2}
                    pl={4}
                    styleType='disc'
                    color={bodyColor}
                    fontSize='sm'
                  >
                    <ListItem>
                      <strong>One-time use:</strong> All credentials are used
                      only once for scanning and are never stored
                    </ListItem>
                    <ListItem>
                      <strong>Metadata only:</strong> We retrieve only metadata
                      (names, expiration dates, locations) — no secret values,
                      private keys, or sensitive data
                    </ListItem>
                    <ListItem>
                      <strong>Your control:</strong> You provide credentials at
                      scan time. After scanning, credentials are immediately
                      discarded
                    </ListItem>
                    <ListItem>
                      <strong>Best practice:</strong> Create temporary
                      credentials with minimal permissions and revoke them after
                      use
                    </ListItem>
                  </List>
                </Box>

                <Divider my={5} />

                <Heading id='import-integrations' size='sm' mb={4} mt={6}>
                  Platform Integrations
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={4}>
                  Connect directly to secret management platforms, source
                  control systems, and cloud providers to automatically discover
                  expiring credentials, certificates, and keys.
                </Text>

                <Box
                  bg={useColorModeValue('blue.50', 'blue.900')}
                  border='1px'
                  borderColor={useColorModeValue('blue.400', 'blue.700')}
                  borderRadius='md'
                  p={4}
                  mb={4}
                >
                  <Text
                    fontSize='sm'
                    color={bodyColor}
                    fontWeight='semibold'
                    mb={2}
                  >
                    ℹ️ About Expiration Dates
                  </Text>
                  <Text fontSize='sm' color={bodyColor}>
                    Some platforms don{"'"}t expose expiration dates for certain
                    token types (e.g., GitHub SSH keys, AWS IAM access keys).
                    These tokens will be imported with an expiration date of{' '}
                    <Code>2099-12-31</Code> and displayed as{' '}
                    <Badge colorScheme='blue' fontSize='xs'>
                      Never expires
                    </Badge>{' '}
                    throughout the dashboard. You can manually update their
                    expiration dates if needed.
                  </Text>
                </Box>

                <Box
                  bg={useColorModeValue('yellow.50', 'yellow.900')}
                  border='1px'
                  borderColor={useColorModeValue('yellow.400', 'yellow.700')}
                  borderRadius='md'
                  p={4}
                  mb={4}
                >
                  <Text
                    fontSize='sm'
                    color={bodyColor}
                    fontWeight='semibold'
                    mb={2}
                  >
                    🌐 IP Whitelisting for Self-Hosted Integrations
                  </Text>
                  <Text fontSize='sm' color={bodyColor} mb={3}>
                    If your self-hosted GitLab, GitHub Enterprise, or other
                    services require IP whitelisting, add the following IP
                    address to your allowlist:
                  </Text>
                  <CopyableCodeBlock code='83.228.200.37' />
                  <Text fontSize='xs' color={bodyColor} mt={2}>
                    This is the static egress IP used by TokenTimer when
                    connecting to your self-hosted integration endpoints.
                  </Text>
                </Box>

                <Box
                  bg={useColorModeValue('green.50', 'green.900')}
                  border='1px'
                  borderColor={useColorModeValue('green.400', 'green.700')}
                  borderRadius='md'
                  p={4}
                  mb={4}
                >
                  <Text
                    fontSize='sm'
                    color={bodyColor}
                    fontWeight='semibold'
                    mb={2}
                  >
                    🔄 Automatic Deduplication
                  </Text>
                  <Text fontSize='sm' color={bodyColor} mb={2}>
                    When importing tokens, the system automatically prevents
                    duplicates by matching on both <strong>name</strong> and{' '}
                    <strong>location</strong>. If you import the same token
                    again (same name + same location), it will update the
                    existing token with new characteristics instead of creating
                    a duplicate.
                  </Text>
                  <List
                    spacing={1}
                    pl={4}
                    styleType='disc'
                    color={bodyColor}
                    fontSize='sm'
                  >
                    <ListItem>
                      <strong>Example:</strong> Import {'"'}Database Password
                      {'"'} from{' '}
                      <Code>
                        aws:secretsmanager:us-east-1:arn:.../db-password
                      </Code>{' '}
                      on Day 1, then import it again on Day 2 with updated
                      expiration date → The existing token is updated, not
                      duplicated
                    </ListItem>
                    <ListItem>
                      <strong>Different tokens:</strong> Tokens with the same
                      location but different names are treated as separate
                      tokens (e.g., {'"'}Production API Key{'"'} vs {'"'}Staging
                      API Key{'"'} at the same path)
                    </ListItem>
                    <ListItem>
                      <strong>File imports:</strong> For CSV/XLSX/JSON imports,
                      include a <Code>location</Code> column for reliable
                      deduplication
                    </ListItem>
                    <ListItem>
                      <strong>Alert catch-up:</strong> When importing tokens,
                      alerts for thresholds that have already passed (stale
                      alerts) are suppressed to prevent immediate notification
                      storms. Alerts will resume naturally as the next future
                      threshold is reached.
                    </ListItem>
                  </List>
                </Box>

                <Heading
                  id='import-hashicorp'
                  size='sm'
                  mb={3}
                  display='flex'
                  alignItems='center'
                  gap={2}
                >
                  HashiCorp Vault
                  <Badge colorScheme='purple' fontSize='xs'>
                    REST API
                  </Badge>
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={4}>
                  Scan KV v2 and PKI mounts to discover secrets and certificates
                  with expiration dates. No SDK required.
                </Text>

                <Accordion allowMultiple defaultIndex={[]} mb={4}>
                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                    mb={2}
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        📋 Credential Setup
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <List
                        spacing={1}
                        pl={4}
                        styleType='decimal'
                        color={bodyColor}
                        fontSize='sm'
                      >
                        <ListItem>
                          Go to Vault UI → <strong>Access</strong> →{' '}
                          <strong>Tokens</strong> →{' '}
                          <strong>Create Token</strong>
                        </ListItem>
                        <ListItem>
                          Set policies: <Code>read</Code> on KV v2 mounts and{' '}
                          <Code>read</Code> on PKI mounts
                        </ListItem>
                        <ListItem>
                          Set TTL (recommended: 1-7 days for one-time use)
                        </ListItem>
                        <ListItem>
                          Copy the token immediately (won{"'"}t be shown again)
                        </ListItem>
                        <ListItem>
                          <Text as='span' color='red.500' fontWeight='semibold'>
                            Revoke after use
                          </Text>{' '}
                          — token is used once and never stored
                        </ListItem>
                      </List>
                    </AccordionPanel>
                  </AccordionItem>

                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                    mb={2}
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        🔐 Permissions Required
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <List
                        spacing={1}
                        pl={4}
                        styleType='disc'
                        color={bodyColor}
                        fontSize='sm'
                      >
                        <ListItem>
                          <Code>read</Code> + <Code>list</Code> on KV v2 mount
                          paths and metadata paths
                        </ListItem>
                        <ListItem>
                          <Code>read</Code> + <Code>list</Code> on PKI mounts
                        </ListItem>
                        <ListItem>
                          <Text as='span' fontStyle='italic'>
                            We only read metadata and certificate contents (for
                            expiration parsing). No secret values are stored.
                          </Text>
                        </ListItem>
                      </List>
                    </AccordionPanel>
                  </AccordionItem>

                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        📦 What We Discover
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <List
                        spacing={2}
                        pl={4}
                        styleType='none'
                        color={bodyColor}
                        fontSize='sm'
                      >
                        <ListItem>
                          <Text fontWeight='semibold'>KV v2 Secrets:</Text>
                          <Text fontSize='xs' ml={2}>
                            Path, name, expiration (if present), auto-detected
                            category/type
                          </Text>
                        </ListItem>
                        <ListItem>
                          <Text fontWeight='semibold'>PKI Certificates:</Text>
                          <Text fontSize='xs' ml={2}>
                            Serial, subject, issuer, expiration (notAfter)
                          </Text>
                        </ListItem>
                        <ListItem fontSize='xs' fontStyle='italic' mt={2}>
                          Supports PEM and base64 DER formats. Smart heuristics
                          auto-map types (e.g., certs → ssl_cert, API keys →
                          api_key).
                        </ListItem>
                      </List>
                    </AccordionPanel>
                  </AccordionItem>
                </Accordion>

                <Text fontSize='xs' color={bodyColor} mt={3}>
                  <strong>Vault URL:</strong>{' '}
                  <Code>https://vault.example.com:8200</Code>
                </Text>

                <Box
                  borderTop='2px solid'
                  borderColor={borderColor}
                  opacity={0.3}
                  my={6}
                />

                <Heading
                  id='import-gitlab'
                  size='sm'
                  mb={3}
                  display='flex'
                  alignItems='center'
                  gap={2}
                >
                  GitLab
                  <Badge colorScheme='orange' fontSize='xs'>
                    REST API v4
                  </Badge>
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={4}>
                  Discover Personal Access Tokens, Project Access Tokens, Group
                  Access Tokens, Deploy Tokens, and SSH keys across your GitLab
                  instance. Configure scan filters to focus on service accounts
                  or specific token types.
                </Text>

                <Accordion allowMultiple defaultIndex={[]} mb={4}>
                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                    mb={2}
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        📋 Credential Setup
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <List
                        spacing={1}
                        pl={4}
                        styleType='decimal'
                        color={bodyColor}
                        fontSize='sm'
                      >
                        <ListItem>
                          Go to GitLab → <strong>User Settings</strong> →{' '}
                          <strong>Access Tokens</strong>
                        </ListItem>
                        <ListItem>
                          Create a new Personal Access Token with{' '}
                          <Code>read_api</Code> scope
                        </ListItem>
                        <ListItem>
                          Set expiration date (recommended: 1-7 days)
                        </ListItem>
                        <ListItem>
                          Copy token immediately (won{"'"}t be shown again)
                        </ListItem>
                        <ListItem>
                          <Text as='span' color='red.500' fontWeight='semibold'>
                            Revoke after use
                          </Text>{' '}
                          — token is used once and never stored
                        </ListItem>
                      </List>
                    </AccordionPanel>
                  </AccordionItem>

                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                    mb={2}
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        🔐 Permissions Required
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <Text
                        fontSize='xs'
                        fontWeight='semibold'
                        mb={2}
                        color={bodyColor}
                      >
                        Token Scope:
                      </Text>
                      <Alert
                        status='success'
                        fontSize='xs'
                        borderRadius='md'
                        mb={3}
                      >
                        <AlertIcon boxSize='12px' />
                        <Text as='span'>
                          The <Code fontSize='xs'>read_api</Code> scope is
                          required and sufficient for all scans, including when
                          using admin accounts. No additional permissions
                          needed.
                        </Text>
                      </Alert>

                      <Text
                        fontSize='xs'
                        fontWeight='semibold'
                        mb={2}
                        color={bodyColor}
                      >
                        What You Can Scan:
                      </Text>
                      <Box pl={4} mb={3}>
                        <Text
                          fontSize='xs'
                          fontWeight='semibold'
                          color='blue.500'
                          mb={1}
                        >
                          👤 Regular User
                        </Text>
                        <List
                          spacing={1}
                          pl={4}
                          styleType='disc'
                          color={bodyColor}
                          fontSize='xs'
                          mb={2}
                        >
                          <ListItem>
                            Your own personal access tokens and SSH keys
                          </ListItem>
                          <ListItem>
                            Projects where you are Maintainer/Owner (for project
                            access tokens and deploy tokens)
                          </ListItem>
                          <ListItem>
                            Groups where you are Maintainer/Owner (for group
                            access tokens)
                          </ListItem>
                          <ListItem>
                            <strong>Best for:</strong> Individual users, team
                            members, GitLab.com
                          </ListItem>
                        </List>

                        <Text
                          fontSize='xs'
                          fontWeight='semibold'
                          color='orange.500'
                          mb={1}
                        >
                          🔑 Admin User (Self-hosted)
                        </Text>
                        <List
                          spacing={1}
                          pl={4}
                          styleType='disc'
                          color={bodyColor}
                          fontSize='xs'
                        >
                          <ListItem>
                            <strong>ALL personal access tokens</strong> across
                            the entire instance (all users)
                          </ListItem>
                          <ListItem>
                            ALL project access tokens and group access tokens
                            you have access to
                          </ListItem>
                          <ListItem>
                            ALL deploy tokens in accessible projects
                          </ListItem>
                          <ListItem>Your own SSH keys</ListItem>
                          <ListItem>
                            <strong>Best for:</strong> Security teams conducting
                            instance-wide token audits
                          </ListItem>
                          <ListItem>
                            <strong>Note:</strong> Admin accounts still use{' '}
                            <Code>read_api</Code> scope - the broader access
                            comes from admin role, not token scope
                          </ListItem>
                        </List>
                      </Box>
                    </AccordionPanel>
                  </AccordionItem>

                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                    mb={2}
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        🎯 Scan Filters
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <Text fontSize='xs' color={bodyColor} mb={2}>
                        Configure which credentials to scan:
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
                          <strong>Token Types:</strong> Select Personal Access
                          Tokens, Project Access Tokens, Group Access Tokens,
                          Deploy Tokens, or SSH Keys
                        </ListItem>
                        <ListItem>
                          <strong>Exclude users Personal Access Tokens:</strong>{' '}
                          Filter out individual user PATs and keep only service
                          account tokens (enabled by default)
                        </ListItem>
                        <ListItem>
                          <strong>Include expired tokens:</strong> Optionally
                          scan tokens that have already expired
                        </ListItem>
                        <ListItem>
                          <strong>Include revoked tokens:</strong> Optionally
                          scan revoked PATs (admin only)
                        </ListItem>
                      </List>
                      <Alert status='info' fontSize='xs' borderRadius='md'>
                        <AlertIcon boxSize='12px' />
                        By default, only active service account tokens are
                        scanned. User PATs are excluded to focus on automation
                        credentials.
                      </Alert>
                    </AccordionPanel>
                  </AccordionItem>

                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        📦 What We Discover
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <List
                        spacing={2}
                        pl={4}
                        styleType='none'
                        color={bodyColor}
                        fontSize='sm'
                      >
                        <ListItem>
                          <Text fontWeight='semibold'>
                            Personal Access Tokens:
                          </Text>
                          <Text fontSize='xs' ml={2}>
                            Name, owner (admin scan), expiration, scopes, last
                            used, creation date
                          </Text>
                        </ListItem>
                        <ListItem>
                          <Text fontWeight='semibold'>
                            Project Access Tokens:
                          </Text>
                          <Text fontSize='xs' ml={2}>
                            Name, project, service account username, expiration,
                            scopes, last used, creation date
                          </Text>
                        </ListItem>
                        <ListItem>
                          <Text fontWeight='semibold'>
                            Group Access Tokens:
                          </Text>
                          <Text fontSize='xs' ml={2}>
                            Name, group, service account username, expiration,
                            scopes, last used, creation date (GitLab 14.7+)
                          </Text>
                        </ListItem>
                        <ListItem>
                          <Text fontWeight='semibold'>Deploy Tokens:</Text>
                          <Text fontSize='xs' ml={2}>
                            Name, project, expiration, scopes, last used,
                            creation date
                          </Text>
                        </ListItem>
                        <ListItem>
                          <Text fontWeight='semibold'>SSH Keys:</Text>
                          <Text fontSize='xs' ml={2}>
                            Title, expiration (if set), last used, creation date
                          </Text>
                        </ListItem>
                        <ListItem fontSize='xs' fontStyle='italic' mt={2}>
                          Metadata only — no actual token values or private keys
                          retrieved.
                        </ListItem>
                      </List>
                    </AccordionPanel>
                  </AccordionItem>
                </Accordion>

                <Text fontSize='xs' color={bodyColor} mt={3}>
                  <strong>Supported:</strong> gitlab.com or self-hosted GitLab
                </Text>

                <Box
                  borderTop='2px solid'
                  borderColor={borderColor}
                  opacity={0.3}
                  my={6}
                />

                <Heading
                  id='import-github'
                  size='sm'
                  mb={3}
                  display='flex'
                  alignItems='center'
                  gap={2}
                >
                  GitHub
                  <Badge colorScheme='gray' fontSize='xs'>
                    REST API v3
                  </Badge>
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={4}>
                  Discover repository secrets, deploy keys, and SSH keys across
                  your GitHub repositories.
                </Text>

                <Accordion allowMultiple defaultIndex={[]} mb={4}>
                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                    mb={2}
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        📋 Credential Setup
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <Text
                        fontSize='xs'
                        fontWeight='bold'
                        mb={2}
                        color={bodyColor}
                      >
                        Classic Token:
                      </Text>
                      <List
                        spacing={1}
                        pl={4}
                        styleType='decimal'
                        color={bodyColor}
                        fontSize='sm'
                        mb={4}
                      >
                        <ListItem>
                          Go to{' '}
                          <ChakraLink
                            href='https://github.com/settings/tokens/new'
                            color='blue.500'
                            textDecoration='underline'
                            isExternal
                          >
                            github.com/settings/tokens/new
                          </ChakraLink>
                          <br />
                          <Text as='span' fontSize='xs' color='gray.500'>
                            (Or: GitHub Settings → Developer Settings → Personal
                            access tokens → Tokens (classic))
                          </Text>
                        </ListItem>
                        <ListItem>
                          Select <Code>repo</Code> scope (full repository
                          access)
                        </ListItem>
                        <ListItem>
                          Optional: <Code>read:public_key</Code> or{' '}
                          <Code>admin:public_key</Code> (required only if
                          scanning user SSH keys)
                        </ListItem>
                        <ListItem>
                          Click {'"'}Generate token{'"'}
                        </ListItem>
                      </List>

                      <Text
                        fontSize='xs'
                        fontWeight='bold'
                        mb={2}
                        color={bodyColor}
                      >
                        Fine-grained Token (Recommended):
                      </Text>
                      <List
                        spacing={1}
                        pl={4}
                        styleType='decimal'
                        color={bodyColor}
                        fontSize='sm'
                      >
                        <ListItem>
                          Go to{' '}
                          <ChakraLink
                            href='https://github.com/settings/personal-access-tokens/new'
                            color='blue.500'
                            textDecoration='underline'
                            isExternal
                          >
                            github.com/settings/personal-access-tokens/new
                          </ChakraLink>
                          <br />
                          <Text as='span' fontSize='xs' color='gray.500'>
                            (Or: GitHub Settings → Developer Settings →
                            Fine-grained tokens)
                          </Text>
                        </ListItem>
                        <ListItem>
                          Select repositories you want to scan
                        </ListItem>
                        <ListItem>
                          <strong>Repository permissions (required):</strong>
                          <List
                            spacing={1}
                            pl={4}
                            styleType='disc'
                            mt={1}
                            fontSize='xs'
                          >
                            <ListItem>
                              <Code>Secrets</Code>: Read-only (for repository
                              secrets)
                            </ListItem>
                            <ListItem>
                              <Code>Administration</Code>: Read-only (for deploy
                              keys)
                            </ListItem>
                            <ListItem>
                              <Code>Metadata</Code>: Read-only (for
                              repositories)
                            </ListItem>
                          </List>
                        </ListItem>
                        <ListItem>
                          <strong>
                            Account permissions (optional - only if scanning
                            user SSH keys):
                          </strong>
                          <List
                            spacing={1}
                            pl={4}
                            styleType='disc'
                            mt={1}
                            fontSize='xs'
                          >
                            <ListItem>
                              <Code>Git SSH keys</Code>: Read-only
                              <Text
                                as='span'
                                color='orange.500'
                                fontWeight='bold'
                              >
                                {' '}
                                (Required if you enable {'"'}SSH Keys (user
                                only){'"'}
                                filter - scans SSH authentication keys)
                              </Text>
                            </ListItem>
                            <ListItem mt={1}>
                              <Code>SSH signing keys</Code>: Read-only
                              <Text as='span' color='gray.600'>
                                {' '}
                                (Currently not scanned - SSH commit signing keys
                                are a separate feature. File a request if
                                needed!)
                              </Text>
                            </ListItem>
                            <ListItem mt={1}>
                              <Text
                                fontSize='2xs'
                                color='gray.500'
                                fontStyle='italic'
                              >
                                Note: GPG keys are a different permission and
                                not related to SSH
                              </Text>
                            </ListItem>
                          </List>
                        </ListItem>
                        <ListItem>
                          Click {'"'}Generate token{'"'}
                        </ListItem>
                      </List>
                    </AccordionPanel>
                  </AccordionItem>

                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                    mb={2}
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        🔐 Permissions Required
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <Text fontSize='xs' fontWeight='semibold' mb={2}>
                        Classic Token:
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
                          <Code>repo</Code> — Access to secrets and deploy keys
                        </ListItem>
                        <ListItem>
                          <Code>read:public_key</Code> — (Optional) For user SSH
                          keys
                        </ListItem>
                      </List>

                      <Text fontSize='xs' fontWeight='semibold' mb={2}>
                        Fine-grained Token:
                      </Text>
                      <List
                        spacing={1}
                        pl={4}
                        styleType='disc'
                        color={bodyColor}
                        fontSize='xs'
                      >
                        <ListItem>
                          <Code>Secrets</Code> (Read) — Repository secrets
                        </ListItem>
                        <ListItem>
                          <Code>Administration</Code> (Read) — Deploy keys
                        </ListItem>
                        <ListItem>
                          <Code>Metadata</Code> (Read) — Repositories info
                        </ListItem>
                      </List>
                    </AccordionPanel>
                  </AccordionItem>

                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        📦 What We Discover
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <List
                        spacing={2}
                        pl={4}
                        styleType='none'
                        color={bodyColor}
                        fontSize='sm'
                      >
                        <ListItem>
                          <Text fontWeight='semibold'>SSH/GPG Keys:</Text>
                          <Text fontSize='xs' ml={2}>
                            Title, creation date
                          </Text>
                        </ListItem>
                        <ListItem>
                          <Text fontWeight='semibold'>
                            Repository Secrets (Actions):
                          </Text>
                          <Text fontSize='xs' ml={2}>
                            Name, repository, last updated
                          </Text>
                        </ListItem>
                        <ListItem>
                          <Text fontWeight='semibold'>Deploy Keys:</Text>
                          <Text fontSize='xs' ml={2}>
                            Title, repository, read-only status
                          </Text>
                        </ListItem>
                        <ListItem
                          fontSize='xs'
                          fontStyle='italic'
                          mt={2}
                          color='orange.500'
                        >
                          GitHub doesn{"'"}t expose expiration dates for these
                          items via API
                        </ListItem>
                      </List>
                    </AccordionPanel>
                  </AccordionItem>
                </Accordion>

                <Text fontSize='xs' color={bodyColor} mt={3}>
                  <strong>Supported:</strong> github.com or GitHub Enterprise
                  Server
                </Text>

                <Box
                  borderTop='2px solid'
                  borderColor={borderColor}
                  opacity={0.3}
                  my={6}
                />

                <Heading
                  id='import-aws'
                  size='sm'
                  mb={3}
                  display='flex'
                  alignItems='center'
                  gap={2}
                >
                  AWS Secrets Manager{' '}
                  <span style={{ fontFamily: 'Montserrat' }}>&</span> IAM
                  <Badge colorScheme='orange' fontSize='xs'>
                    AWS SDK v3
                  </Badge>
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={4}>
                  Discover secrets from Secrets Manager (with rotation dates),
                  certificates from Certificate Manager (ACM) and IAM access
                  keys across your AWS account.
                </Text>

                <Accordion allowMultiple defaultIndex={[]} mb={4}>
                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                    mb={2}
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        📋 Credential Setup
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <Text
                        fontSize='xs'
                        color={bodyColor}
                        fontWeight='semibold'
                        mb={2}
                      >
                        Option 1 (Recommended): Temporary IAM User
                      </Text>
                      <List
                        spacing={1}
                        pl={4}
                        styleType='decimal'
                        color={bodyColor}
                        fontSize='sm'
                        mb={3}
                      >
                        <ListItem>
                          AWS Console → <strong>IAM</strong> →{' '}
                          <strong>Users</strong> → <strong>Create user</strong>
                        </ListItem>
                        <ListItem>
                          Attach custom policy (see permissions below)
                        </ListItem>
                        <ListItem>
                          Create Access Key → Copy Access Key ID and Secret
                          Access Key
                        </ListItem>
                        <ListItem>
                          <Text as='span' color='red.500' fontWeight='semibold'>
                            Delete user after use
                          </Text>{' '}
                          — credentials are used once and never stored
                        </ListItem>
                      </List>
                      <Text
                        fontSize='xs'
                        color={bodyColor}
                        fontWeight='semibold'
                      >
                        Option 2: AWS STS Temporary Credentials
                      </Text>
                      <List
                        spacing={1}
                        pl={4}
                        styleType='disc'
                        color={bodyColor}
                        fontSize='xs'
                      >
                        <ListItem>
                          Use <Code>sts:AssumeRole</Code> to get temporary
                          credentials with Session Token
                        </ListItem>
                      </List>
                    </AccordionPanel>
                  </AccordionItem>

                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                    mb={2}
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        🔐 IAM Permissions Required
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <Text fontSize='xs' fontWeight='semibold' mb={2}>
                        For Secrets Manager:
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
                          <Code>secretsmanager:ListSecrets</Code>
                        </ListItem>
                        <ListItem>
                          <Code>secretsmanager:DescribeSecret</Code>
                        </ListItem>
                      </List>
                      <Text fontSize='xs' fontWeight='semibold' mb={2}>
                        For Certificate Manager (ACM):
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
                          <Code>acm:ListCertificates</Code>
                        </ListItem>
                        <ListItem>
                          <Code>acm:DescribeCertificate</Code>
                        </ListItem>
                      </List>
                      <Text fontSize='xs' fontWeight='semibold' mb={2}>
                        For IAM Access Keys:
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
                          <Code>iam:ListUsers</Code>
                        </ListItem>
                        <ListItem>
                          <Code>iam:ListAccessKeys</Code>
                        </ListItem>
                      </List>
                      <Text fontSize='xs' fontWeight='semibold' mb={1}>
                        Example IAM Policy:
                      </Text>
                      <CopyableCodeBlock
                        code={`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:ListSecrets",
        "secretsmanager:DescribeSecret",
        "acm:ListCertificates",
        "acm:DescribeCertificate",
        "iam:ListUsers",
        "iam:ListAccessKeys"
      ],
      "Resource": "*"
    }
  ]
}`}
                      />
                    </AccordionPanel>
                  </AccordionItem>

                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        📦 What We Discover
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <List
                        spacing={2}
                        pl={4}
                        styleType='none'
                        color={bodyColor}
                        fontSize='sm'
                      >
                        <ListItem>
                          <Text fontWeight='semibold'>Secrets Manager:</Text>
                          <Text fontSize='xs' ml={2}>
                            Name, ARN, description, rotation/deletion dates
                          </Text>
                        </ListItem>
                        <ListItem>
                          <Text fontWeight='semibold'>
                            Certificate Manager (ACM):
                          </Text>
                          <Text fontSize='xs' ml={2}>
                            Domain names, SANs, expiration date, issuer, serial
                            number, status, in-use status
                          </Text>
                        </ListItem>
                        <ListItem>
                          <Text fontWeight='semibold'>IAM Access Keys:</Text>
                          <Text fontSize='xs' ml={2}>
                            User name, key ID, status, creation date
                          </Text>
                        </ListItem>
                        <ListItem fontSize='xs' fontStyle='italic' mt={2}>
                          Metadata only — no actual secret values, private keys,
                          or certificate private keys retrieved.
                        </ListItem>
                      </List>
                    </AccordionPanel>
                  </AccordionItem>
                </Accordion>

                <Box
                  borderTop='2px solid'
                  borderColor={borderColor}
                  opacity={0.3}
                  my={6}
                />

                <Heading
                  id='import-azure'
                  size='sm'
                  mb={3}
                  display='flex'
                  alignItems='center'
                  gap={2}
                >
                  Azure Key Vault
                  <Badge colorScheme='blue' fontSize='xs'>
                    REST API v7.4
                  </Badge>
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={4}>
                  Discover secrets, certificates, and cryptographic keys from
                  Azure Key Vault instances.
                </Text>

                <Accordion allowMultiple defaultIndex={[]} mb={4}>
                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                    mb={2}
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        📋 Credential Setup
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <Text
                        fontSize='xs'
                        color={bodyColor}
                        fontWeight='semibold'
                        mb={2}
                      >
                        Option 1 (Recommended): Service Principal
                      </Text>
                      <List
                        spacing={1}
                        pl={4}
                        styleType='decimal'
                        color={bodyColor}
                        fontSize='sm'
                        mb={3}
                      >
                        <ListItem>
                          Azure Portal → <strong>Azure AD</strong> →{' '}
                          <strong>App registrations</strong> →{' '}
                          <strong>New</strong>
                        </ListItem>
                        <ListItem>
                          Create app registration (note Application/Client ID)
                        </ListItem>
                        <ListItem>
                          <strong>Certificates & secrets</strong> →{' '}
                          <strong>New client secret</strong> → Copy value
                        </ListItem>
                        <ListItem>
                          Your Key Vault → <strong>Access control</strong> →
                          Assign <Code>Key Vault Reader</Code> role
                        </ListItem>
                        <ListItem>
                          Get token:{' '}
                          <Code>
                            az account get-access-token --resource
                            https://vault.azure.net
                          </Code>
                        </ListItem>
                        <ListItem>
                          <Text as='span' color='red.500' fontWeight='semibold'>
                            Revoke after use
                          </Text>{' '}
                          — token is used once and never stored
                        </ListItem>
                      </List>
                      <Text
                        fontSize='xs'
                        color={bodyColor}
                        fontWeight='semibold'
                      >
                        Option 2: Azure CLI Temporary Token
                      </Text>
                      <List
                        spacing={1}
                        pl={4}
                        styleType='disc'
                        color={bodyColor}
                        fontSize='xs'
                      >
                        <ListItem>
                          Run <Code>az login</Code> then generate token with
                          command above
                        </ListItem>
                      </List>
                    </AccordionPanel>
                  </AccordionItem>

                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                    mb={2}
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        🔐 Permissions Required
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <Text fontSize='xs' fontWeight='semibold' mb={2}>
                        Azure RBAC (Recommended):
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
                          <Code>Key Vault Reader</Code> role
                        </ListItem>
                        <ListItem>
                          <Code>Key Vault Secrets User</Code> role (alternative)
                        </ListItem>
                      </List>
                      <Text fontSize='xs' fontWeight='semibold' mb={2}>
                        Or Classic Access Policies:
                      </Text>
                      <List
                        spacing={1}
                        pl={4}
                        styleType='disc'
                        color={bodyColor}
                        fontSize='xs'
                      >
                        <ListItem>
                          <Code>Get</Code> + <Code>List</Code> for secrets,
                          certificates, and keys
                        </ListItem>
                      </List>
                    </AccordionPanel>
                  </AccordionItem>

                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        📦 What We Discover
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <List
                        spacing={2}
                        pl={4}
                        styleType='none'
                        color={bodyColor}
                        fontSize='sm'
                      >
                        <ListItem>
                          <Text fontWeight='semibold'>Secrets:</Text>
                          <Text fontSize='xs' ml={2}>
                            Name, expiration (attributes.exp), creation/update
                            times
                          </Text>
                        </ListItem>
                        <ListItem>
                          <Text fontWeight='semibold'>Certificates:</Text>
                          <Text fontSize='xs' ml={2}>
                            Name, expiration, issuer, creation/update times
                          </Text>
                        </ListItem>
                        <ListItem>
                          <Text fontWeight='semibold'>Cryptographic Keys:</Text>
                          <Text fontSize='xs' ml={2}>
                            Name, key type, expiration (if set), creation/update
                            times
                          </Text>
                        </ListItem>
                        <ListItem fontSize='xs' fontStyle='italic' mt={2}>
                          Metadata only — no secret values, certificate
                          contents, or key materials retrieved.
                        </ListItem>
                      </List>
                    </AccordionPanel>
                  </AccordionItem>
                </Accordion>

                <Text fontSize='xs' color={bodyColor} mt={3}>
                  <strong>Vault URL:</strong>{' '}
                  <Code>https://your-vault-name.vault.azure.net</Code>
                </Text>

                <Box
                  borderTop='2px solid'
                  borderColor={borderColor}
                  opacity={0.3}
                  my={6}
                />

                <Heading
                  id='import-azure-ad'
                  size='sm'
                  mb={3}
                  display='flex'
                  alignItems='center'
                  gap={2}
                >
                  Azure AD (App Registrations{' '}
                  <span style={{ fontFamily: 'Montserrat' }}>&</span> Service
                  Principals)
                  <Badge colorScheme='blue' fontSize='xs'>
                    Graph API v1.0
                  </Badge>
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={4}>
                  Discover expiring client secrets and certificates from Azure
                  AD app registrations and service principals. Critical for
                  preventing auth failures.
                </Text>

                <Accordion allowMultiple defaultIndex={[]} mb={4}>
                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                    mb={2}
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        📋 Credential Setup
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <Text
                        fontSize='xs'
                        color={bodyColor}
                        fontWeight='semibold'
                        mb={2}
                      >
                        Get Microsoft Graph API Token
                      </Text>
                      <List
                        spacing={1}
                        pl={4}
                        styleType='decimal'
                        color={bodyColor}
                        fontSize='sm'
                        mb={3}
                      >
                        <ListItem>
                          Ensure you have <strong>Global Admin</strong> or{' '}
                          <strong>Application Administrator</strong> role
                        </ListItem>
                        <ListItem>
                          Using Azure CLI: <Code>az login</Code>
                        </ListItem>
                        <ListItem>
                          Get token:{' '}
                          <Code>
                            az account get-access-token --resource
                            https://graph.microsoft.com
                          </Code>
                        </ListItem>
                        <ListItem>
                          Copy the <Code>accessToken</Code> value from JSON
                          response
                        </ListItem>
                        <ListItem>
                          <Text as='span' color='red.500' fontWeight='semibold'>
                            Token expires quickly
                          </Text>{' '}
                          — use immediately, never stored
                        </ListItem>
                      </List>
                      <Text fontSize='xs' color={bodyColor} fontStyle='italic'>
                        Alternative: Use Azure Portal → Azure AD → App
                        registrations → Create app → API permissions → Get token
                        via OAuth2 flow
                      </Text>
                    </AccordionPanel>
                  </AccordionItem>

                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                    mb={2}
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        🔐 Permissions Required
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <Text fontSize='xs' fontWeight='semibold' mb={2}>
                        Microsoft Graph API Permissions:
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
                          <Code>Application.Read.All</Code> (application
                          permission, admin consent required)
                        </ListItem>
                        <ListItem>
                          OR <Code>Application.ReadWrite.All</Code> (if you have
                          write access)
                        </ListItem>
                        <ListItem>
                          OR <Code>Directory.Read.All</Code> (can read all
                          directory objects)
                        </ListItem>
                      </List>
                      <Text fontSize='xs' fontWeight='semibold' mb={2}>
                        Role Requirements:
                      </Text>
                      <List
                        spacing={1}
                        pl={4}
                        styleType='disc'
                        color={bodyColor}
                        fontSize='xs'
                      >
                        <ListItem>
                          Global Admin, Application Administrator, or Cloud
                          Application Administrator
                        </ListItem>
                      </List>
                    </AccordionPanel>
                  </AccordionItem>

                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        📦 What We Discover
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <List
                        spacing={2}
                        pl={4}
                        styleType='none'
                        color={bodyColor}
                        fontSize='sm'
                      >
                        <ListItem>
                          <Text fontWeight='semibold'>
                            App Registration Client Secrets:
                          </Text>
                          <Text fontSize='xs' ml={2}>
                            App name, secret name, expiration date (endDateTime)
                          </Text>
                        </ListItem>
                        <ListItem>
                          <Text fontWeight='semibold'>
                            App Registration Certificates:
                          </Text>
                          <Text fontSize='xs' ml={2}>
                            App name, cert name, expiration, key type, usage
                          </Text>
                        </ListItem>
                        <ListItem>
                          <Text fontWeight='semibold'>
                            Service Principal Credentials:
                          </Text>
                          <Text fontSize='xs' ml={2}>
                            SP name, credential name, expiration (same fields as
                            apps)
                          </Text>
                        </ListItem>
                        <ListItem fontSize='xs' fontStyle='italic'>
                          Metadata only — no actual secret values or certificate
                          contents retrieved.
                        </ListItem>
                      </List>
                    </AccordionPanel>
                  </AccordionItem>
                </Accordion>

                <Text fontSize='xs' color={bodyColor} mt={3}>
                  <strong>Token Scope:</strong>{' '}
                  <Code>https://graph.microsoft.com/.default</Code>
                </Text>

                <Box
                  borderTop='2px solid'
                  borderColor={borderColor}
                  opacity={0.3}
                  my={6}
                />

                <Heading
                  id='import-gcp'
                  size='sm'
                  mb={3}
                  display='flex'
                  alignItems='center'
                  gap={2}
                >
                  GCP Secret Manager
                  <Badge colorScheme='red' fontSize='xs'>
                    REST API v1
                  </Badge>
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={4}>
                  Discover secrets with expiration dates from Google Cloud
                  Secret Manager.
                </Text>

                <Accordion allowMultiple defaultIndex={[]} mb={4}>
                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                    mb={2}
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        📋 Credential Setup
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <Text
                        fontSize='xs'
                        color={bodyColor}
                        fontWeight='semibold'
                        mb={2}
                      >
                        Option 1 (Recommended): Service Account
                      </Text>
                      <List
                        spacing={1}
                        pl={4}
                        styleType='decimal'
                        color={bodyColor}
                        fontSize='sm'
                        mb={3}
                      >
                        <ListItem>
                          GCP Console → <strong>IAM & Admin</strong> →{' '}
                          <strong>Service Accounts</strong> →{' '}
                          <strong>Create</strong>
                        </ListItem>
                        <ListItem>
                          Assign role:{' '}
                          <Code>Secret Manager Secret Accessor</Code>
                        </ListItem>
                        <ListItem>Create and download JSON key file</ListItem>
                        <ListItem>
                          Get token:{' '}
                          <Code>
                            gcloud auth application-default print-access-token
                          </Code>
                        </ListItem>
                        <ListItem>
                          <Text as='span' color='red.500' fontWeight='semibold'>
                            Revoke after use
                          </Text>{' '}
                          — token is used once and never stored
                        </ListItem>
                      </List>
                      <Text
                        fontSize='xs'
                        color={bodyColor}
                        fontWeight='semibold'
                      >
                        Option 2: OAuth2 Temporary Token
                      </Text>
                      <List
                        spacing={1}
                        pl={4}
                        styleType='disc'
                        color={bodyColor}
                        fontSize='xs'
                      >
                        <ListItem>
                          Use OAuth2 flow with{' '}
                          <Code>
                            https://www.googleapis.com/auth/secretmanager
                          </Code>{' '}
                          scope
                        </ListItem>
                      </List>
                    </AccordionPanel>
                  </AccordionItem>

                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                    mb={2}
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        🔐 Permissions Required
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <Text fontSize='xs' fontWeight='semibold' mb={2}>
                        IAM Roles:
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
                          <Code>roles/secretmanager.secretAccessor</Code>{' '}
                          (recommended)
                        </ListItem>
                        <ListItem>
                          <Code>roles/secretmanager.viewer</Code> (alternative)
                        </ListItem>
                      </List>
                      <Text fontSize='xs' fontWeight='semibold' mb={2}>
                        API Scopes:
                      </Text>
                      <List
                        spacing={1}
                        pl={4}
                        styleType='disc'
                        color={bodyColor}
                        fontSize='xs'
                      >
                        <ListItem>
                          <Code>
                            https://www.googleapis.com/auth/cloud-platform
                          </Code>
                        </ListItem>
                        <ListItem>
                          <Code>
                            https://www.googleapis.com/auth/secretmanager
                          </Code>
                        </ListItem>
                      </List>
                    </AccordionPanel>
                  </AccordionItem>

                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        📦 What We Discover
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <List
                        spacing={2}
                        pl={4}
                        styleType='none'
                        color={bodyColor}
                        fontSize='sm'
                      >
                        <ListItem>
                          <Text fontWeight='semibold'>Secrets:</Text>
                          <Text fontSize='xs' ml={2}>
                            Name, expiration (from enabled versions),
                            creation/update times
                          </Text>
                        </ListItem>
                        <ListItem fontSize='xs' fontStyle='italic' mt={2}>
                          Only enabled secret versions are checked for
                          expiration. Metadata only — no secret values
                          retrieved.
                        </ListItem>
                      </List>
                    </AccordionPanel>
                  </AccordionItem>
                </Accordion>

                <Text fontSize='xs' color={bodyColor} mt={3}>
                  <strong>Project ID:</strong> Your GCP project ID (e.g.,{' '}
                  <Code>my-project-123456</Code>)
                </Text>

                <Divider my={8} />

                <Heading id='import-file' size='sm' mb={3} mt={6}>
                  File Import
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={4}>
                  Bulk import tokens from CSV, XLSX, JSON, or YAML files.
                  Perfect for migrating from spreadsheets or exporting from
                  other systems.
                </Text>

                <Box
                  bg={useColorModeValue(
                    'rgba(255, 255, 255, 0.72)',
                    'gray.900'
                  )}
                  border='1px'
                  borderColor={borderColor}
                  borderRadius='md'
                  p={4}
                  mb={4}
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
                  >
                    <ListItem>
                      <Code>name</Code>, <Code>category</Code>,{' '}
                      <Code>type</Code>
                    </ListItem>
                  </List>
                  <Text fontSize='xs' fontWeight='semibold' mt={3} mb={2}>
                    Optional Fields
                  </Text>
                  <List
                    spacing={1}
                    pl={4}
                    styleType='disc'
                    color={bodyColor}
                    fontSize='xs'
                  >
                    <ListItem>
                      <Code>expiresAt</Code> (defaults to{' '}
                      <Badge colorScheme='blue' fontSize='2xs'>
                        Never expires
                      </Badge>{' '}
                      if omitted)
                    </ListItem>
                  </List>
                  <Text fontSize='xs' fontWeight='semibold' mt={3} mb={2}>
                    Supported Formats
                  </Text>
                  <List
                    spacing={1}
                    pl={4}
                    styleType='disc'
                    color={bodyColor}
                    fontSize='xs'
                  >
                    <ListItem>
                      <Code>CSV</Code>, <Code>XLSX</Code>, <Code>JSON</Code>,{' '}
                      <Code>YAML</Code>
                    </ListItem>
                  </List>
                  <Text fontSize='xs' fontWeight='semibold' mt={3} mb={2}>
                    Expiration Date Format
                  </Text>
                  <List
                    spacing={1}
                    pl={4}
                    styleType='disc'
                    color={bodyColor}
                    fontSize='xs'
                  >
                    <ListItem>
                      Use <Code>YYYY-MM-DD</Code> format (e.g.,{' '}
                      <Code>2026-12-31</Code>)
                    </ListItem>
                    <ListItem>
                      If omitted or set to <Code>null</Code>, defaults to{' '}
                      <Badge colorScheme='blue' fontSize='2xs'>
                        Never expires
                      </Badge>{' '}
                      (<Code>2099-12-31</Code>)
                    </ListItem>
                  </List>
                </Box>
                <Accordion allowMultiple defaultIndex={[]} mb={4}>
                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                    mb={2}
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        📄 CSV/XLSX Example
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <CopyableCodeBlock
                        code={`name,category,type,expiresAt,section,domain,privileges,last_used
Example TLS Cert,cert,ssl_cert,2026-01-31,"prod, public",example.com,,
API Gateway Key,key_secret,api_key,2025-12-15,"prod, api",api.example.com,"read, write",2025-06-10`}
                      />
                    </AccordionPanel>
                  </AccordionItem>

                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                    mb={2}
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        📄 JSON Example
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <CopyableCodeBlock
                        code={`[
  {
    "name": "Example API Key",
    "category": "key_secret",
    "type": "api_key",
    "expiresAt": "2026-05-15",
    "section": "backend, internal",
    "domain": "service.example.com",
    "privileges": "read:all, write:logs",
    "last_used": "2025-11-20"
  }
]`}
                      />
                    </AccordionPanel>
                  </AccordionItem>

                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                    mb={2}
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        📄 YAML Example
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <CopyableCodeBlock
                        code={`tokens:
  - name: Example TLS Cert
    category: cert
    type: ssl_cert
    expiresAt: 2026-01-31
    section: prod, external
    privileges: "read, sign"
    last_used: 2025-10-15
    domains:
      - example.com
      - www.example.com
    issuer: "Let's Encrypt"
    location: /etc/ssl/certs
    used_by: edge-proxy`}
                      />
                    </AccordionPanel>
                  </AccordionItem>

                  <AccordionItem
                    border='1px'
                    borderColor={borderColor}
                    borderRadius='md'
                  >
                    <AccordionButton>
                      <Box
                        flex='1'
                        textAlign='left'
                        fontWeight='semibold'
                        fontSize='sm'
                      >
                        📋 Field Constraints
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                    <AccordionPanel pb={4}>
                      <Text fontSize='xs' fontWeight='semibold' mb={2}>
                        Required Fields:
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
                          <Code>name</Code> (3-100 chars), <Code>category</Code>
                          , <Code>type</Code>
                        </ListItem>
                      </List>

                      <Text fontSize='xs' fontWeight='semibold' mb={2}>
                        Optional Fields:
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
                          <Code>expiresAt</Code> (YYYY-MM-DD, defaults to{' '}
                          <Badge colorScheme='blue' fontSize='2xs'>
                            Never expires
                          </Badge>{' '}
                          if omitted), <Code>section</Code>,{' '}
                          <Code>domains</Code>, <Code>location</Code>,{' '}
                          <Code>used_by</Code>
                        </ListItem>
                        <ListItem>
                          <strong>Certificates:</strong> <Code>issuer</Code>,{' '}
                          <Code>serial_number</Code>, <Code>subject</Code>
                        </ListItem>
                        <ListItem>
                          <strong>Keys:</strong> <Code>key_size</Code> (positive
                          integer), <Code>algorithm</Code>
                        </ListItem>
                        <ListItem>
                          <strong>Licenses:</strong> <Code>license_type</Code>,{' '}
                          <Code>vendor</Code>, <Code>cost</Code>,{' '}
                          <Code>renewal_url</Code>, <Code>renewal_date</Code>
                        </ListItem>
                        <ListItem>
                          <Code>contacts</Code>, <Code>description</Code>,{' '}
                          <Code>notes</Code>, <Code>contact_group_id</Code>
                        </ListItem>
                      </List>

                      <Text fontSize='xs' color={bodyColor} fontStyle='italic'>
                        Workspace is taken from your current selection, so you
                        don{"'"}t include <Code>workspace_id</Code> in the file.
                      </Text>
                    </AccordionPanel>
                  </AccordionItem>
                </Accordion>
              </Box>

              <Box
                id='endpoint-monitoring'
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={2}>
                  Endpoint & SSL monitoring
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={3}>
                  TokenTimer can monitor HTTPS endpoints for SSL certificate
                  expiration and endpoint health. When you add an endpoint,
                  TokenTimer automatically fetches the SSL certificate, creates
                  a token to track its expiration, and optionally performs
                  periodic health checks. The Domain Checker uses
                  subfinder&apos;s default passive discovery behavior to find
                  publicly known subdomains for a root domain, then lets you
                  review and bulk-import them as SSL tokens. It does not scan
                  private DNS or internal network records.
                </Text>

                <Heading as='h3' size='sm' mt={4} mb={2}>
                  How SSL tokens are created
                </Heading>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    When you add a URL (e.g., <Code>https://example.com</Code>),
                    TokenTimer connects via TLS to read the SSL certificate.
                  </ListItem>
                  <ListItem>
                    A token is <strong>automatically created</strong> with the
                    hostname as its name (e.g., &quot;example.com&quot;), the
                    certificate expiration date, issuer, serial number, and
                    subject.
                  </ListItem>
                  <ListItem>
                    The token&apos;s <Code>domains</Code> field is populated
                    with the hostname and the <Code>location</Code> field stores
                    the full URL.
                  </ListItem>
                  <ListItem>
                    The token type is set to <Code>ssl_cert</Code> with category{' '}
                    <Code>cert</Code>.
                  </ListItem>
                  <ListItem>
                    On subsequent SSL checks, TokenTimer refreshes the linked
                    token&apos;s certificate metadata, including expiration
                    date, issuer, subject, and serial number when the
                    certificate changes or is renewed.
                  </ListItem>
                </List>

                <Heading as='h3' size='sm' mt={4} mb={2}>
                  Health checking
                </Heading>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    <strong>Enable/disable</strong>: Health checking is off by
                    default and can be toggled per endpoint.
                  </ListItem>
                  <ListItem>
                    <strong>Check intervals</strong>: Every 1 min, 5 min, 30
                    min, hourly, or daily.
                  </ListItem>
                  <ListItem>
                    <strong>What is checked</strong>: An HTTP GET request is
                    made to the URL. A 2xx or 3xx response is
                    &quot;healthy&quot;; 4xx/5xx or timeouts are
                    &quot;unhealthy&quot;.
                  </ListItem>
                  <ListItem>
                    <strong>Dashboard indicator</strong>: A health status icon
                    appears next to the token&apos;s expiry pill in the
                    dashboard (green = healthy, orange = unhealthy, red = error,
                    gray = pending).
                  </ListItem>
                  <ListItem>
                    <strong>Alerts</strong>: When the status transitions from
                    healthy to unhealthy, an alert is triggered. See the{' '}
                    <ChakraLink
                      href='/docs/alerts#endpoint-health'
                      color={linkColor}
                    >
                      Endpoint Health Alerts
                    </ChakraLink>{' '}
                    documentation for details on the alerting strategy.
                  </ListItem>
                </List>

                <Heading as='h3' size='sm' mt={4} mb={2}>
                  Managing endpoints and Domain Checker
                </Heading>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    Click{' '}
                    <strong>&quot;Endpoint &amp; SSL monitor&quot;</strong> on
                    the dashboard to open the Endpoint &amp; SSL monitoring
                    modal. From there you can add a single URL for health checks
                    and SSL tracking, or use the Domain Checker to discover and
                    bulk‑import every SSL certificate ever issued for a root
                    domain.
                  </ListItem>
                  <ListItem>
                    The modal lists monitored endpoints with SSL status, health
                    status, response time, and check interval.
                  </ListItem>
                  <ListItem>
                    Use the refresh button to trigger a manual health check.
                  </ListItem>
                  <ListItem>
                    Deleting an endpoint monitor does <strong>not</strong>{' '}
                    delete the associated SSL token.
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
