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
  Flex,
  Image,
  Divider,
} from '@chakra-ui/react';
import { Link as RouterLink, useNavigate } from 'react-router-dom';
import { AccessibleButton } from '../components/Accessibility';

import SEO from '../components/SEO.jsx';

export default function DocsIntro() {
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
        title='Documentation'
        description='TokenTimer product documentation: tokens, alerts, audit, usage, teams, and API.'
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
              <Heading as='h2' size='sm' mb={3}>
                Documentation
              </Heading>
              <List
                spacing={2}
                styleType='disc'
                pl={4}
                fontSize='sm'
                color={bodyColor}
              >
                <ListItem>
                  <ChakraLink
                    as={RouterLink}
                    to='/docs/tokens'
                    color={linkColor}
                  >
                    Tokens
                  </ChakraLink>
                  <List
                    spacing={1}
                    pl={4}
                    mt={1}
                    styleType='circle'
                    fontSize='xs'
                  >
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/tokens#overview'
                        color={linkColor}
                      >
                        Overview
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/tokens#fields'
                        color={linkColor}
                      >
                        Fields & categories
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/tokens#scoping'
                        color={linkColor}
                      >
                        Workspace scoping
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/tokens#import'
                        color={linkColor}
                      >
                        Import tokens
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
                            as={RouterLink}
                            to='/docs/tokens#import-integrations'
                            color={linkColor}
                          >
                            Platform Integrations
                          </ChakraLink>
                        </ListItem>
                        <ListItem>
                          <ChakraLink
                            as={RouterLink}
                            to='/docs/tokens#import-hashicorp'
                            color={linkColor}
                          >
                            Vault (HashiCorp)
                          </ChakraLink>
                        </ListItem>
                        <ListItem>
                          <ChakraLink
                            as={RouterLink}
                            to='/docs/tokens#import-gitlab'
                            color={linkColor}
                          >
                            GitLab
                          </ChakraLink>
                        </ListItem>
                        <ListItem>
                          <ChakraLink
                            as={RouterLink}
                            to='/docs/tokens#import-github'
                            color={linkColor}
                          >
                            GitHub
                          </ChakraLink>
                        </ListItem>
                        <ListItem>
                          <ChakraLink
                            as={RouterLink}
                            to='/docs/tokens#import-aws'
                            color={linkColor}
                          >
                            AWS
                          </ChakraLink>
                        </ListItem>
                        <ListItem>
                          <ChakraLink
                            as={RouterLink}
                            to='/docs/tokens#import-azure'
                            color={linkColor}
                          >
                            Azure Key Vault
                          </ChakraLink>
                        </ListItem>
                        <ListItem>
                          <ChakraLink
                            as={RouterLink}
                            to='/docs/tokens#import-azure-ad'
                            color={linkColor}
                          >
                            Azure AD
                          </ChakraLink>
                        </ListItem>
                        <ListItem>
                          <ChakraLink
                            as={RouterLink}
                            to='/docs/tokens#import-gcp'
                            color={linkColor}
                          >
                            GCP
                          </ChakraLink>
                        </ListItem>
                        <ListItem>
                          <ChakraLink
                            as={RouterLink}
                            to='/docs/tokens#import-file'
                            color={linkColor}
                          >
                            File import
                          </ChakraLink>
                        </ListItem>
                      </List>
                    </ListItem>
                  </List>
                </ListItem>
                <ListItem>
                  <ChakraLink
                    as={RouterLink}
                    to='/docs/alerts'
                    color={linkColor}
                  >
                    Alerts & Preferences
                  </ChakraLink>
                  <List
                    spacing={1}
                    pl={4}
                    mt={1}
                    styleType='circle'
                    fontSize='xs'
                  >
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/alerts#overview'
                        color={linkColor}
                      >
                        Overview
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/alerts#thresholds'
                        color={linkColor}
                      >
                        Thresholds
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/alerts#delivery-window'
                        color={linkColor}
                      >
                        Delivery Window
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/alerts#channels'
                        color={linkColor}
                      >
                        Channels & webhooks
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/alerts#whatsapp'
                        color={linkColor}
                      >
                        WhatsApp & Contacts
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/alerts#contact-groups'
                        color={linkColor}
                      >
                        Contact Groups
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/alerts#weekly-digest'
                        color={linkColor}
                      >
                        Weekly Digest
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/alerts#endpoint-health'
                        color={linkColor}
                      >
                        Endpoint Health Alerts
                      </ChakraLink>
                    </ListItem>
                  </List>
                </ListItem>
                <ListItem>
                  <ChakraLink
                    as={RouterLink}
                    to='/docs/audit'
                    color={linkColor}
                  >
                    Audit
                  </ChakraLink>
                  <List
                    spacing={1}
                    pl={4}
                    mt={1}
                    styleType='circle'
                    fontSize='xs'
                  >
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/audit#overview'
                        color={linkColor}
                      >
                        Overview
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/audit#workspace-scope'
                        color={linkColor}
                      >
                        Workspace scope
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/audit#org-scope'
                        color={linkColor}
                      >
                        Organization scope
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/audit#event-catalog'
                        color={linkColor}
                      >
                        Event catalog
                      </ChakraLink>
                    </ListItem>
                  </List>
                </ListItem>
                <ListItem>
                  <ChakraLink
                    as={RouterLink}
                    to='/docs/usage'
                    color={linkColor}
                  >
                    Usage & Limits
                  </ChakraLink>
                  <List
                    spacing={1}
                    pl={4}
                    mt={1}
                    styleType='circle'
                    fontSize='xs'
                  >
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/usage#overview'
                        color={linkColor}
                      >
                        Overview
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/usage#org'
                        color={linkColor}
                      >
                        Organization usage
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/usage#workspace'
                        color={linkColor}
                      >
                        Workspace usage
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/usage#colors'
                        color={linkColor}
                      >
                        Color thresholds
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/usage#limits'
                        color={linkColor}
                      >
                        Threshold indicators
                      </ChakraLink>
                    </ListItem>
                  </List>
                </ListItem>
                <ListItem>
                  <ChakraLink
                    as={RouterLink}
                    to='/docs/teams'
                    color={linkColor}
                  >
                    Teams, Workspaces & RBAC
                  </ChakraLink>
                  <List
                    spacing={1}
                    pl={4}
                    mt={1}
                    styleType='circle'
                    fontSize='xs'
                  >
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/teams#overview'
                        color={linkColor}
                      >
                        Overview
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/teams#roles'
                        color={linkColor}
                      >
                        Roles & permissions
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/teams#permissions-boundaries'
                        color={linkColor}
                      >
                        Permission boundaries
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/teams#guidance'
                        color={linkColor}
                      >
                        Practical guidance
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/teams#deleting'
                        color={linkColor}
                      >
                        Deleting a workspace
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/teams#scoping'
                        color={linkColor}
                      >
                        Alert preferences scope
                      </ChakraLink>
                    </ListItem>
                  </List>
                </ListItem>
                <ListItem>
                  <ChakraLink as={RouterLink} to='/docs/api' color={linkColor}>
                    API Reference
                  </ChakraLink>
                  <List
                    spacing={1}
                    pl={4}
                    mt={1}
                    styleType='circle'
                    fontSize='xs'
                  >
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/api#quick-start'
                        color={linkColor}
                      >
                        Quick start
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/api#all-plans'
                        color={linkColor}
                      >
                        All plans
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/api#all-plans-auth'
                        color={linkColor}
                      >
                        Authentication
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/api#all-plans-tokens'
                        color={linkColor}
                      >
                        Tokens
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/api#all-plans-alerts'
                        color={linkColor}
                      >
                        Alerts
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/api#all-plans-audit'
                        color={linkColor}
                      >
                        Audit (user)
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/api#all-plans-account'
                        color={linkColor}
                      >
                        Account & Usage
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/api#workspace-management'
                        color={linkColor}
                      >
                        Workspace management
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/api#workspace-management-workspaces'
                        color={linkColor}
                      >
                        Workspaces
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/api#workspace-management-members'
                        color={linkColor}
                      >
                        Members
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/api#workspace-management-transfer'
                        color={linkColor}
                      >
                        Token transfer
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/api#workspace-management-alert-settings'
                        color={linkColor}
                      >
                        Alert settings & Webhooks
                      </ChakraLink>
                    </ListItem>
                    <ListItem>
                      <ChakraLink
                        as={RouterLink}
                        to='/docs/api#workspace-management-audit-org'
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
          <GridItem minW={0}>
            <VStack align='stretch' spacing={6} w='full' minW={0}>
              <Heading size='lg'>TokenTimer Documentation</Heading>
              <Box
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={2}>
                  Welcome
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={3}>
                  TokenTimer helps you track expirations of any expiring asset
                  you could think of and notifies you before and after expiry.
                  Use workspaces and sections to isolate data by team, project
                  or organization, and roles to control access.
                </Text>
                <Heading as='h3' size='sm' mt={2} mb={1}>
                  Start here
                </Heading>
                <List spacing={1} pl={4} styleType='disc'>
                  <ListItem>
                    New to TokenTimer? Read{' '}
                    <ChakraLink
                      onClick={() => navigate('/docs/tokens')}
                      cursor='pointer'
                      color={linkColor}
                    >
                      Tokens
                    </ChakraLink>{' '}
                    then set up{' '}
                    <ChakraLink
                      onClick={() => navigate('/docs/alerts')}
                      cursor='pointer'
                      color={linkColor}
                    >
                      Alerts & Preferences
                    </ChakraLink>
                    .
                  </ListItem>
                  <ListItem>
                    Working in a team? See{' '}
                    <ChakraLink
                      onClick={() => navigate('/docs/teams')}
                      cursor='pointer'
                      color={linkColor}
                    >
                      Teams, Workspaces & RBAC
                    </ChakraLink>
                    .
                  </ListItem>
                  <ListItem>
                    Need to explore activity or troubleshoot? Visit{' '}
                    <ChakraLink
                      onClick={() => navigate('/docs/audit')}
                      cursor='pointer'
                      color={linkColor}
                    >
                      Audit
                    </ChakraLink>
                    .
                  </ListItem>
                  <ListItem>
                    Want to integrate programmatically? Jump to the{' '}
                    <ChakraLink
                      onClick={() => navigate('/docs/api')}
                      cursor='pointer'
                      color={linkColor}
                    >
                      API Reference
                    </ChakraLink>
                    .
                  </ListItem>
                </List>
                <Heading as='h3' size='sm' mt={4} mb={1}>
                  Usage and access
                </Heading>
                <Text fontSize='sm' color={bodyColor}>
                  Review role boundaries and usage visibility in{' '}
                  <ChakraLink
                    onClick={() => navigate('/docs/usage')}
                    cursor='pointer'
                    color={linkColor}
                  >
                    Usage & Limits
                  </ChakraLink>{' '}
                  and{' '}
                  <ChakraLink
                    onClick={() => navigate('/docs/teams')}
                    cursor='pointer'
                    color={linkColor}
                  >
                    Teams, Workspaces & RBAC
                  </ChakraLink>
                  .
                </Text>
              </Box>
            </VStack>
          </GridItem>

          {/* Right spacer */}
          <GridItem display={{ base: 'none', lg: 'block' }} />
        </Grid>
      </Box>
    </>
  );
}
