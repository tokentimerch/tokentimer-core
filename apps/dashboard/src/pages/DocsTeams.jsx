import {
  Box,
  Heading,
  Text,
  VStack,
  List,
  ListItem,
  ListIcon,
  Alert,
  AlertIcon,
  useColorModeValue,
  Grid,
  GridItem,
  Link as ChakraLink,
  Button,
  Flex,
  Image,
  Divider,
} from '@chakra-ui/react';
import { FiArrowLeft } from 'react-icons/fi';
import { CheckCircleIcon } from '@chakra-ui/icons';
import { useNavigate } from 'react-router-dom';
import { AccessibleButton } from '../components/Accessibility';

import SEO from '../components/SEO.jsx';

export default function DocsTeams() {
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
        title='Docs – Teams, Workspaces & RBAC'
        description='Manage teams, roles, workspaces, and access control in TokenTimer.'
        noindex
      />
      {/* Header handled by DocsLayout */}
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
                  <ChakraLink href='#overview' color={linkColor}>
                    Overview
                  </ChakraLink>
                </ListItem>
                <ListItem>
                  <ChakraLink href='#roles' color={linkColor}>
                    Roles & permissions
                  </ChakraLink>
                </ListItem>
                <ListItem>
                  <ChakraLink href='#permissions-boundaries' color={linkColor}>
                    Permission boundaries
                  </ChakraLink>
                </ListItem>
                <ListItem>
                  <ChakraLink href='#guidance' color={linkColor}>
                    Practical guidance: Workspaces vs Sections
                  </ChakraLink>
                </ListItem>
                <ListItem>
                  <ChakraLink href='#transfer' color={linkColor}>
                    Transferring tokens
                  </ChakraLink>
                </ListItem>
                <ListItem>
                  <ChakraLink href='#deleting' color={linkColor}>
                    Deleting a workspace
                  </ChakraLink>
                </ListItem>
                <ListItem>
                  <ChakraLink href='#scoping' color={linkColor}>
                    Alert preferences scope
                  </ChakraLink>
                </ListItem>
              </List>
            </Box>
          </GridItem>

          <GridItem minW={0}>
            <VStack align='stretch' spacing={6} w='full' minW={0}>
              <Heading size='lg'>Teams, Workspaces, and RBAC</Heading>

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
                <Text fontSize='sm' color={bodyColor}>
                  TokenTimer supports organizations through{' '}
                  <strong>Workspaces</strong> and role-based access control
                  (RBAC). Workspaces isolate tokens, alert preferences, and
                  audit events. RBAC defines who can manage or view them.
                </Text>
              </Box>

              <Box
                id='roles'
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={2}>
                  Roles and Permissions
                </Heading>
                <List spacing={2} mt={2} color={bodyColor} fontSize='sm'>
                  <ListItem>
                    <ListIcon as={CheckCircleIcon} color='green.500' />
                    <strong>Admin</strong>: full control; create/rename/delete
                    workspaces and tokens, manage members, update preferences,
                    view audit (org + workspace), and access System Settings.
                  </ListItem>
                  <ListItem>
                    <ListIcon as={CheckCircleIcon} color='green.500' />
                    <strong>Workspace Manager</strong>: manage members (except
                    admins, create/update/delete tokens) and preferences within
                    assigned workspaces; view workspace audit. Managers cannot
                    access System Settings.
                  </ListItem>
                  <ListItem>
                    <ListIcon as={CheckCircleIcon} color='green.500' />
                    <strong>Viewer</strong>: view tokens in assigned workspaces.
                  </ListItem>
                </List>
                <Text fontSize='sm' color={bodyColor} mt={3}>
                  Practical guidance: grant Viewer to most teammates or
                  auditors, Manager to service owners who renew assets, and
                  Admin to a minimal set of security owners.
                </Text>
              </Box>

              <Box
                id='permissions-boundaries'
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={2}>
                  Permission boundaries
                </Heading>
                <List spacing={2} mt={2} color={bodyColor} fontSize='sm'>
                  <ListItem>
                    <strong>System Settings</strong> is admin-only.
                  </ListItem>
                  <ListItem>
                    <strong>Role changes</strong> are admin-only.
                  </ListItem>
                  <ListItem>
                    <strong>Workspace managers</strong> can invite/remove
                    members but cannot change admin roles or access system-wide
                    configuration.
                  </ListItem>
                </List>
                <Alert status='info' mt={3} borderRadius='md'>
                  <AlertIcon /> TokenTimer Core uses role-based access control.
                </Alert>
              </Box>

              <Box
                id='guidance'
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={2}>
                  Practical guidance: Workspaces vs Sections
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={2}>
                  Choose the right boundary to keep ownership and notifications
                  clean and predictable.
                </Text>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    <strong>Create a new workspace</strong> when you need:
                  </ListItem>
                </List>
                <List
                  spacing={1}
                  pl={8}
                  styleType='circle'
                  mb={2}
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    Isolated workspaces and notifications.(e.g. different
                    default contact points.)
                  </ListItem>
                  <ListItem>
                    Separate audit and membership boundaries (e.g. different
                    customers)
                  </ListItem>
                </List>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    <strong>Create a new section</strong> when you need:
                  </ListItem>
                </List>
                <List
                  spacing={1}
                  pl={8}
                  styleType='circle'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    Separate tokens by teams, products, or environments inside
                    the same workspace.
                  </ListItem>
                  <ListItem>Different contact groups per section.</ListItem>
                </List>
              </Box>

              <Box
                id='transfer'
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={2}>
                  Transferring tokens between workspaces
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={2}>
                  Move tokens from one workspace to another without re‑creating
                  them. This keeps alert settings and history attributed to the
                  correct workspace going forward.
                </Text>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  mb={2}
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    <strong>Where</strong>: open <em>Workspaces</em>, pick a
                    workspace, then click <em>Transfer tokens</em>.
                  </ListItem>
                  <ListItem>
                    <strong>Who</strong>: Admins; Workspace Managers may
                    transfer if they are attributed to two or more workspaces.
                  </ListItem>
                  <ListItem>
                    <strong>Scope</strong>: available in TokenTimer Core; access
                    is role-based.
                  </ListItem>
                </List>
                <Heading as='h3' size='sm' mt={3} mb={2}>
                  How To
                </Heading>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    In the Workspace section, click on {'"'}Transfer tokens{'"'}
                    , select the source and destination workspaces.
                  </ListItem>
                  <ListItem>
                    Use the search, category, or section filters to narrow the
                    list.
                  </ListItem>
                  <ListItem>
                    Select individual tokens or select all filtered tokens, then
                    click <em>Transfer selected</em>.
                  </ListItem>
                </List>
              </Box>

              <Box
                id='deleting'
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={2}>
                  Deleting a Workspace
                </Heading>
                <Text fontSize='sm' color={bodyColor}>
                  Deleting a workspace removes its tokens, members, sections,
                  invitations, and settings. Audit and delivery logs remain for
                  history, with their workspace unlinked.
                </Text>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  mt={3}
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    Consider transferring tokens to another workspace beforehand
                    if you still need alerts.
                  </ListItem>
                  <ListItem>Export data for an offline record.</ListItem>
                </List>
                <Alert status='warning' mt={3} borderRadius='md'>
                  <AlertIcon /> This action is irreversible. Consider exporting
                  data before deletion.
                </Alert>
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
                  Alert Preferences are Workspace-scoped
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={3}>
                  Default thresholds and channels are configured per workspace.
                  Recipients are managed via <em>contact groups</em>; a token
                  uses its selected group, falling back to the workspace’s
                  default group. Groups can optionally define their own
                  thresholds policy which overrides workspace defaults for
                  assigned tokens.
                </Text>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    Use sections to route ownership (e.g., different teams) and
                    filter dashboards.
                  </ListItem>
                  <ListItem>
                    Changes to workspace thresholds apply to tokens without a
                    group thresholds override.
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
