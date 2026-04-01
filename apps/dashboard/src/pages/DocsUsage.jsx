import {
  Box,
  Heading,
  Text,
  VStack,
  List,
  ListItem,
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
import { AccessibleButton } from '../components/Accessibility';
import { useNavigate } from 'react-router-dom';

import SEO from '../components/SEO.jsx';

export default function DocsUsage() {
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
        title='Docs – Usage & Limits'
        description='Track usage at organization and workspace level and understand threshold indicators.'
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
                fontSize='sm'
                color={bodyColor}
              >
                <ListItem>
                  <ChakraLink href='#overview' color={linkColor}>
                    Overview
                  </ChakraLink>
                </ListItem>
                <ListItem>
                  <ChakraLink href='#org' color={linkColor}>
                    Organization usage (admin)
                  </ChakraLink>
                </ListItem>
                <ListItem>
                  <ChakraLink href='#workspace' color={linkColor}>
                    Workspace usage
                  </ChakraLink>
                </ListItem>
                <ListItem>
                  <ChakraLink href='#limits' color={linkColor}>
                    Threshold indicators
                  </ChakraLink>
                </ListItem>
              </List>
            </Box>
          </GridItem>

          <GridItem minW={0}>
            <VStack align='stretch' spacing={6} w='full' minW={0}>
              <Heading size='lg'>
                Usage <span style={{ fontFamily: 'Montserrat' }}>&</span> Limits
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
                  TokenTimer tracks usage at two levels: organization and
                  workspace. Organization usage summarizes all your admin‑owned
                  workspaces (admin role). Workspace usage focuses on the
                  currently selected workspace.
                </Text>
              </Box>

              <Box
                id='org'
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={2}>
                  Organization usage (admin)
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={3}>
                  Admins can view aggregated counts across their organization:
                  number of workspaces, members, tokens, and monthly deliveries.
                  Each metric shows current usage and operational trend.
                </Text>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    <strong>Workspaces</strong>: total count.
                  </ListItem>
                  <ListItem>
                    <strong>Members</strong>: organization member count.
                  </ListItem>
                  <ListItem>
                    <strong>Tokens</strong>: total tokens across all admin
                    workspaces.
                  </ListItem>
                  <ListItem>
                    <strong>Deliveries</strong>: monthly alert deliveries.
                  </ListItem>
                </List>
              </Box>

              <Box
                id='workspace'
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={2}>
                  Workspace usage
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={3}>
                  Inside a workspace, you see token counts and monthly
                  deliveries by channel. Managers and admins see this section;
                  viewers see read‑only token data.
                </Text>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    <strong>Tokens</strong>: count within the selected
                    workspace.
                  </ListItem>
                  <ListItem>
                    <strong>Deliveries</strong>: monthly successes by channel.
                  </ListItem>
                  <ListItem>
                    <strong>Troubleshooting</strong>: spikes without matching
                    token growth may indicate tighter thresholds or frequent
                    post‑expiry reminders.
                  </ListItem>
                </List>
              </Box>
              <Box
                id='limits'
                bg={cardBg}
                border='1px solid'
                borderColor={borderColor}
                borderRadius='md'
                p={{ base: 4, md: 6 }}
                w='full'
                overflowX='hidden'
              >
                <Heading size='md' mb={2}>
                  Threshold indicators
                </Heading>
                <Text fontSize='sm' color={bodyColor} mb={2}>
                  In TokenTimer Core, usage is informational. There is no
                  restriction like in Tokentimer Cloud
                </Text>
                <List
                  spacing={1}
                  pl={4}
                  styleType='disc'
                  color={bodyColor}
                  fontSize='sm'
                >
                  <ListItem>
                    Use these metrics to track growth and forecast alert volume.
                  </ListItem>
                  <ListItem>
                    Color thresholds are visual guidance, not hard limits.
                  </ListItem>
                  <ListItem>
                    Alert delivery counters reset monthly (UTC).
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
