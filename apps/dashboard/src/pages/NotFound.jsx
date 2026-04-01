import { Box, Heading, Text, Button, VStack } from '@chakra-ui/react';
import { Link as RouterLink } from 'react-router-dom';
import SEO from '../components/SEO.jsx';

export default function NotFound() {
  const canonical = '/404';
  return (
    <Box
      minH='100vh'
      display='flex'
      alignItems='center'
      justifyContent='center'
      p={{ base: 4, md: 8 }}
      overflowX='hidden'
    >
      <SEO
        title='Page Not Found'
        description='The page you are looking for does not exist.'
        canonical={canonical}
        noindex
      />
      <VStack spacing={4} textAlign='center'>
        <Heading size='2xl'>404</Heading>
        <Text>Sorry, we couldn’t find that page.</Text>
        <VStack spacing={2}>
          <Button as={RouterLink} to='/' colorScheme='blue'>
            Go Home
          </Button>
          <Button as={RouterLink} to='/pricing' variant='ghost'>
            View Pricing
          </Button>
          <Button as={RouterLink} to='/docs' variant='ghost'>
            Read the Docs
          </Button>
          <Button as={RouterLink} to='/help' variant='ghost'>
            Get Help
          </Button>
        </VStack>
      </VStack>
    </Box>
  );
}
