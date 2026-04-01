import {
  Modal,
  ModalOverlay,
  ModalContent,
  ModalHeader,
  ModalBody,
  ModalFooter,
  Button,
  VStack,
  Text,
  Link,
  Box,
  Icon,
  useColorModeValue,
  HStack,
} from '@chakra-ui/react';
import { useNavigate } from 'react-router-dom';
import { FaRocket, FaCheckCircle } from 'react-icons/fa';
import { FiPlay } from 'react-icons/fi';

function WelcomeModal({
  isOpen,
  onClose,
  data,
  displayName,
  emailSent = true,
  onStartTour,
}) {
  const navigate = useNavigate();
  const bgColor = useColorModeValue('white', 'gray.800');
  const borderColor = useColorModeValue('gray.200', 'gray.600');
  const headerColor = useColorModeValue('blue.600', 'blue.400');
  const textColor = useColorModeValue('gray.700', 'gray.300');
  const subTextColor = useColorModeValue('gray.700', 'gray.400');
  const nextTextColor = useColorModeValue('gray.500', 'gray.500');

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      isCentered
      size='md'
      closeOnOverlayClick={false}
      closeOnEsc={false}
    >
      <ModalOverlay bg='blackAlpha.300' backdropFilter='blur(10px)' />
      <ModalContent bg={bgColor} border='1px solid' borderColor={borderColor}>
        <ModalHeader textAlign='center' color={headerColor}>
          <VStack spacing={3}>
            <Icon as={FaRocket} w={8} h={8} color='blue.500' />
            <Text>Welcome on board! 🎉</Text>
          </VStack>
        </ModalHeader>

        <ModalBody>
          <VStack spacing={4} textAlign='center'>
            <Box>
              <Text
                fontSize='lg'
                fontWeight='semibold'
                color={textColor}
                mb={2}
              >
                Hi {data?.userName || displayName || 'there'}! 👋
              </Text>
              <Text color={subTextColor} fontSize='md'>
                Your TokenTimer account has been created successfully.
              </Text>
            </Box>

            {emailSent ? (
              <Box bg='green.50' p={4} borderRadius='md' w='full'>
                <VStack spacing={3}>
                  <Icon as={FaCheckCircle} w={6} h={6} color='green.500' />
                  <Text fontSize='sm' color='green.700' fontWeight='medium'>
                    Account Ready!
                  </Text>
                  <Text fontSize='sm' color='green.600'>
                    Your account has been created and is ready to use.
                  </Text>
                  <Text fontSize='xs' color='green.500'>
                    You can start managing your tokens right away.
                  </Text>
                </VStack>
              </Box>
            ) : (
              <Box bg='green.50' p={4} borderRadius='md' w='full'>
                <VStack spacing={3}>
                  <Icon as={FaCheckCircle} w={6} h={6} color='green.500' />
                  <Text fontSize='sm' color='green.700' fontWeight='medium'>
                    Email Verified!
                  </Text>
                  <Text fontSize='sm' color='green.600'>
                    Your email has been verified and your account is now active.
                  </Text>
                  <Text fontSize='xs' color='green.500'>
                    You can start managing your tokens right away.
                  </Text>
                </VStack>
              </Box>
            )}

            <Box bg='gray.50' p={4} borderRadius='md' w='full'>
              <Text fontSize='sm' color={subTextColor}>
                <strong>What{"'"}s next?</strong>
              </Text>
              <VStack spacing={2} mt={2} align='start'>
                {onStartTour && (
                  <Text fontSize='xs' color={nextTextColor}>
                    <Link
                      as='button'
                      onClick={onStartTour}
                      color='blue.500'
                      textDecoration='underline'
                      _hover={{ textDecoration: 'underline' }}
                    >
                      ✓ Try our product tour to discover the possibilities
                    </Link>
                  </Text>
                )}
                <Text fontSize='xs' color={nextTextColor}>
                  <Link
                    onClick={() => navigate('/docs')}
                    cursor='pointer'
                    color='blue.500'
                    textDecoration='underline'
                  >
                    ✓ Check the documentation to see how it works
                  </Link>
                </Text>
                <Text fontSize='xs' color={nextTextColor}>
                  ✓ Add your first token or secret
                </Text>
                <Text fontSize='xs' color={nextTextColor}>
                  ✓ Setup your contact groups and thresholds
                </Text>
              </VStack>
            </Box>
          </VStack>
        </ModalBody>

        <ModalFooter justifyContent='center'>
          <HStack spacing={3}>
            {onStartTour && (
              <Button
                leftIcon={<Icon as={FiPlay} />}
                variant='outline'
                colorScheme='blue'
                onClick={onStartTour}
                size='lg'
                px={6}
                _hover={{ transform: 'translateY(-1px)', boxShadow: 'lg' }}
                transition='all 0.2s'
              >
                Take Tour
              </Button>
            )}
            <Button
              colorScheme='blue'
              onClick={onClose}
              size='lg'
              px={8}
              _hover={{ transform: 'translateY(-1px)', boxShadow: 'lg' }}
              transition='all 0.2s'
            >
              {emailSent ? 'Go to Dashboard' : 'Get Started'}
            </Button>
          </HStack>
        </ModalFooter>
      </ModalContent>
    </Modal>
  );
}

export default WelcomeModal;
