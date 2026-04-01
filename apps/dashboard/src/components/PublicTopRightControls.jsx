import {
  HStack,
  Button,
  Box,
  useColorModeValue,
  IconButton,
  Drawer,
  DrawerOverlay,
  DrawerContent,
  DrawerHeader,
  DrawerBody,
  VStack,
  Flex,
  Image,
} from '@chakra-ui/react';
import { FiMenu, FiLogIn, FiHome, FiBook } from 'react-icons/fi';
import { useNavigate } from 'react-router-dom';
import ThemeToggle from './ThemeToggle.jsx';
import React from 'react';

export default function PublicTopRightControls({ session, topOffset }) {
  const navigate = useNavigate();
  const isLoggedIn = !!session;
  const primaryHoverBg = useColorModeValue('blue.100', 'primary.900');
  const bgColor = useColorModeValue('gray.100', '#0f172a');
  const borderColor = useColorModeValue('gray.400', 'gray.700');
  const textColor = useColorModeValue('#1f2937', '#f8fafc');
  const menuButtonColor = useColorModeValue('#0a4bb1', 'blue.300');

  const [isOpen, setIsOpen] = React.useState(false);
  const onOpen = () => setIsOpen(true);
  const onClose = () => setIsOpen(false);

  const topValue = topOffset || { base: 4, md: 6 };

  return (
    <>
      <HStack
        position='fixed'
        top={topValue}
        right={{ base: 4, md: 7 }}
        zIndex={9999}
        spacing={2}
      >
        {/* Mobile drawer trigger */}
        <IconButton
          aria-label='Open menu'
          icon={<FiMenu />}
          variant='ghost'
          size='sm'
          color={textColor}
          display={{ base: 'inline-flex', md: 'none' }}
          onClick={onOpen}
          _hover={{ bg: primaryHoverBg }}
        />

        {/* Desktop navigation */}
        <Button
          onClick={() => navigate('/docs')}
          cursor='pointer'
          variant='ghost'
          size='sm'
          colorScheme='blue'
          color={menuButtonColor}
          bg='transparent'
          _hover={{ bg: primaryHoverBg }}
          _focus={{ bg: 'transparent' }}
          _active={{ bg: 'transparent' }}
          display={{ base: 'none', md: 'inline-flex' }}
        >
          Docs
        </Button>

        <Button
          onClick={() => navigate(isLoggedIn ? '/dashboard' : '/login')}
          variant='ghost'
          size='sm'
          colorScheme='blue'
          color={menuButtonColor}
          bg='transparent'
          cursor='pointer'
          _hover={{ bg: primaryHoverBg }}
          _focus={{ bg: 'transparent' }}
          _active={{ bg: 'transparent' }}
          display={{ base: 'none', md: 'inline-flex' }}
        >
          {isLoggedIn ? 'Dashboard' : 'Sign In'}
        </Button>
        <Box display={{ base: 'none', md: 'inline-flex' }}>
          <ThemeToggle />
        </Box>
      </HStack>

      {/* Mobile Drawer */}
      <Drawer isOpen={isOpen} placement='left' onClose={onClose} size='sm'>
        <DrawerOverlay />
        <DrawerContent bg={bgColor} borderRightColor={borderColor} maxW='320px'>
          <DrawerHeader
            borderBottomWidth='1px'
            borderColor={borderColor}
            position='relative'
          >
            <Flex align='center' justify='space-between'>
              <Button
                onClick={() => navigate('/')}
                variant='ghost'
                size='sm'
                px={0}
                py={0}
                h='40px'
                minW='auto'
                cursor='pointer'
                _hover={{
                  bg: primaryHoverBg,
                }}
                _focus={{
                  boxShadow: 'none',
                }}
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
              </Button>
              <ThemeToggle />
            </Flex>
          </DrawerHeader>
          <DrawerBody p='0'>
            <VStack spacing='0' align='stretch'>
              {/* Navigation Links */}
              <VStack spacing='1' align='stretch' p='4'>
                <Button
                  variant='ghost'
                  justifyContent='start'
                  leftIcon={isLoggedIn ? <FiHome /> : <FiLogIn />}
                  onClick={() => {
                    navigate(isLoggedIn ? '/dashboard' : '/login');
                    onClose();
                  }}
                  _hover={{
                    bg: primaryHoverBg,
                  }}
                  whiteSpace='normal'
                  textAlign='left'
                  h='auto'
                  py={2}
                  px={3}
                >
                  {isLoggedIn ? 'Dashboard' : 'Sign In'}
                </Button>

                <Button
                  variant='ghost'
                  justifyContent='start'
                  leftIcon={<FiBook />}
                  onClick={() => {
                    navigate('/docs');
                    onClose();
                  }}
                  _hover={{
                    bg: primaryHoverBg,
                  }}
                  whiteSpace='normal'
                  textAlign='left'
                  h='auto'
                  py={2}
                  px={3}
                >
                  Docs
                </Button>
              </VStack>
            </VStack>
          </DrawerBody>
        </DrawerContent>
      </Drawer>
    </>
  );
}
