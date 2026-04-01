import {
  Box,
  Container,
  Flex,
  Text,
  Link,
  HStack,
  VStack,
  useColorModeValue,
  Icon,
} from '@chakra-ui/react';
import { useNavigate, useLocation } from 'react-router-dom';
import { FiFileText, FiMail, FiBookOpen } from 'react-icons/fi';
import {
  useBrandColors,
  useLandingColors,
  useBackgroundColors,
  useBorderColors,
} from '../hooks/useColors.js';

/**
 * Footer component with comprehensive navigation and branding
 */
const Footer = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const isLandingPage = location.pathname === '/';

  // Use navigation colors to match the navigation bar
  const { surface: navBgColor } = useBackgroundColors();
  const { default: navBorderColor } = useBorderColors();

  // Use landing colors on landing page for text/links, but match nav background
  const landingColors = useLandingColors();
  const { accent: linkColor } = useBrandColors();

  // Match navigation bar background and border - more contrast in light mode
  const sectionBg = useColorModeValue('rgba(255, 255, 255, 0.98)', navBgColor);
  const borderColor = useColorModeValue('gray.400', navBorderColor);

  // Call all hooks unconditionally (Rules of Hooks)
  const textColorApp = useColorModeValue('gray.800', 'gray.300');
  const headingColorApp = useColorModeValue('gray.900', 'white');
  const linkHoverLanding = useColorModeValue('blue.600', 'blue.400');
  const linkHoverApp = useColorModeValue('blue.600', 'blue.300');

  // Then conditionally select which value to use
  const textColor = isLandingPage ? landingColors.textColor : textColorApp;
  const headingColor = isLandingPage
    ? landingColors.headingColor
    : headingColorApp;
  const footerLinkColor = isLandingPage
    ? landingColors.primaryColor
    : linkColor;
  const footerLinkHoverColor = isLandingPage ? linkHoverLanding : linkHoverApp;

  const currentYear = new Date().getFullYear();

  return (
    <Box
      as='footer'
      bg={sectionBg}
      borderTopWidth='1px'
      borderColor={borderColor}
      mt='auto'
      py='8'
      // Fixed height prevents CLS from footer rendering late
      h={{ base: '250px', md: '110px' }}
      minH={{ base: '250px', md: '110px' }}
      // contain: layout paint prevents this element from affecting siblings during render
      style={{
        backdropFilter: 'none',
        WebkitBackdropFilter: 'none',
        backgroundColor: sectionBg,
        contain: 'layout paint',
      }}
    >
      <Container
        maxW={isLandingPage ? '7xl' : '1200px'}
        px={{ base: 4, md: 6 }}
      >
        <Flex
          direction={{ base: 'column', md: 'row' }}
          justify='space-between'
          align={{ base: 'center', md: 'center' }}
          gap='6'
          minW={0}
        >
          {/* Brand */}
          <VStack
            align={{ base: 'center', md: 'start' }}
            spacing='2'
            flexShrink={0}
          >
            <Text
              fontSize='lg'
              fontWeight='bold'
              color={headingColor}
              textAlign={{ base: 'center', md: 'left' }}
            >
              TokenTimer
            </Text>
            <Text
              fontSize='sm'
              color={textColor}
              textAlign={{ base: 'center', md: 'left' }}
            >
              © {currentYear} TokenTimer — Privacy by Design
            </Text>
          </VStack>

          {/* Navigation Links and Social Media Icons */}
          <HStack
            spacing={{ base: '3', md: '4' }}
            flexWrap={{ base: 'wrap', md: 'nowrap' }}
            justify={{ base: 'center', md: 'end' }}
            flexShrink={0}
            minW={0}
            maxW={{ base: '100%', md: 'none' }}
            sx={{
              '&::-webkit-scrollbar': {
                display: 'none',
              },
              scrollbarWidth: 'none',
            }}
          >
            <Link
              href='/docs'
              onClick={e => {
                e.preventDefault();
                navigate('/docs');
              }}
              cursor='pointer'
              color={footerLinkColor}
              _hover={{
                textDecoration: 'none',
                color: footerLinkHoverColor,
              }}
              fontSize='sm'
              whiteSpace='nowrap'
              flexShrink={0}
              aria-label='Documentation'
            >
              <HStack spacing='2' align='center'>
                <Icon as={FiBookOpen} boxSize={4} />
                <Text>Docs</Text>
              </HStack>
            </Link>
            <Link
              href='/help'
              onClick={e => {
                e.preventDefault();
                navigate('/help');
              }}
              cursor='pointer'
              color={footerLinkColor}
              _hover={{
                textDecoration: 'none',
                color: footerLinkHoverColor,
              }}
              fontSize='sm'
              whiteSpace='nowrap'
              flexShrink={0}
              aria-label='Help and Support'
            >
              <HStack spacing='2' align='center'>
                <Icon as={FiMail} boxSize={4} />
                <Text>Help</Text>
              </HStack>
            </Link>
            <Link
              href='https://github.com/tokentimerch/tokentimer-core'
              isExternal
              color={footerLinkColor}
              _hover={{
                textDecoration: 'none',
                color: footerLinkHoverColor,
              }}
              display='flex'
              alignItems='center'
              fontSize='sm'
              whiteSpace='nowrap'
              flexShrink={0}
              aria-label='View source on GitHub'
            >
              <HStack spacing='2' align='center'>
                <Icon as={FiFileText} boxSize={4} />
                <Text>GitHub</Text>
              </HStack>
            </Link>
          </HStack>
        </Flex>
      </Container>
    </Box>
  );
};

export default Footer;
