import { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import {
  Box,
  Card,
  CardBody,
  Badge,
  Heading,
  Text,
  VStack,
  HStack,
  Icon,
  SimpleGrid,
  useColorModeValue,
  Image,
} from '@chakra-ui/react';
import {
  FiShield,
  FiKey,
  FiFileText,
  FiSettings,
  FiMail,
  FiBell,
  FiMessageCircle,
  FiZap,
  FiCheckCircle,
  FiServer,
  FiRefreshCw,
  FiUpload,
  FiGlobe,
} from 'react-icons/fi';
import { SiDiscord, SiPagerduty } from 'react-icons/si';
import { useLandingColors } from '../hooks/useColors.js';

export function HowItWorks({
  mailColor,
  mailHover,
  teamsColor: _teamsColor,
  teamsHover: _teamsHover,
  discordColor,
  discordHover,
  pagerdutyColor,
  pagerdutyHover,
  internetColor,
  internetHover,
  textColor: textColorProp,
}) {
  const [activeStep, setActiveStep] = useState(null);
  const [isMobile, setIsMobile] = useState(false);
  const [, setDebugInfo] = useState(''); // Debug info for display
  const cardRefs = useRef([]);
  const visibleCardsRef = useRef(new Set()); // Track currently visible cards
  const containerRef = useRef(null); // Track the main container for desktop scroll progress
  const scrollActiveStepRef = useRef(null); // Track scroll-based active step
  const hoveredStepRef = useRef(null); // Track hovered step
  const scrollCountRef = useRef(0); // Count scroll calls
  const animationProgressRef = useRef(0); // Track animation progress (0-3)

  // Use theme colors from Landing page
  const { textColor, headingColor, primaryColor, cardBg, cardBorderColor } =
    useLandingColors();

  const textColorSecondary = useColorModeValue('gray.600', 'gray.400');

  // Card styling with theme colors
  const cardBgWithOpacity = useColorModeValue(cardBg, 'rgba(2, 6, 23, 0.46)');
  const cardBorder = useColorModeValue(
    cardBorderColor,
    'rgba(255, 255, 255, 0.1)'
  );
  const hoverBorderColor = useColorModeValue('#0a4bb1', '#0a4bb1');
  const cardShadow = useColorModeValue('lg', '2xl');
  const cardHoverShadow = useColorModeValue('xl', '2xl');
  const stepNumberBorderColor = useColorModeValue(
    'whiteAlpha.300',
    'whiteAlpha.200'
  );
  const stepIconBg = useColorModeValue('gray.100', 'whiteAlpha.100');
  const stepIconBorderColor = useColorModeValue('gray.200', 'whiteAlpha.200');

  // Badge colors using theme
  const badgeBg = useColorModeValue('orange.100', 'orange.500');
  const badgeColor = useColorModeValue('orange.800', 'orange.200');
  const badgeBorder = useColorModeValue('orange.300', 'orange.400');

  const steps = [
    {
      number: 1,
      title: 'Capture',
      description:
        'Quickly add assets or import them via our integrations: from certificates and keys to licenses, contracts, and documents.',
      icon: FiUpload,
      colorFrom: 'blue.500',
      colorTo: 'cyan.500',
    },
    {
      number: 2,
      title: 'Configure',
      description:
        'Set thresholds, recipients, and channels: Email, Slack, Teams, Discord, PagerDuty, custom webhook, SMS, WhatsApp, etc...',
      icon: FiSettings,
      colorFrom: 'purple.500',
      colorTo: 'indigo.500',
    },
    {
      number: 3,
      title: 'Deliver',
      description:
        'We deliver notifications using high-available and carefully monitored systems with queue management, backoff strategies, and instant retry capabilities.',
      icon: FiZap,
      colorFrom: 'teal.500',
      colorTo: 'emerald.500',
    },
  ];

  // Make the main container background fully traxnsparent for floating effect
  const mainBg = useColorModeValue('transparent', 'transparent');

  // Detect mobile device
  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth < 768); // md breakpoint
    };
    checkMobile();
    window.addEventListener('resize', checkMobile);
    return () => window.removeEventListener('resize', checkMobile);
  }, []);

  // Desktop: Always show all cards (no scroll animation)
  useEffect(() => {
    if (!isMobile) {
      // On desktop, always activate all 3 cards
      setActiveStep(null); // Set to null so hover still works, but all visual animations show
    }
  }, [isMobile]);

  // Intersection Observer for scroll-based animation
  useEffect(() => {
    let observers = [];
    let rafId = null;
    const currentIsMobile = isMobile; // Capture the current value

    // Function to update activeStep based on currently visible cards (mobile)
    const updateActiveStepMobile = () => {
      // Find the highest visible card number
      let highestVisible = null;
      visibleCardsRef.current.forEach(stepNumber => {
        if (highestVisible === null || stepNumber > highestVisible) {
          highestVisible = stepNumber;
        }
      });

      // Set activeStep to the highest visible card, or null if none are visible
      scrollActiveStepRef.current = highestVisible;
      setActiveStep(highestVisible);
    };

    // Function to update activeStep based on scroll progress (desktop)
    // This is mainly for initial state and intersection observer updates
    const updateActiveStepDesktop = () => {
      if (!containerRef.current) {
        setDebugInfo('No containerRef');
        return;
      }

      const rect = containerRef.current.getBoundingClientRect();
      const windowHeight = window.innerHeight;

      // Section hasn't entered viewport yet
      if (rect.top > windowHeight) {
        animationProgressRef.current = 0;
        scrollActiveStepRef.current = null;
        if (hoveredStepRef.current === null) {
          setActiveStep(null);
        }
        setDebugInfo(`Before section | rectTop: ${Math.round(rect.top)}`);
        return;
      }

      // Section has scrolled past - show all
      if (rect.bottom < 0) {
        animationProgressRef.current = 3;
        scrollActiveStepRef.current = 3;
        if (hoveredStepRef.current === null) {
          setActiveStep(3);
        }
        setDebugInfo(`After section | rectTop: ${Math.round(rect.top)}`);
        return;
      }

      // In viewport - show current state (wheel handler manages the animation)
      setDebugInfo(
        `rectTop: ${Math.round(rect.top)}, progress: ${animationProgressRef.current.toFixed(1)}, step: ${scrollActiveStepRef.current}`
      );
    };

    // Scroll handler to check visibility on every scroll
    const handleScroll = () => {
      if (rafId) {
        cancelAnimationFrame(rafId);
      }
      rafId = requestAnimationFrame(() => {
        scrollCountRef.current += 1;
        if (currentIsMobile) {
          // Mobile: Check each card's visibility manually
          cardRefs.current.forEach((ref, index) => {
            if (!ref) return;
            const stepNumber = index + 1;
            const rect = ref.getBoundingClientRect();
            const windowHeight = window.innerHeight;

            // Card is visible if at least 80% is in the viewport (between 20% and 80% of viewport)
            const viewportTop = windowHeight * 0.2;
            const viewportBottom = windowHeight * 0.8;
            const cardTop = rect.top;
            const cardBottom = rect.bottom;
            const cardHeight = rect.height;

            // Calculate visible portion
            const visibleTop = Math.max(cardTop, viewportTop);
            const visibleBottom = Math.min(cardBottom, viewportBottom);
            const visibleHeight = Math.max(0, visibleBottom - visibleTop);
            const visibleRatio =
              cardHeight > 0 ? visibleHeight / cardHeight : 0;

            const isVisible = visibleRatio >= 0.8;

            if (isVisible) {
              visibleCardsRef.current.add(stepNumber);
            } else {
              visibleCardsRef.current.delete(stepNumber);
            }
          });

          updateActiveStepMobile();
        } else {
          // Desktop: Use scroll progress of the section
          updateActiveStepDesktop();
        }
      });
    };

    // Small delay to ensure refs are populated
    const timeoutId = setTimeout(() => {
      // Set up Intersection Observer for mobile only
      if (currentIsMobile) {
        observers = cardRefs.current
          .filter(ref => ref !== null && ref !== undefined)
          .map((ref, index) => {
            const observer = new IntersectionObserver(
              entries => {
                entries.forEach(entry => {
                  const stepNumber = index + 1;
                  if (entry.isIntersecting && entry.intersectionRatio >= 0.8) {
                    visibleCardsRef.current.add(stepNumber);
                  } else {
                    visibleCardsRef.current.delete(stepNumber);
                  }
                  updateActiveStepMobile();
                });
              },
              {
                threshold: [0, 0.8, 1.0], // Trigger at 80% visibility
                rootMargin: '0px',
              }
            );

            observer.observe(ref);
            return observer;
          });
      } else {
        // Desktop: Use IntersectionObserver to detect scroll changes
        const containerObserver = new IntersectionObserver(
          entries => {
            entries.forEach(() => {
              handleScroll();
            });
          },
          {
            threshold: Array.from({ length: 21 }, (_, i) => i * 0.05), // Check every 5%
            rootMargin: '0px',
          }
        );

        if (containerRef.current) {
          containerObserver.observe(containerRef.current);
          observers.push(containerObserver);
        }
      }

      // Listen to scroll events for updates (both mobile and desktop)
      window.addEventListener('scroll', handleScroll, { passive: true });
      document.addEventListener('scroll', handleScroll, { passive: true });

      // Trigger initial check
      handleScroll();
    }, 100);

    return () => {
      clearTimeout(timeoutId);
      if (rafId) {
        cancelAnimationFrame(rafId);
      }
      window.removeEventListener('scroll', handleScroll);
      document.removeEventListener('scroll', handleScroll);
      observers.forEach(observer => {
        if (observer) observer.disconnect();
      });
    };
  }, [isMobile]);

  return (
    <Box
      id='how-it-works'
      ref={containerRef}
      position='relative'
      w='full'
      bg={mainBg}
      borderRadius='2xl'
      p={{ base: 8, md: 16 }}
      overflow='hidden'
    >
      {/* Debug indicator - commented out
      <Box
        position='fixed'
        top='10px'
        right='10px'
        bg='black'
        color='white'
        p={2}
        borderRadius='md'
        fontSize='xs'
        zIndex={9999}
        maxW='350px'
      >
        <div>Active: {activeStep || 'none'} | Mobile: {isMobile ? 'yes' : 'no'} | Scrolls: {scrollCountRef.current}</div>
        <div>{debugInfo}</div>
      </Box>
      */}
      <Box position='relative' zIndex={10} maxW='7xl' mx='auto'>
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
        >
          <VStack spacing={4} textAlign='center' mb={16}>
            <Heading as='h2' size='xl' color={headingColor}>
              How it works
            </Heading>
            <Text color={textColor} maxW='3xl' mx='auto'>
              Capture your assets, configure thresholds and channels, and let
              TokenTimer deliver on time.
            </Text>
          </VStack>
        </motion.div>

        {/* Steps */}
        <SimpleGrid columns={{ base: 1, lg: 3 }} spacing={8} mb={12}>
          {steps.map((step, index) => (
            <motion.div
              key={step.number}
              ref={el => {
                cardRefs.current[index] = el;
              }}
              initial={{ opacity: 0, y: 50 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.6, delay: index * 0.2 }}
              onMouseEnter={() => {
                if (!isMobile) {
                  hoveredStepRef.current = step.number;
                  setActiveStep(step.number);
                }
              }}
              onMouseLeave={() => {
                if (!isMobile) {
                  hoveredStepRef.current = null;
                  // Restore scroll-based active step
                  setActiveStep(scrollActiveStepRef.current);
                }
              }}
            >
              <Card
                position='relative'
                overflow='hidden'
                bg={cardBgWithOpacity}
                backdropFilter='blur(20px)'
                border='1px solid'
                borderColor={cardBorder}
                boxShadow={cardShadow}
                transition='all 0.5s'
                h='full'
                transform={
                  activeStep === step.number ? 'scale(1.05)' : 'scale(1)'
                }
                _hover={{
                  boxShadow: cardHoverShadow,
                  borderColor: hoverBorderColor,
                }}
              >
                <Box
                  position='absolute'
                  inset={0}
                  bgGradient={`linear(to-br, ${step.colorFrom}/20, ${step.colorTo}/20)`}
                  opacity={0.5}
                />

                <CardBody position='relative' p={8}>
                  {/* Step number badge */}
                  <motion.div
                    animate={
                      activeStep === step.number
                        ? { scale: 1.1, rotate: 360 }
                        : { scale: 1, rotate: 0 }
                    }
                    transition={{ duration: 0.6 }}
                  >
                    <Box
                      position='absolute'
                      top={-4}
                      right={-4}
                      w={16}
                      h={16}
                      borderRadius='full'
                      bgGradient='linear(to-br, #0e151f, #0a4bb1)'
                      border='1px solid'
                      borderColor={stepNumberBorderColor}
                      display='flex'
                      alignItems='center'
                      justifyContent='center'
                      boxShadow='xl'
                    >
                      <Text
                        color='white !important'
                        fontSize='xl'
                        fontWeight='bold'
                      >
                        {step.number}
                      </Text>
                    </Box>
                  </motion.div>

                  {/* Icon */}
                  <motion.div
                    animate={activeStep === step.number ? { y: -5 } : { y: 0 }}
                    transition={{ duration: 0.3 }}
                  >
                    <Box
                      w={16}
                      h={16}
                      borderRadius='2xl'
                      bg={stepIconBg}
                      backdropFilter='blur(10px)'
                      border='1px solid'
                      borderColor={stepIconBorderColor}
                      display='flex'
                      alignItems='center'
                      justifyContent='center'
                      mb={6}
                    >
                      <Icon as={step.icon} w={8} h={8} color={primaryColor} />
                    </Box>
                  </motion.div>

                  {/* Title */}
                  <Heading as='h3' size='md' mb={4} color={headingColor}>
                    {step.title}
                  </Heading>

                  {/* Description */}
                  <Text
                    color={textColor}
                    fontSize='sm'
                    lineHeight='relaxed'
                    mb={6}
                  >
                    {step.description}
                  </Text>

                  {/* Visual element based on step */}
                  <Box mt={6}>
                    {step.number === 1 && (
                      <CaptureVisual active={!isMobile || activeStep === 1} />
                    )}
                    {step.number === 2 && (
                      <ConfigureVisual
                        active={!isMobile || activeStep === 2}
                        badgeBg={badgeBg}
                        badgeColor={badgeColor}
                        badgeBorder={badgeBorder}
                        textColor={textColor}
                        textColorSecondary={textColorSecondary}
                      />
                    )}
                    {step.number === 3 && (
                      <DeliverVisual
                        active={!isMobile || activeStep === 3}
                        textColor={textColor}
                        textColorSecondary={textColorSecondary}
                      />
                    )}
                  </Box>
                </CardBody>
              </Card>
            </motion.div>
          ))}
        </SimpleGrid>

        {/* Works with your tools */}
        <VStack
          spacing={6}
          mt={12}
          mb={0}
          color={useColorModeValue('gray.500', 'gray.400')}
        >
          <Text
            color={textColorProp || textColor}
            fontWeight='medium'
            fontSize='lg'
          >
            Works with your tools
          </Text>
          <VStack spacing={6}>
            <HStack spacing={10} justify='center' flexWrap='wrap'>
              <Icon
                as={FiMail}
                boxSize={8}
                aria-label='Email'
                title='Email'
                color={mailColor}
                _hover={{ color: mailHover }}
              />
              <Image
                loading='lazy'
                decoding='async'
                src='/Branding/slack.svg'
                boxSize={8}
                alt='Slack'
                title='Slack'
              />
              <Image
                loading='lazy'
                decoding='async'
                src='/Branding/teams.svg'
                boxSize={8}
                alt='Microsoft Teams'
                title='Microsoft Teams'
              />
              <Icon
                as={SiDiscord}
                boxSize={8}
                aria-label='Discord'
                title='Discord'
                color={discordColor}
                _hover={{ color: discordHover }}
              />
              <Icon
                as={SiPagerduty}
                boxSize={8}
                aria-label='PagerDuty'
                title='PagerDuty'
                color={pagerdutyColor}
                _hover={{ color: pagerdutyHover }}
              />
              <Image
                loading='lazy'
                decoding='async'
                src='/Branding/whatsapp.svg'
                boxSize={8}
                alt='WhatsApp'
                title='WhatsApp'
              />
              <Icon
                as={FiGlobe}
                boxSize={8}
                aria-label='Custom Webhooks'
                title='Custom Webhooks'
                color={internetColor}
                _hover={{ color: internetHover }}
              />
            </HStack>
            <HStack spacing={10} justify='center' flexWrap='wrap'>
              <Image
                loading='lazy'
                decoding='async'
                src='/Branding/vendor-logos/hashicorp.png'
                boxSize={8}
                alt='HashiCorp Vault'
                title='HashiCorp Vault'
              />
              <Image
                loading='lazy'
                decoding='async'
                src='/Branding/vendor-logos/gitlab.png'
                boxSize={8}
                alt='GitLab'
                title='GitLab'
              />
              <Image
                loading='lazy'
                decoding='async'
                src='/Branding/vendor-logos/github.png'
                boxSize={8}
                alt='GitHub'
                title='GitHub'
              />
              <Image
                loading='lazy'
                decoding='async'
                src='/Branding/vendor-logos/aws.png'
                boxSize={8}
                alt='AWS'
                title='AWS'
              />
              <Image
                loading='lazy'
                decoding='async'
                src='/Branding/vendor-logos/azure.svg'
                boxSize={8}
                alt='Azure'
                title='Azure'
              />
              <Image
                loading='lazy'
                decoding='async'
                src='/Branding/vendor-logos/google-cloud-icon.png'
                boxSize={8}
                alt='Google Cloud'
                title='Google Cloud'
              />
            </HStack>
          </VStack>
        </VStack>
      </Box>
    </Box>
  );
}

// Visual for Capture step
function CaptureVisual({ active }) {
  const { textColor, headingColor } = useLandingColors();
  const assets = [
    { icon: FiShield, label: 'SSL Cert', color: 'blue.500' },
    { icon: FiKey, label: 'API Key', color: 'purple.500' },
    { icon: FiFileText, label: 'License', color: 'teal.500' },
  ];

  const assetBorder = useColorModeValue('gray.200', 'whiteAlpha.100');
  const checkColor = useColorModeValue('green.500', 'green.400');

  return (
    <VStack spacing={2} align='stretch'>
      {assets.map((asset, index) => (
        <motion.div
          key={asset.label}
          initial={{ x: -20, opacity: 0 }}
          animate={active ? { x: 0, opacity: 1 } : { x: -20, opacity: 0 }}
          transition={{ duration: 0.4, delay: index * 0.1 }}
        >
          <HStack
            spacing={3}
            p={3}
            borderRadius='lg'
            bg={`${asset.color}/20`}
            border='1px solid'
            borderColor={assetBorder}
            backdropFilter='blur(10px)'
          >
            <Icon as={asset.icon} w={4} h={4} color={headingColor} />
            <Text color={textColor} fontSize='sm'>
              {asset.label}
            </Text>
            <Box ml='auto'>
              <motion.div
                initial={{ scale: 0 }}
                animate={active ? { scale: 1 } : { scale: 0 }}
                transition={{ duration: 0.3, delay: 0.3 + index * 0.1 }}
              >
                <Icon as={FiCheckCircle} w={4} h={4} color={checkColor} />
              </motion.div>
            </Box>
          </HStack>
        </motion.div>
      ))}
    </VStack>
  );
}

// Visual for Configure step
function ConfigureVisual({
  active,
  badgeBg,
  badgeColor,
  badgeBorder,
  _textColor,
  textColorSecondary,
}) {
  const channels = [
    { icon: FiMail, label: 'Email' },
    { icon: FiBell, label: 'Slack' },
    { icon: FiMessageCircle, label: 'Teams' },
  ];

  const boxBg = useColorModeValue('gray.50', 'whiteAlpha.50');
  const boxBorder = useColorModeValue('gray.200', 'whiteAlpha.100');

  return (
    <VStack spacing={3} align='stretch'>
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={active ? { opacity: 1, y: 0 } : { opacity: 0, y: 10 }}
        transition={{ duration: 0.4 }}
      >
        <Box
          p={3}
          borderRadius='lg'
          bg={boxBg}
          border='1px solid'
          borderColor={boxBorder}
        >
          <Text color={textColorSecondary} fontSize='xs' mb={2}>
            Threshold
          </Text>
          <Badge
            bg={useColorModeValue('orange.100', badgeBg)}
            color={useColorModeValue('orange.800', badgeColor)}
            border='1px solid'
            borderColor={useColorModeValue('orange.300', badgeBorder)}
            fontWeight='bold'
            sx={{
              _light: {
                bg: 'orange.100 !important',
                color: 'orange.800 !important',
                borderColor: 'orange.300 !important',
              },
            }}
          >
            48 hours
          </Badge>
        </Box>
      </motion.div>

      <HStack spacing={2}>
        {channels.map((channel, index) => (
          <motion.div
            key={channel.label}
            initial={{ scale: 0, rotate: -180 }}
            animate={
              active ? { scale: 1, rotate: 0 } : { scale: 0, rotate: -180 }
            }
            transition={{ duration: 0.4, delay: index * 0.1 }}
            style={{ flex: 1 }}
          >
            <VStack
              spacing={1}
              p={2}
              borderRadius='lg'
              bg={boxBg}
              border='1px solid'
              borderColor={boxBorder}
            >
              <Icon as={channel.icon} w={4} h={4} color={textColorSecondary} />
              <Text color={textColorSecondary} fontSize='xs'>
                {channel.label}
              </Text>
            </VStack>
          </motion.div>
        ))}
      </HStack>
    </VStack>
  );
}

// Visual for Deliver step
function DeliverVisual({ active, _textColor, textColorSecondary }) {
  const boxBg = useColorModeValue('gray.50', 'whiteAlpha.50');
  const boxBorder = useColorModeValue('gray.200', 'whiteAlpha.100');
  const successBg = useColorModeValue('green.50', 'green.500/10');
  const successBorder = useColorModeValue('green.200', 'green.400/30');
  const successText = useColorModeValue('green.700', 'green.300');
  const successIcon = useColorModeValue('green.600', 'green.400');
  const successDot = useColorModeValue('green.500', 'green.400');

  return (
    <VStack spacing={3} align='stretch'>
      <motion.div
        initial={{ opacity: 0, scale: 0.9 }}
        animate={active ? { opacity: 1, scale: 1 } : { opacity: 0, scale: 0.9 }}
        transition={{ duration: 0.4 }}
      >
        <HStack
          spacing={3}
          p={3}
          borderRadius='lg'
          bg={successBg}
          border='1px solid'
          borderColor={successBorder}
        >
          <motion.div
            animate={active ? { rotate: 360 } : { rotate: 0 }}
            transition={{
              duration: 2,
              repeat: active ? Infinity : 0,
              ease: 'linear',
            }}
          >
            <Icon as={FiServer} w={4} h={4} color={successIcon} />
          </motion.div>
          <Text color={successText} fontSize='sm'>
            Queue Active
          </Text>
          <Box ml='auto'>
            <motion.div
              animate={
                active
                  ? { scale: [1, 1.5, 1], opacity: [1, 0.5, 1] }
                  : { scale: 1, opacity: 1 }
              }
              transition={{ duration: 1.5, repeat: active ? Infinity : 0 }}
            >
              <Box w={2} h={2} borderRadius='full' bg={successDot} />
            </motion.div>
          </Box>
        </HStack>
      </motion.div>
      <SimpleGrid columns={2} spacing={2}>
        <motion.div
          initial={{ opacity: 0, x: -10 }}
          animate={active ? { opacity: 1, x: 0 } : { opacity: 0, x: -10 }}
          transition={{ duration: 0.4, delay: 0.2 }}
        >
          <VStack
            spacing={1}
            p={2}
            borderRadius='md'
            bg={boxBg}
            border='1px solid'
            borderColor={boxBorder}
            textAlign='center'
          >
            <Icon
              as={FiRefreshCw}
              w={3}
              h={3}
              color={textColorSecondary}
              mx='auto'
              mb={1}
            />
            <Text color={textColorSecondary} fontSize='xs'>
              Retry
            </Text>
          </VStack>
        </motion.div>
        <motion.div
          initial={{ opacity: 0, x: 10 }}
          animate={active ? { opacity: 1, x: 0 } : { opacity: 0, x: 10 }}
          transition={{ duration: 0.4, delay: 0.3 }}
        >
          <VStack
            spacing={1}
            p={2}
            borderRadius='md'
            bg={boxBg}
            border='1px solid'
            borderColor={boxBorder}
            textAlign='center'
          >
            <Icon
              as={FiCheckCircle}
              w={3}
              h={3}
              color={successIcon}
              mx='auto'
              mb={1}
            />
            <Text color={textColorSecondary} fontSize='xs'>
              99.9% Up
            </Text>
          </VStack>
        </motion.div>
      </SimpleGrid>
    </VStack>
  );
}
