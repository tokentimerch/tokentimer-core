import {
  Badge,
  Box,
  Collapse,
  Flex,
  HStack,
  Icon,
  Text,
} from '@chakra-ui/react';
import { FiCheck, FiChevronDown, FiChevronUp, FiX } from 'react-icons/fi';
import { DashboardPanel } from './DashboardPrimitives';
import { useDashboardTheme } from '../hooks/useDashboardTheme';
import { SETTINGS_PANEL_PADDING } from '../styles/dashboardLayout';

export function SettingsIntegrationCard({
  title,
  description,
  icon,
  configured = false,
  isOpen = false,
  onToggle,
  children,
  tourTarget,
}) {
  const { muted, border, dashboard } = useDashboardTheme();
  const hoverBg = dashboard.bg.panelHover;

  return (
    <DashboardPanel p={0} overflow='hidden' data-tour={tourTarget}>
      <Flex
        as='button'
        type='button'
        w='full'
        textAlign='left'
        px={SETTINGS_PANEL_PADDING}
        py={{ base: 5, md: 6 }}
        align='center'
        gap={5}
        onClick={onToggle}
        _hover={{ bg: hoverBg }}
        transition='background 0.15s ease'
      >
        {icon ? (
          <Flex
            align='center'
            justify='center'
            boxSize='48px'
            borderRadius='md'
            bg={dashboard.accent.interactiveSurface}
            flexShrink={0}
          >
            {icon}
          </Flex>
        ) : null}
        <Box flex='1' minW={0}>
          <HStack spacing={2} flexWrap='wrap' mb={1}>
            <Text fontWeight='bold' fontSize='md'>
              {title}
            </Text>
            {configured ? (
              <Badge
                colorScheme='green'
                display='flex'
                alignItems='center'
                gap={1}
              >
                <FiCheck size={12} /> Configured
              </Badge>
            ) : (
              <Badge
                colorScheme='orange'
                display='flex'
                alignItems='center'
                gap={1}
              >
                <FiX size={12} /> Not configured
              </Badge>
            )}
          </HStack>
          {description ? (
            <Text fontSize='sm' color={muted} lineHeight='1.5'>
              {description}
            </Text>
          ) : null}
        </Box>
        <Icon
          as={isOpen ? FiChevronUp : FiChevronDown}
          boxSize={5}
          color={muted}
          flexShrink={0}
        />
      </Flex>
      <Collapse in={isOpen} animateOpacity>
        <Box
          px={SETTINGS_PANEL_PADDING}
          pb={SETTINGS_PANEL_PADDING}
          pt={SETTINGS_PANEL_PADDING}
          borderTop='1px solid'
          borderColor={border}
        >
          {children}
        </Box>
      </Collapse>
    </DashboardPanel>
  );
}
