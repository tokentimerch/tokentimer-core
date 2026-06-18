import { useCallback, useEffect, useState } from 'react';
import {
  Box,
  Button,
  Divider,
  Flex,
  HStack,
  Icon,
  Select,
  Text,
  VStack,
  useColorModeValue,
} from '@chakra-ui/react';
import { useDashboardTheme } from '../hooks/useDashboardTheme';
import {
  SETTINGS_NESTED_RADIUS,
  SETTINGS_PANEL_PADDING,
  SETTINGS_SECTION_GAP,
} from '../styles/dashboardLayout';
import { dashboardThemeColors } from '../styles/theme.js';

function scrollToSettingsSection(sectionId) {
  if (!sectionId) return;
  const el = document.getElementById(sectionId);
  if (!el) return;
  el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  if (window.history?.replaceState) {
    window.history.replaceState(null, '', `#${sectionId}`);
  } else {
    window.location.hash = sectionId;
  }
}

/**
 * Settings page wrapper. Pass `sections` only when a sticky section nav is
 * warranted on very wide layouts; otherwise children stack full width.
 */
export function SettingsPageShell({
  sections = [],
  intro = null,
  quickConfig = null,
  sidebarIntro = null,
  children,
}) {
  const { surface, border, muted, dashboard } = useDashboardTheme();
  const navBg = dashboard.bg.nested;
  const activeBg = useColorModeValue(
    dashboardThemeColors.accent.interactiveSurface.light,
    dashboardThemeColors.bg.panelHover.dark
  );
  const activeColor = dashboard.accent.navActive;
  const [activeId, setActiveId] = useState(sections[0]?.id || '');

  useEffect(() => {
    if (!sections.length) return undefined;
    const hash = window.location.hash.replace(/^#/, '');
    if (hash && sections.some(s => s.id === hash)) {
      setActiveId(hash);
      const timer = window.setTimeout(() => scrollToSettingsSection(hash), 120);
      return () => window.clearTimeout(timer);
    }
    return undefined;
  }, [sections]);

  useEffect(() => {
    if (!sections.length) return undefined;

    const observer = new IntersectionObserver(
      entries => {
        const visible = entries
          .filter(entry => entry.isIntersecting)
          .sort((a, b) => b.intersectionRatio - a.intersectionRatio);
        if (visible[0]?.target?.id) {
          setActiveId(visible[0].target.id);
        }
      },
      { rootMargin: '-20% 0px -55% 0px', threshold: [0.1, 0.35, 0.6] }
    );

    sections.forEach(section => {
      const el = document.getElementById(section.id);
      if (el) observer.observe(el);
    });

    return () => observer.disconnect();
  }, [sections]);

  const handleNavClick = useCallback(sectionId => {
    setActiveId(sectionId);
    scrollToSettingsSection(sectionId);
  }, []);

  if (!sections.length) {
    return (
      <Box w='full'>
        {(intro || quickConfig) && (
          <Box mb={SETTINGS_SECTION_GAP}>
            {intro}
            {quickConfig}
          </Box>
        )}
        <VStack align='stretch' spacing={SETTINGS_SECTION_GAP} w='full'>
          {children}
        </VStack>
      </Box>
    );
  }

  return (
    <Flex
      align='flex-start'
      gap={{ base: 4, lg: 8 }}
      w='full'
      direction={{ base: 'column', lg: 'row' }}
    >
      <Box
        display={{ base: 'block', lg: 'none' }}
        w='full'
        position='sticky'
        top='0'
        zIndex={2}
        bg={surface}
        py={2}
        mx={-1}
        px={1}
      >
        <Select
          size='sm'
          value={activeId}
          onChange={e => handleNavClick(e.target.value)}
          aria-label='Settings section'
        >
          {sections.map(section => (
            <option key={section.id} value={section.id}>
              {section.label}
            </option>
          ))}
        </Select>
      </Box>

      <Box
        display={{ base: 'none', lg: 'block' }}
        w='240px'
        flexShrink={0}
        position='sticky'
        top='16px'
        alignSelf='flex-start'
      >
        <Box
          border='1px solid'
          borderColor={border}
          borderRadius='md'
          bg={navBg}
          p={2}
        >
          {sidebarIntro ? (
            <>
              <Box px={1} pb={2}>
                {sidebarIntro}
              </Box>
              <Box px={1} pb={2}>
                <Divider opacity={0.65} />
              </Box>
            </>
          ) : null}
          <Text
            px={2}
            py={1}
            fontSize='xs'
            fontWeight='semibold'
            letterSpacing='0.06em'
            textTransform='uppercase'
            color={muted}
          >
            Sections
          </Text>
          <VStack align='stretch' spacing={1} mt={1}>
            {sections.map(section => {
              const isActive = activeId === section.id;
              return (
                <Button
                  key={section.id}
                  size='sm'
                  variant='ghost'
                  justifyContent='flex-start'
                  alignItems='flex-start'
                  height='auto'
                  py={2}
                  fontWeight={isActive ? 'semibold' : 'medium'}
                  bg={isActive ? activeBg : 'transparent'}
                  color={isActive ? activeColor : 'inherit'}
                  onClick={() => handleNavClick(section.id)}
                  data-tour={section.tourTarget}
                >
                  <HStack align='flex-start' spacing={2} w='full'>
                    {section.icon ? (
                      <Icon
                        as={section.icon}
                        boxSize={3.5}
                        mt='2px'
                        flexShrink={0}
                        opacity={isActive ? 1 : 0.72}
                      />
                    ) : null}
                    <Box minW={0} textAlign='left'>
                      <Text fontSize='sm' lineHeight='short'>
                        {section.label}
                      </Text>
                      {section.description ? (
                        <Text
                          fontSize='xs'
                          color={muted}
                          fontWeight='normal'
                          lineHeight='1.4'
                          mt={0.5}
                          noOfLines={2}
                        >
                          {section.description}
                        </Text>
                      ) : null}
                    </Box>
                  </HStack>
                </Button>
              );
            })}
          </VStack>
        </Box>
      </Box>

      <Box flex='1' minW={0} w='full'>
        {(intro || quickConfig) && (
          <Box mb={SETTINGS_SECTION_GAP}>
            {intro}
            {quickConfig}
          </Box>
        )}
        <VStack align='stretch' spacing={SETTINGS_SECTION_GAP} w='full'>
          {children}
        </VStack>
      </Box>
    </Flex>
  );
}

/** Anchor target for in-page nav / hash deep links. */
export function SettingsSection({ id, children, ...props }) {
  return (
    <Box id={id} scrollMarginTop='88px' w='full' {...props}>
      {children}
    </Box>
  );
}

/** Shared nested-surface tokens (matches Control Center / Audit panels). */
export function useSettingsNestedTheme() {
  const { border, dashboard, surface } = useDashboardTheme();
  const nestedSurfaceBg = dashboard.bg.nested;
  const nestedFieldBg = dashboard.bg.field;

  return {
    panelBorder: border,
    nestedSurfaceBg,
    nestedFieldBg,
    surface,
  };
}

/** Nested card inside a settings panel (webhooks, contacts, etc.). */
export function SettingsNestedSurface({ borderColor, bg, children, ...props }) {
  const { panelBorder, nestedSurfaceBg } = useSettingsNestedTheme();

  return (
    <Box
      w='full'
      p={SETTINGS_PANEL_PADDING}
      borderRadius={SETTINGS_NESTED_RADIUS}
      border='1px solid'
      borderColor={borderColor ?? panelBorder}
      bg={bg ?? nestedSurfaceBg}
      {...props}
    >
      {children}
    </Box>
  );
}

/** Left-aligned readable width for forms (not page-centered). */
export function SettingsFormWidth({ children, maxW = '760px', ...props }) {
  return (
    <Box w='full' maxW={{ base: '100%', xl: maxW }} {...props}>
      {children}
    </Box>
  );
}
