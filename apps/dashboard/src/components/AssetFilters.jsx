import { useState } from 'react';
import {
  Box,
  Button,
  Circle,
  Collapse,
  Divider,
  Flex,
  HStack,
  Input,
  InputGroup,
  InputLeftElement,
  Text,
  useBreakpointValue,
  useColorMode,
  useColorModeValue,
  VStack,
} from '@chakra-ui/react';
import { Archive, Search } from 'lucide-react';
import { getColorFromString } from '../styles/colors.js';
import { useDashboardTheme } from '../hooks/useDashboardTheme.js';
import {
  normInventoryValue,
  splitInventoryList,
} from '../utils/inventoryFilterCounts.js';

const STATUS_COLOR_SCHEMES = {
  all: 'blue',
  critical: 'red',
  due: 'orange',
  healthy: 'green',
  expired: 'gray',
};

const CHIP_MIN_HEIGHT = '32px';

const STATUS_CHIP_LAYOUT = {
  variant: 'unstyled',
  minH: CHIP_MIN_HEIGHT,
  h: 'auto',
  px: 3,
  py: 1,
  fontWeight: 'medium',
  borderRadius: 'md',
  borderWidth: '1px',
  borderStyle: 'solid',
  _focus: { boxShadow: 'none' },
  _focusVisible: { boxShadow: 'outline' },
};

function getFilterChipProps({
  colorScheme,
  active,
  isLight,
  filled = false,
  strongHover = false,
}) {
  if (strongHover) {
    if (active) {
      return {
        ...STATUS_CHIP_LAYOUT,
        fontWeight: 'semibold',
        bg: `${colorScheme}.600`,
        color: 'white',
        borderWidth: '2px',
        borderColor: isLight ? `${colorScheme}.800` : 'whiteAlpha.900',
        _hover: {
          bg: `${colorScheme}.700`,
          borderColor: isLight ? `${colorScheme}.900` : 'white',
          color: 'white',
        },
      };
    }

    return {
      ...STATUS_CHIP_LAYOUT,
      bg: isLight ? `${colorScheme}.100` : `${colorScheme}.900`,
      color: isLight ? `${colorScheme}.800` : `${colorScheme}.100`,
      borderColor: isLight ? `${colorScheme}.300` : `${colorScheme}.600`,
      _hover: {
        bg: isLight ? `${colorScheme}.200` : `${colorScheme}.800`,
        borderColor: isLight ? `${colorScheme}.500` : `${colorScheme}.500`,
        color: isLight ? `${colorScheme}.900` : `${colorScheme}.50`,
      },
    };
  }

  if (active) {
    return {
      variant: 'solid',
      colorScheme,
      color: 'white',
      borderColor: `${colorScheme}.500`,
      _hover: {
        bg: `${colorScheme}.600`,
        color: 'white',
      },
      _focus: { boxShadow: 'none' },
      _focusVisible: { boxShadow: 'outline' },
    };
  }

  if (filled && isLight) {
    return {
      variant: 'solid',
      bg: `${colorScheme}.500`,
      color: 'white',
      borderColor: `${colorScheme}.600`,
      opacity: 0.82,
      _hover: {
        opacity: 1,
        bg: `${colorScheme}.600`,
        borderColor: `${colorScheme}.700`,
      },
      _focus: { boxShadow: 'none' },
      _focusVisible: { boxShadow: 'outline' },
    };
  }

  return {
    variant: 'outline',
    colorScheme,
    bg: isLight ? `${colorScheme}.50` : `${colorScheme}.900`,
    color: isLight ? `${colorScheme}.700` : `${colorScheme}.200`,
    borderColor: isLight ? `${colorScheme}.300` : `${colorScheme}.600`,
    _hover: {
      bg: isLight ? `${colorScheme}.100` : `${colorScheme}.800`,
      borderColor: `${colorScheme}.500`,
    },
    _focus: { boxShadow: 'none' },
    _focusVisible: { boxShadow: 'outline' },
  };
}

function getStatusColorScheme(value) {
  return STATUS_COLOR_SCHEMES[value] || 'gray';
}

function getCategoryColorScheme(value, TOKEN_CATEGORIES) {
  return (
    TOKEN_CATEGORIES.find(category => category.value === value)?.color || 'gray'
  );
}

function getSectionColorScheme(section) {
  if (section.name === '__all__') return 'blue';
  if (section.name === '__none__') return 'gray';
  return getColorFromString(section.name);
}

function isSectionActive(section, currentSection) {
  const current = normInventoryValue(currentSection) || '__all__';
  const sectionNorm = normInventoryValue(section.name);

  if (sectionNorm === '__all__') {
    return current === '__all__';
  }
  if (sectionNorm === '__none__') {
    return current === '__none__';
  }
  return splitInventoryList(currentSection).some(
    part => normInventoryValue(part) === sectionNorm
  );
}

function getNextSectionValue(section, currentSection) {
  const currentVal = normInventoryValue(currentSection) || '__all__';
  const sectionNorm = normInventoryValue(section.name);

  if (sectionNorm === '__all__') {
    return '__all__';
  }
  if (sectionNorm === '__none__') {
    return '__none__';
  }

  let parts =
    currentVal === '__all__' || currentVal === '__none__'
      ? []
      : splitInventoryList(currentSection);

  const normalizedParts = parts.map(part => normInventoryValue(part));
  if (normalizedParts.includes(sectionNorm)) {
    parts = parts.filter((_, index) => normalizedParts[index] !== sectionNorm);
  } else {
    parts.push(section.name);
  }

  return parts.length > 0 ? parts.join(',') : '__all__';
}

function getNextCategoryValue(categoryValue, currentCategories) {
  const current = Array.isArray(currentCategories) ? currentCategories : [];
  // Single-select: clicking the active category clears it; otherwise it
  // replaces any previous selection so only one category is active at a time.
  return current.includes(categoryValue) ? [] : [categoryValue];
}

function ScrollableChipRow({ children, isMobileLayout }) {
  if (!isMobileLayout) {
    return (
      <HStack spacing={2} flexWrap='wrap'>
        {children}
      </HStack>
    );
  }

  // On mobile, wrap instead of horizontal scroll so every chip stays visible.
  return (
    <Flex gap={2} flexWrap='wrap' w='100%'>
      {children}
    </Flex>
  );
}

export default function AssetFilters({
  statusFilter,
  setStatusFilter,
  selectedCategories,
  setSelectedCategories,
  statusFilterOptions = [],
  categoryFilterOptions = [],
  sectionFilterOptions = [],
  panelQueries,
  setPanelQueries,
  TOKEN_CATEGORIES = [],
  categoryIcons = {},
  onGlobalSearchChange,
  onFilterReset,
  onSectionNavigate,
  showRetired = false,
  onToggleShowRetired,
  retiredCount = 0,
}) {
  const { colorMode } = useColorMode();
  const isLight = colorMode === 'light';
  const { inputBg, border: inputBorder, muted } = useDashboardTheme();
  const isMobileLayout = useBreakpointValue({ base: true, md: false });
  const [sectionsExpanded, setSectionsExpanded] = useState(false);

  const placeholderColor = muted;
  const filterLabelColor = useColorModeValue(
    'gray.600',
    'rgba(203, 213, 225, 0.86)'
  );
  const searchIconColor = useColorModeValue(
    'var(--chakra-colors-gray-500)',
    'rgba(148, 163, 184, 0.86)'
  );

  const notifyFilterReset = () => {
    if (typeof onFilterReset === 'function') {
      onFilterReset();
    }
  };

  const showSectionChips = !isMobileLayout || sectionsExpanded;

  return (
    <VStack spacing={3} align='stretch'>
      <Flex
        gap={3}
        align={{ base: 'stretch', lg: 'center' }}
        justify='space-between'
        direction={{ base: 'column', lg: 'row' }}
      >
        <HStack
          spacing={2}
          align='center'
          w={{ base: '100%', lg: 'auto' }}
          flexShrink={0}
        >
          <InputGroup maxW={{ base: '100%', lg: '320px' }} size='sm'>
            <InputLeftElement pointerEvents='none' h='32px'>
              <Search size={16} color={searchIconColor} />
            </InputLeftElement>
          <Input
            value={panelQueries.__global || ''}
            onChange={event => {
              const nextValue = event.target.value;
              setPanelQueries(prev => ({
                ...prev,
                __global: nextValue,
              }));
              if (typeof onGlobalSearchChange === 'function') {
                onGlobalSearchChange(nextValue);
              }
              notifyFilterReset();
            }}
            placeholder='Search assets, domains, owners...'
            size='sm'
            bg={inputBg}
            borderColor={inputBorder}
            borderRadius='md'
            pl='36px'
            minH={CHIP_MIN_HEIGHT}
            _placeholder={{ color: placeholderColor }}
          />
          </InputGroup>
          {(retiredCount > 0 || showRetired) &&
          typeof onToggleShowRetired === 'function' ? (
            <Button
              size='sm'
              flexShrink={0}
              borderRadius='md'
              minH={CHIP_MIN_HEIGHT}
              variant={showRetired ? 'solid' : 'outline'}
              colorScheme='gray'
              leftIcon={<Archive size={14} />}
              onClick={() => {
                onToggleShowRetired(!showRetired);
                notifyFilterReset();
              }}
              aria-pressed={showRetired}
              title='Show revoked and decommissioned certificates'
            >
              Retired
              <Box
                as='span'
                ml={2}
                px={1.5}
                borderRadius='sm'
                bg={showRetired ? 'whiteAlpha.300' : 'blackAlpha.200'}
                fontSize='xs'
                fontWeight='semibold'
                lineHeight='1.5'
              >
                {retiredCount}
              </Box>
            </Button>
          ) : null}
        </HStack>
        <ScrollableChipRow isMobileLayout={isMobileLayout}>
          {statusFilterOptions.map(option => {
            const active = statusFilter === option.value;
            const colorScheme = getStatusColorScheme(option.value);
            const isStatusChip = true;
            const chipProps = getFilterChipProps({
              colorScheme,
              active,
              isLight,
              strongHover: isStatusChip,
            });

            return (
              <Button
                key={option.value}
                size='sm'
                borderRadius='md'
                fontWeight='medium'
                flexShrink={0}
                onClick={() => {
                  setStatusFilter(option.value);
                  notifyFilterReset();
                }}
                {...chipProps}
              >
                {option.label}
                <Box
                  as='span'
                  ml={2}
                  px={1.5}
                  borderRadius='sm'
                  bg={
                    isStatusChip
                      ? active
                        ? 'whiteAlpha.300'
                        : isLight
                          ? `${colorScheme}.200`
                          : 'whiteAlpha.200'
                      : 'whiteAlpha.300'
                  }
                  color='inherit'
                  fontSize='xs'
                  fontWeight='semibold'
                  lineHeight='1.5'
                >
                  {option.count}
                </Box>
              </Button>
            );
          })}
        </ScrollableChipRow>
      </Flex>

      <Divider borderColor='rgba(148, 163, 184, 0.12)' />

      <Box>
        <Text fontSize='xs' color={filterLabelColor} mb={2}>
          Category
        </Text>
        <ScrollableChipRow isMobileLayout={isMobileLayout}>
          {categoryFilterOptions.map(category => {
            const active = selectedCategories.includes(category.value);
            const colorScheme = getCategoryColorScheme(
              category.value,
              TOKEN_CATEGORIES
            );
            const chipProps = getFilterChipProps({
              colorScheme,
              active,
              isLight,
            });
            const CategoryIcon = categoryIcons[category.value];

            return (
              <Button
                key={category.value}
                size='sm'
                borderRadius='md'
                fontWeight='medium'
                flexShrink={0}
                onClick={() => {
                  setSelectedCategories(prev =>
                    getNextCategoryValue(category.value, prev)
                  );
                  notifyFilterReset();
                }}
                {...chipProps}
              >
                {CategoryIcon ? (
                  <Box
                    as='span'
                    color={active ? 'white' : `${colorScheme}.400`}
                    display='inline-flex'
                  >
                    <CategoryIcon size={15} />
                  </Box>
                ) : null}
                <Box as='span' ml={CategoryIcon ? 2 : 0}>
                  {category.label}
                </Box>
                <Box
                  as='span'
                  ml={2}
                  px={1.5}
                  borderRadius='sm'
                  bg='whiteAlpha.200'
                  color='inherit'
                  fontSize='xs'
                  fontWeight='semibold'
                  lineHeight='1.5'
                >
                  {category.count}
                </Box>
              </Button>
            );
          })}
        </ScrollableChipRow>
      </Box>

      <Box>
        {isMobileLayout ? (
          <Button
            size='sm'
            variant='ghost'
            px={0}
            mb={2}
            h='auto'
            minH={CHIP_MIN_HEIGHT}
            fontWeight='medium'
            color={filterLabelColor}
            justifyContent='flex-start'
            onClick={() => setSectionsExpanded(open => !open)}
            aria-expanded={sectionsExpanded}
          >
            Sections
            <Text as='span' ml={2} fontSize='xs' color={muted}>
              {sectionsExpanded ? 'Hide' : 'Show'}
            </Text>
          </Button>
        ) : (
          <Text fontSize='xs' color={filterLabelColor} mb={2}>
            Sections
          </Text>
        )}
        <Collapse in={showSectionChips} animateOpacity>
          <HStack spacing={2} flexWrap='wrap'>
            {sectionFilterOptions.map(section => {
              const currentSection = panelQueries?.__section || '__all__';
              const active = isSectionActive(section, currentSection);
              const colorScheme = getSectionColorScheme(section);
              const chipProps = getFilterChipProps({
                colorScheme,
                active,
                isLight,
              });

              return (
                <Button
                  key={`section-${section.name || 'none'}`}
                  size='sm'
                  borderRadius='md'
                  fontWeight='medium'
                  flexShrink={0}
                  onClick={() => {
                    const next = getNextSectionValue(section, currentSection);
                    setPanelQueries(prev => ({ ...prev, __section: next }));
                    notifyFilterReset();
                    if (typeof onSectionNavigate === 'function') {
                      onSectionNavigate(next);
                    }
                  }}
                  {...chipProps}
                >
                  <Circle
                    size='7px'
                    bg={active ? 'white' : `${colorScheme}.400`}
                    mr={2}
                  />
                  {section.label}
                  {section.name !== '__all__' && (
                    <Box
                      as='span'
                      ml={2}
                      px={1.5}
                      borderRadius='sm'
                      bg='whiteAlpha.200'
                      color='inherit'
                      fontSize='xs'
                      fontWeight='semibold'
                      lineHeight='1.5'
                    >
                      {section.count}
                    </Box>
                  )}
                </Button>
              );
            })}
          </HStack>
        </Collapse>
      </Box>
    </VStack>
  );
}
