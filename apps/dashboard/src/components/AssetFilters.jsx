import {
  Badge,
  Box,
  Button,
  Circle,
  Divider,
  Flex,
  HStack,
  Input,
  InputGroup,
  InputLeftElement,
  Text,
  useColorMode,
  useColorModeValue,
  VStack,
} from '@chakra-ui/react';
import { Search } from 'lucide-react';
import { getColorFromString } from '../styles/colors.js';
import { useDashboardTheme } from '../hooks/useDashboardTheme.js';

const STATUS_COLOR_SCHEMES = {
  all: 'blue',
  critical: 'red',
  due: 'orange',
  healthy: 'green',
  expired: 'gray',
};

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

function getFilterChipProps({ colorScheme, active, isLight, filled = false }) {
  if (active) {
    return {
      variant: 'solid',
      colorScheme,
      color: 'white',
      borderColor: `${colorScheme}.500`,
      _hover: {
        bg: `${colorScheme}.600`,
      },
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
  };
}

function isSectionActive(section, currentSection) {
  const current = currentSection || '__all__';

  if (section.name === '__all__') {
    return current === '__all__';
  }
  if (section.name === '__none__') {
    return current === '__none__';
  }
  return current.split(',').includes(section.name);
}

function getNextSectionValue(section, currentSection) {
  const currentVal = currentSection || '__all__';

  if (section.name === '__all__') {
    return '__all__';
  }
  if (section.name === '__none__') {
    return '__none__';
  }

  let parts =
    currentVal === '__all__' || currentVal === '__none__'
      ? []
      : currentVal.split(',').filter(Boolean);

  if (parts.includes(section.name)) {
    parts = parts.filter(part => part !== section.name);
  } else {
    parts.push(section.name);
  }

  return parts.length > 0 ? parts.join(',') : '__all__';
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
}) {
  const { colorMode } = useColorMode();
  const isLight = colorMode === 'light';
  const { inputBg, border: inputBorder, muted } = useDashboardTheme();

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

  return (
    <VStack spacing={3} align='stretch'>
      <Flex
        gap={3}
        align={{ base: 'stretch', lg: 'center' }}
        justify='space-between'
        direction={{ base: 'column', lg: 'row' }}
      >
        <InputGroup maxW={{ base: '100%', lg: '360px' }} size='sm'>
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
            _placeholder={{ color: placeholderColor }}
          />
        </InputGroup>
        <HStack spacing={2} flexWrap='wrap'>
          {statusFilterOptions.map(option => {
            const active = statusFilter === option.value;
            const colorScheme = getStatusColorScheme(option.value);
            const chipProps = getFilterChipProps({
              colorScheme,
              active,
              isLight,
            });

            return (
              <Button
                key={option.value}
                size='xs'
                borderRadius='md'
                fontWeight='medium'
                onClick={() => {
                  setStatusFilter(option.value);
                  notifyFilterReset();
                }}
                {...chipProps}
              >
                <Circle
                  size='7px'
                  bg={active ? 'white' : `${colorScheme}.400`}
                  mr={2}
                />
                {option.label}
                <Badge ml={2} bg='whiteAlpha.200' color='inherit'>
                  {option.count}
                </Badge>
              </Button>
            );
          })}
        </HStack>
      </Flex>

      <Divider borderColor='rgba(148, 163, 184, 0.12)' />

      <Box>
        <Text fontSize='xs' color={filterLabelColor} mb={2}>
          Category
        </Text>
        <HStack spacing={2} flexWrap='wrap'>
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
                onClick={() => {
                  setSelectedCategories(active ? [] : [category.value]);
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
                <Text as='span' ml={CategoryIcon ? 2 : 0}>
                  {category.label}
                </Text>
                <Badge ml={2} bg='whiteAlpha.200' color='inherit'>
                  {category.count}
                </Badge>
              </Button>
            );
          })}
        </HStack>
      </Box>

      <Box>
        <Text fontSize='xs' color={filterLabelColor} mb={2}>
          Sections
        </Text>
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
                <Badge ml={2} bg='whiteAlpha.200' color='inherit'>
                  {section.count}
                </Badge>
              </Button>
            );
          })}
        </HStack>
      </Box>
    </VStack>
  );
}
