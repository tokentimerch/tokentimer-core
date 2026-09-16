import { useMemo } from 'react';
import {
  Button,
  HStack,
  Menu,
  MenuButton,
  MenuItem,
  MenuItemOption,
  MenuList,
  MenuOptionGroup,
  Text,
  useColorModeValue,
} from '@chakra-ui/react';
import { CheckIcon, ChevronDownIcon } from '@chakra-ui/icons';

/**
 * Reusable single- or multi-select dropdown (Chakra Menu).
 *
 * `value` is always `string[]`. Empty means no selection.
 * When `multiple` is false, choosing another option replaces the current one.
 */
export default function SelectMenu({
  options = [],
  value = [],
  onChange,
  multiple = false,
  isDisabled = false,
  placeholder = 'Select…',
  emptyText = 'No options available.',
  helperText = '',
  allowEmpty = true,
  emptyOptionLabel = 'None',
  size = 'sm',
  maxMenuH = '240px',
  matchWidth = true,
  buttonProps = {},
  menuListProps = {},
  'aria-label': ariaLabel,
}) {
  const helperColor = useColorModeValue('gray.600', 'gray.400');
  const buttonBorder = useColorModeValue('gray.300', 'whiteAlpha.300');
  const buttonBg = useColorModeValue('white', 'gray.800');
  const checkColor = useColorModeValue('blue.500', 'blue.300');
  const selected = useMemo(
    () => (Array.isArray(value) ? value.map(String) : []),
    [value]
  );
  const items = useMemo(
    () =>
      (Array.isArray(options) ? options : [])
        .filter(opt => opt && opt.value != null && String(opt.value) !== '')
        .map(opt => ({
          value: String(opt.value),
          label: opt.label == null ? String(opt.value) : String(opt.label),
        })),
    [options]
  );

  const labelByValue = useMemo(() => {
    const map = new Map(items.map(item => [item.value, item.label]));
    return map;
  }, [items]);

  const summary = useMemo(() => {
    if (selected.length === 0) return placeholder;
    if (!multiple || selected.length === 1) {
      return labelByValue.get(selected[0]) || selected[0];
    }
    if (selected.length <= 2) {
      return selected.map(id => labelByValue.get(id) || id).join(', ');
    }
    return `${selected.length} selected`;
  }, [selected, multiple, placeholder, labelByValue]);

  const groupValue = multiple
    ? selected
    : selected.length > 0
      ? selected[0]
      : '';

  const handleGroupChange = next => {
    if (multiple) {
      const ids = (Array.isArray(next) ? next : next == null ? [] : [next])
        .map(String)
        .filter(Boolean);
      onChange?.(ids);
      return;
    }
    const id = next == null ? '' : String(next);
    onChange?.(id ? [id] : []);
  };

  if (items.length === 0) {
    return (
      <Text fontSize='xs' color={helperColor}>
        {emptyText}
      </Text>
    );
  }

  return (
    <>
      <Menu
        closeOnSelect={!multiple}
        matchWidth={matchWidth}
        placement='bottom-start'
        strategy='fixed'
        gutter={4}
      >
        <MenuButton
          as={Button}
          size={size}
          variant='outline'
          w='100%'
          fontWeight='normal'
          isDisabled={isDisabled}
          bg={buttonBg}
          borderColor={buttonBorder}
          px={3}
          type='button'
          aria-label={ariaLabel || placeholder}
          title={
            selected.length > 2
              ? selected.map(id => labelByValue.get(id) || id).join(', ')
              : undefined
          }
          {...buttonProps}
        >
          <HStack w='100%' spacing={2} justify='space-between'>
            <Text
              as='span'
              flex='1'
              minW={0}
              textAlign='left'
              noOfLines={1}
              color={selected.length === 0 ? helperColor : 'inherit'}
            >
              {summary}
            </Text>
            <ChevronDownIcon
              boxSize='1.25em'
              flexShrink={0}
              opacity={0.85}
              aria-hidden
            />
          </HStack>
        </MenuButton>
        <MenuList
          maxH={maxMenuH}
          overflowY='auto'
          zIndex='popover'
          py={1}
          {...menuListProps}
        >
          {allowEmpty ? (
            <MenuItem
              fontSize={size}
              type='button'
              icon={
                selected.length === 0 ? (
                  <CheckIcon color={checkColor} boxSize='0.85em' />
                ) : undefined
              }
              onClick={() => onChange?.([])}
            >
              {emptyOptionLabel}
            </MenuItem>
          ) : null}
          <MenuOptionGroup
            type={multiple ? 'checkbox' : 'radio'}
            value={groupValue}
            onChange={handleGroupChange}
          >
            {items.map(item => (
              <MenuItemOption
                key={item.value}
                value={item.value}
                fontSize={size}
                icon={<CheckIcon color={checkColor} boxSize='0.85em' />}
              >
                {item.label}
              </MenuItemOption>
            ))}
          </MenuOptionGroup>
        </MenuList>
      </Menu>
      {helperText ? (
        <Text fontSize='xs' mt={1} color={helperColor}>
          {helperText}
        </Text>
      ) : null}
    </>
  );
}
