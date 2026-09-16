import { useMemo, useRef } from 'react';
import {
  Box,
  Button,
  HStack,
  Popover,
  PopoverBody,
  PopoverContent,
  PopoverTrigger,
  Text,
  useColorModeValue,
  useDisclosure,
  useOutsideClick,
} from '@chakra-ui/react';
import { CheckIcon, ChevronDownIcon } from '@chakra-ui/icons';

/**
 * Reusable single- or multi-select dropdown.
 *
 * `value` is always `string[]`. Empty means no selection.
 * When `multiple` is false, choosing another option replaces the current one.
 *
 * Popover (not Menu) so it works inside Chakra Modals. closeOnBlur is off:
 * with the default on, a modal + portaled list closes on mousedown before the
 * option handler runs, which looks like a stuck "Workspace default".
 * Selection runs on pointerdown (not click) so preventDefault can keep focus
 * without cancelling the gesture.
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
  const { isOpen, onOpen, onClose } = useDisclosure();
  const contentRef = useRef(null);
  const triggerRef = useRef(null);
  const helperColor = useColorModeValue('gray.600', 'gray.400');
  const buttonBorder = useColorModeValue('gray.300', 'whiteAlpha.300');
  const buttonBg = useColorModeValue('white', 'gray.800');
  const listBg = useColorModeValue('white', 'gray.800');
  const listBorder = useColorModeValue('gray.200', 'whiteAlpha.300');
  const hoverBg = useColorModeValue('gray.100', 'whiteAlpha.100');
  const checkColor = useColorModeValue('blue.500', 'blue.300');
  const selected = useMemo(
    () => (Array.isArray(value) ? value.map(String) : []),
    [value]
  );
  const selectedSet = useMemo(() => new Set(selected), [selected]);
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

  useOutsideClick({
    ref: contentRef,
    handler: event => {
      if (triggerRef.current?.contains(event.target)) return;
      onClose();
    },
    enabled: isOpen,
  });

  const chooseEmpty = event => {
    event.preventDefault();
    onChange?.([]);
    if (!multiple) onClose();
  };

  const toggleValue = (event, id) => {
    event.preventDefault();
    if (multiple) {
      if (selectedSet.has(id)) {
        onChange?.(selected.filter(v => v !== id));
      } else {
        onChange?.([...selected, id]);
      }
      return;
    }
    onChange?.([id]);
    onClose();
  };

  if (items.length === 0) {
    return (
      <Text fontSize='xs' color={helperColor}>
        {emptyText}
      </Text>
    );
  }

  return (
    <Box w='100%' minW={0} maxW='100%'>
      <Popover
        isOpen={isOpen}
        onOpen={onOpen}
        onClose={onClose}
        placement='bottom-start'
        strategy='fixed'
        gutter={4}
        matchWidth={matchWidth}
        closeOnBlur={false}
        closeOnEsc
        returnFocusOnClose={false}
        isLazy={false}
      >
        <PopoverTrigger>
          <Button
            ref={triggerRef}
            size={size}
            variant='outline'
            w='100%'
            maxW='100%'
            minW={0}
            overflow='hidden'
            fontWeight='normal'
            isDisabled={isDisabled}
            bg={buttonBg}
            borderColor={buttonBorder}
            px={3}
            type='button'
            aria-label={ariaLabel || placeholder}
            aria-expanded={isOpen}
            aria-haspopup='listbox'
            title={
              selected.length > 0
                ? selected.map(id => labelByValue.get(id) || id).join(', ')
                : undefined
            }
            {...buttonProps}
          >
            <HStack
              w='100%'
              minW={0}
              spacing={2}
              justify='space-between'
              overflow='hidden'
            >
              <Text
                as='span'
                flex='1'
                minW={0}
                textAlign='left'
                noOfLines={1}
                overflow='hidden'
                textOverflow='ellipsis'
                whiteSpace='nowrap'
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
          </Button>
        </PopoverTrigger>
        <PopoverContent
          ref={contentRef}
          w={matchWidth ? '100%' : undefined}
          maxW='100vw'
          bg={listBg}
          borderColor={listBorder}
          zIndex='popover'
          _focus={{ boxShadow: 'none' }}
          {...menuListProps}
        >
          <PopoverBody p={1} maxH={maxMenuH} overflowY='auto' role='listbox'>
            {allowEmpty ? (
              <Box
                as='button'
                type='button'
                w='100%'
                display='flex'
                alignItems='center'
                gap={2}
                px={3}
                py={2}
                borderRadius='md'
                fontSize={size}
                textAlign='left'
                bg='transparent'
                _hover={{ bg: hoverBg }}
                onPointerDown={chooseEmpty}
              >
                <Box w='0.85em' flexShrink={0}>
                  {selected.length === 0 ? (
                    <CheckIcon color={checkColor} boxSize='0.85em' />
                  ) : null}
                </Box>
                <Text as='span' noOfLines={1}>
                  {emptyOptionLabel}
                </Text>
              </Box>
            ) : null}
            {items.map(item => {
              const isSelected = selectedSet.has(item.value);
              return (
                <Box
                  key={item.value}
                  as='button'
                  type='button'
                  w='100%'
                  display='flex'
                  alignItems='center'
                  gap={2}
                  px={3}
                  py={2}
                  borderRadius='md'
                  fontSize={size}
                  textAlign='left'
                  bg='transparent'
                  _hover={{ bg: hoverBg }}
                  onPointerDown={event => toggleValue(event, item.value)}
                  aria-selected={isSelected}
                >
                  <Box w='0.85em' flexShrink={0}>
                    {isSelected ? (
                      <CheckIcon color={checkColor} boxSize='0.85em' />
                    ) : null}
                  </Box>
                  <Text as='span' noOfLines={1}>
                    {item.label}
                  </Text>
                </Box>
              );
            })}
          </PopoverBody>
        </PopoverContent>
      </Popover>
      {helperText ? (
        <Text fontSize='xs' mt={1} color={helperColor}>
          {helperText}
        </Text>
      ) : null}
    </Box>
  );
}
