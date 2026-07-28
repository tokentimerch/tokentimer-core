import { useMemo } from 'react';
import {
  Button,
  Flex,
  HStack,
  IconButton,
  Select,
  Text,
  VisuallyHidden,
  useColorModeValue,
} from '@chakra-ui/react';
import { FiChevronRight } from 'react-icons/fi';
import { useDashboardThemeColors } from '../hooks/useDashboardTheme.js';

/** Page sizes offered when a caller does not supply its own. */
export const DEFAULT_PAGE_SIZE_OPTIONS = [10, 20, 50, 100];

/**
 * Shared page control for offset/limit lists.
 *
 * Deliberately stateless: it derives everything it shows from the numbers the
 * server reported and hands every change back through `onChange`, so the page
 * position can live wherever the caller keeps it (URL search params, local
 * state) without this component holding a second copy that can disagree.
 *
 * There is no `hasMore` prop. With a real `total`, "is there a next page" is
 * `offset + limit < total`, and a separate flag could only ever contradict it.
 *
 * @param {object} props
 * @param {number} props.limit - Rows per page currently in effect.
 * @param {number} [props.offset] - Zero-based index of the first row shown.
 * @param {number} [props.total] - Row count for the whole (filtered) list.
 * @param {(next: { limit: number, offset: number }) => void} props.onChange -
 *   Called with the full next page position; a page-size change resets the
 *   offset to 0, because keeping it would land the reader on a different row.
 * @param {number[]} [props.pageSizeOptions]
 * @param {string} [props.noun] - Plural noun for the rows, used in the
 *   accessible labels ("Next page of jobs") so a screen reader user with two
 *   lists on one tab can tell the controls apart.
 */
export default function DashboardPagination({
  limit,
  offset = 0,
  total = 0,
  onChange,
  pageSizeOptions = DEFAULT_PAGE_SIZE_OPTIONS,
  noun = 'items',
}) {
  const {
    muted: mutedTextColor,
    inputBg,
    border: inputBorder,
  } = useDashboardThemeColors();
  const controlColor = useColorModeValue(
    'gray.600',
    'rgba(203, 213, 225, 0.9)'
  );
  const controlHoverBg = useColorModeValue(
    'gray.100',
    'rgba(30, 41, 59, 0.72)'
  );
  const controlHoverColor = useColorModeValue('gray.900', 'white');
  const pageBg = useColorModeValue('blue.50', 'rgba(37, 99, 235, 0.18)');
  const pageColor = useColorModeValue('blue.700', 'white');
  const pageBorder = useColorModeValue('blue.200', 'rgba(59, 130, 246, 0.38)');

  const safeTotal = Math.max(0, Number(total) || 0);
  const requestedLimit = Number(limit);
  const pageSize =
    Number.isFinite(requestedLimit) && requestedLimit > 0
      ? Math.floor(requestedLimit)
      : pageSizeOptions[0] || 20;
  const safeOffset = Math.max(0, Number(offset) || 0);

  const pageCount = Math.max(1, Math.ceil(safeTotal / pageSize));
  const page = Math.min(pageCount, Math.floor(safeOffset / pageSize) + 1);
  const rangeStart = safeTotal === 0 ? 0 : safeOffset + 1;
  const rangeEnd = Math.min(safeOffset + pageSize, safeTotal);

  // A server may clamp the page size to a value the caller does not offer; the
  // select has to be able to show what is actually in effect.
  const sizeOptions = useMemo(() => {
    const merged = new Set(
      [...(pageSizeOptions || []), pageSize]
        .map(value => Number(value))
        .filter(value => Number.isFinite(value) && value > 0)
    );
    return Array.from(merged).sort((a, b) => a - b);
  }, [pageSizeOptions, pageSize]);

  const emit = next => {
    if (typeof onChange !== 'function') return;
    onChange(next);
  };

  return (
    <Flex
      as='nav'
      aria-label={`${noun} pagination`}
      align={{ base: 'stretch', md: 'center' }}
      justify={{ base: 'space-between', md: 'end' }}
      direction={{ base: 'column', sm: 'row' }}
      gap={3}
      flex='1'
      minW={0}
    >
      <HStack spacing={2}>
        <Text color={mutedTextColor} fontSize='sm'>
          Show
        </Text>
        <Select
          size='sm'
          w='84px'
          aria-label={`${noun} per page`}
          value={pageSize}
          bg={inputBg}
          borderColor={inputBorder}
          onChange={event =>
            emit({ limit: Number(event.target.value), offset: 0 })
          }
        >
          {sizeOptions.map(size => (
            <option key={size} value={size}>
              {size}
            </option>
          ))}
        </Select>
      </HStack>

      <HStack spacing={3} justify={{ base: 'space-between', sm: 'end' }}>
        <Text
          color={mutedTextColor}
          fontSize='sm'
          whiteSpace='nowrap'
          role='status'
          aria-live='polite'
        >
          <VisuallyHidden>
            {`Showing ${rangeStart} to ${rangeEnd} of ${safeTotal} ${noun}`}
          </VisuallyHidden>
          <Text as='span' aria-hidden='true'>
            {rangeStart}-{rangeEnd} of {safeTotal}
          </Text>
        </Text>
        <HStack spacing={1}>
          <IconButton
            aria-label={`Previous page of ${noun}`}
            icon={<FiChevronRight />}
            size='sm'
            variant='ghost'
            color={controlColor}
            isDisabled={safeOffset <= 0}
            onClick={() =>
              emit({
                limit: pageSize,
                offset: Math.max(0, safeOffset - pageSize),
              })
            }
            sx={{ svg: { transform: 'rotate(180deg)' } }}
            _hover={{
              bg: controlHoverBg,
              color: controlHoverColor,
            }}
          />
          <Button
            size='sm'
            variant='outline'
            borderColor={pageBorder}
            color={pageColor}
            bg={pageBg}
            minW='38px'
            aria-label={`Page ${page} of ${pageCount}`}
            // Not interactive: the surrounding arrows move the page. It exists
            // to say where the reader currently is.
            tabIndex={-1}
            pointerEvents='none'
          >
            {page}
          </Button>
          <IconButton
            aria-label={`Next page of ${noun}`}
            icon={<FiChevronRight />}
            size='sm'
            variant='ghost'
            color={controlColor}
            isDisabled={page >= pageCount}
            onClick={() =>
              emit({
                limit: pageSize,
                offset: Math.min(
                  (pageCount - 1) * pageSize,
                  safeOffset + pageSize
                ),
              })
            }
            _hover={{
              bg: controlHoverBg,
              color: controlHoverColor,
            }}
          />
        </HStack>
      </HStack>
    </Flex>
  );
}
