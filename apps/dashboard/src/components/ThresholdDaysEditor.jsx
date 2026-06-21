import { useRef, useState } from 'react';
import {
  Box,
  Flex,
  FormControl,
  FormErrorMessage,
  IconButton,
  Input,
  Text,
} from '@chakra-ui/react';
import { FiX } from 'react-icons/fi';
import { useDashboardTheme } from '../hooks/useDashboardTheme';
import {
  formatThresholdChipLabel,
  formatThresholdLabel,
  getThresholdDraftError,
  MAX_ALERT_THRESHOLD_DAYS,
  MIN_ALERT_THRESHOLD_DAYS,
  normalizeThresholds,
  parseThresholdDraft,
} from '../utils/alertThresholds.js';

const THRESHOLD_HELPER_TEXT =
  'Positive = days before expiry. 0 = on expiry. Negative = days after. Press Enter to add.';

export default function ThresholdDaysEditor({
  value,
  onChange,
  isDisabled = false,
  isInvalid = false,
  errorMessage = '',
  inheritHint = '',
  minCount = 1,
}) {
  const { muted, border, dashboard } = useDashboardTheme();
  const inputRef = useRef(null);
  const [draft, setDraft] = useState('');
  const [draftError, setDraftError] = useState('');
  const thresholds = normalizeThresholds(value);

  const chipBg = dashboard.bg.panelHover;
  const chipBorder = border;

  const updateThresholds = next => {
    onChange(normalizeThresholds(next));
    setDraftError('');
  };

  const handleAdd = days => {
    if (isDisabled) return;
    if (thresholds.includes(days)) {
      setDraftError('That threshold is already added.');
      return;
    }
    updateThresholds([...thresholds, days]);
    setDraft('');
  };

  const handleRemove = days => {
    if (isDisabled) return;
    const next = thresholds.filter(entry => entry !== days);
    if (minCount > 0 && next.length < minCount) return;
    updateThresholds(next);
  };

  const handleAddDraft = () => {
    const parsed = parseThresholdDraft(draft);
    if (parsed === null) {
      if (String(draft).trim()) {
        setDraftError(getThresholdDraftError());
      }
      return;
    }
    handleAdd(parsed);
  };

  const handleKeyDown = event => {
    if (event.key === 'Enter') {
      event.preventDefault();
      handleAddDraft();
      return;
    }
    if (
      event.key === 'Backspace' &&
      !String(draft).trim() &&
      thresholds.length > minCount
    ) {
      handleRemove(thresholds[thresholds.length - 1]);
    }
  };

  const activeError = draftError || errorMessage;
  const showFieldError = Boolean(activeError);

  return (
    <FormControl isInvalid={isInvalid || showFieldError} isDisabled={isDisabled}>
      <Box
        border='1px solid'
        borderColor={showFieldError ? 'red.400' : border}
        borderRadius='md'
        bg={dashboard.bg.field}
        px={3}
        py={2}
        minH='42px'
        cursor={isDisabled ? 'not-allowed' : 'text'}
        transition='border-color 120ms ease, box-shadow 120ms ease'
        onClick={() => {
          if (!isDisabled) inputRef.current?.focus();
        }}
        _focusWithin={
          isDisabled
            ? undefined
            : showFieldError
              ? {
                  borderColor: 'red.400',
                  boxShadow: '0 0 0 1px var(--chakra-colors-red-400)',
                }
              : {
                  borderColor: dashboard.accent.navActive,
                  boxShadow: `0 0 0 1px ${dashboard.accent.navActive}`,
                }
        }
      >
        <Flex wrap='wrap' gap={1.5} align='center'>
          {thresholds.map(days => (
            <Flex
              key={days}
              align='center'
              gap={1}
              px={2}
              py='3px'
              borderRadius='md'
              border='1px solid'
              borderColor={chipBorder}
              bg={chipBg}
              maxW='100%'
            >
              <Text fontSize='sm' lineHeight='short' whiteSpace='nowrap'>
                {formatThresholdChipLabel(days)}
              </Text>
              {!isDisabled ? (
                <IconButton
                  aria-label={`Remove ${formatThresholdLabel(days)}`}
                  icon={<FiX />}
                  size='xs'
                  variant='ghost'
                  minW='18px'
                  h='18px'
                  color={muted}
                  _hover={{ color: 'inherit', bg: 'blackAlpha.100' }}
                  onMouseDown={event => event.preventDefault()}
                  onClick={event => {
                    event.stopPropagation();
                    handleRemove(days);
                  }}
                />
              ) : null}
            </Flex>
          ))}

          {!isDisabled ? (
            <Input
              ref={inputRef}
              variant='unstyled'
              size='sm'
              flex='1'
              minW='72px'
              maxW={{ base: '100%', sm: '120px' }}
              h='28px'
              px={1}
              value={draft}
              inputMode='numeric'
              placeholder={thresholds.length ? 'Add days…' : 'e.g. 30, 0, -7'}
              aria-invalid={showFieldError ? true : undefined}
              onChange={event => {
                setDraft(event.target.value);
                if (draftError) setDraftError('');
              }}
              onKeyDown={handleKeyDown}
            />
          ) : null}
        </Flex>

        {activeError ? (
          <FormErrorMessage mt={2} mb={0} display='block'>
            {activeError}
          </FormErrorMessage>
        ) : null}
      </Box>

      <Text fontSize='xs' color={muted} mt={2} lineHeight='1.45'>
        {THRESHOLD_HELPER_TEXT}
      </Text>
      {inheritHint ? (
        <Text fontSize='xs' color={muted} mt={1} lineHeight='1.45'>
          {inheritHint}
        </Text>
      ) : null}
    </FormControl>
  );
}
