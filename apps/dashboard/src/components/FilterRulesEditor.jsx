import {
  Box,
  Button,
  HStack,
  IconButton,
  Input,
  Select,
  Text,
  VStack,
  Badge,
} from '@chakra-ui/react';
import { FiPlus, FiTrash2 } from 'react-icons/fi';

const MAX_RULES = 50;

export function isValidFilterRule(rule) {
  if (!rule || typeof rule.value !== 'string' || rule.value.length === 0) {
    return false;
  }
  if (rule.matchType === 'regex') {
    try {
      new RegExp(rule.value);
    } catch (_) {
      return false;
    }
  }
  return true;
}

/**
 * Returns only the complete, valid rules from the editor state, ready to be
 * sent to the API. Incomplete rows (empty value, invalid regex) are dropped.
 */
export function sanitizeFilterRules(rules) {
  if (!Array.isArray(rules)) return [];
  return rules.filter(isValidFilterRule).map(r => ({
    action: r.action,
    matchType: r.matchType,
    field: r.field,
    value: r.value,
  }));
}

/**
 * Ordered include/exclude rule editor (issue #69).
 * Rules: { action: 'include'|'exclude', matchType: 'regex'|'exact',
 *          field: 'name'|'description', value: string }
 * Exclude rules win; if any include rule exists, items must match one.
 */
export default function FilterRulesEditor({
  rules = [],
  onChange,
  borderColor,
  helpTextColor,
}) {
  const addRule = () => {
    if (rules.length >= MAX_RULES) return;
    onChange([
      ...rules,
      { action: 'exclude', matchType: 'exact', field: 'name', value: '' },
    ]);
  };

  const updateRule = (index, patch) => {
    const next = rules.map((r, i) => (i === index ? { ...r, ...patch } : r));
    onChange(next);
  };

  const removeRule = index => {
    onChange(rules.filter((_, i) => i !== index));
  };

  const regexError = rule => {
    if (rule.matchType !== 'regex' || !rule.value) return null;
    try {
      new RegExp(rule.value);
      return null;
    } catch (e) {
      return e.message;
    }
  };

  const hasIncludeRules = rules.some(r => r.action === 'include');

  return (
    <Box border='1px solid' borderColor={borderColor} borderRadius='md' p={3}>
      <HStack justify='space-between' mb={2}>
        <Text fontSize='sm' fontWeight='medium'>
          Filter rules
        </Text>
        <Button
          size='xs'
          leftIcon={<FiPlus />}
          variant='outline'
          onClick={addRule}
          isDisabled={rules.length >= MAX_RULES}
        >
          Add rule
        </Button>
      </HStack>
      <Text fontSize='xs' color={helpTextColor} mb={rules.length > 0 ? 3 : 0}>
        Rules apply to scan results before import. Exclude rules always win.
        {hasIncludeRules
          ? ' Since include rules are defined, only items matching an include rule are kept.'
          : ' Without include rules, everything not excluded is kept.'}
      </Text>
      {rules.length > 0 && (
        <VStack align='stretch' spacing={2}>
          {rules.map((rule, i) => {
            const err = regexError(rule);
            return (
              <Box key={i}>
                <HStack spacing={2} align='center' flexWrap='wrap'>
                  <Select
                    size='xs'
                    w='96px'
                    value={rule.action}
                    onChange={e => updateRule(i, { action: e.target.value })}
                  >
                    <option value='include'>Include</option>
                    <option value='exclude'>Exclude</option>
                  </Select>
                  <Select
                    size='xs'
                    w='110px'
                    value={rule.field}
                    onChange={e => updateRule(i, { field: e.target.value })}
                  >
                    <option value='name'>Name</option>
                    <option value='description'>Description</option>
                  </Select>
                  <Select
                    size='xs'
                    w='96px'
                    value={rule.matchType}
                    onChange={e => updateRule(i, { matchType: e.target.value })}
                  >
                    <option value='exact'>Exact</option>
                    <option value='regex'>Regex</option>
                  </Select>
                  <Input
                    size='xs'
                    flex='1'
                    minW='140px'
                    placeholder={
                      rule.matchType === 'regex'
                        ? 'e.g. ^iac-provisioned:.*'
                        : 'exact value'
                    }
                    value={rule.value}
                    maxLength={500}
                    isInvalid={Boolean(err)}
                    onChange={e => updateRule(i, { value: e.target.value })}
                  />
                  <IconButton
                    size='xs'
                    variant='ghost'
                    colorScheme='red'
                    icon={<FiTrash2 />}
                    aria-label='Remove rule'
                    onClick={() => removeRule(i)}
                  />
                </HStack>
                {err ? (
                  <Badge colorScheme='red' fontSize='2xs' mt={1}>
                    Invalid regex: {err}
                  </Badge>
                ) : null}
              </Box>
            );
          })}
        </VStack>
      )}
    </Box>
  );
}
