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

// ReDoS hardening (issue #69 follow-up): mirrors the same heuristic used
// server-side in importFilterRules.js so the UI can reject an obviously
// unsafe pattern immediately, instead of only finding out on server
// round-trip. Keep this logically identical to the server-side check.
const MAX_REGEX_QUANTIFIERS = 10;
const MAX_REGEX_GROUPS = 10;

/**
 * Accepts a regex value either as a bare pattern (`^foo`) or as a full
 * JavaScript regex literal (`/^foo/i`), mirroring the server-side parser
 * in importFilterRules.js so previews match what actually runs on import.
 */
export function parseRegexValue(value) {
  const src = typeof value === 'string' ? value : '';
  const match = /^\/(.+)\/([a-z]*)$/s.exec(src);
  if (match && /^[gimsuy]*$/.test(match[2])) {
    return { pattern: match[1], flags: match[2] };
  }
  return { pattern: src, flags: '' };
}

export function findUnsafeRegexReason(pattern) {
  const src = typeof pattern === 'string' ? pattern : '';
  let inClass = false;
  let quantifierCount = 0;
  let groupCount = 0;
  const groupStack = [];
  let i = 0;
  const len = src.length;

  const readBoundedQuantifier = pos => {
    const close = src.indexOf('}', pos);
    if (close === -1) return null;
    const inner = src.slice(pos + 1, close);
    if (!/^\d+(,\d*)?$/.test(inner)) return null;
    const parts = inner.split(',');
    const repeatsMoreThanOnce =
      parts.length === 1
        ? Number(parts[0]) > 1
        : (parts[1] === '' ? Infinity : Number(parts[1])) > 1;
    return { end: close, repeatsMoreThanOnce };
  };

  while (i < len) {
    const ch = src[i];
    if (ch === '\\') {
      i += 2;
      continue;
    }
    if (inClass) {
      if (ch === ']') inClass = false;
      i++;
      continue;
    }
    if (ch === '[') {
      inClass = true;
      i++;
      continue;
    }
    if (ch === '(') {
      groupStack.push({ hasQuantifier: false });
      groupCount++;
      i++;
      continue;
    }
    if (ch === ')') {
      const closed = groupStack.pop() || { hasQuantifier: false };
      let quantifiesGroup = false;
      const next = src[i + 1];
      if (next === '*' || next === '+') {
        quantifiesGroup = true;
      } else if (next === '{') {
        const q = readBoundedQuantifier(i + 1);
        if (q) quantifiesGroup = q.repeatsMoreThanOnce;
      }
      if (quantifiesGroup) quantifierCount++;
      if (closed.hasQuantifier && quantifiesGroup) {
        return 'nested quantifiers detected';
      }
      if (groupStack.length > 0 && (closed.hasQuantifier || quantifiesGroup)) {
        groupStack[groupStack.length - 1].hasQuantifier = true;
      }
      i++;
      continue;
    }
    if (ch === '*' || ch === '+') {
      quantifierCount++;
      if (groupStack.length > 0) {
        groupStack[groupStack.length - 1].hasQuantifier = true;
      }
      i++;
      continue;
    }
    if (ch === '{') {
      const q = readBoundedQuantifier(i);
      if (q) {
        quantifierCount++;
        if (q.repeatsMoreThanOnce && groupStack.length > 0) {
          groupStack[groupStack.length - 1].hasQuantifier = true;
        }
        i = q.end + 1;
        continue;
      }
      i++;
      continue;
    }
    i++;
  }

  if (quantifierCount > MAX_REGEX_QUANTIFIERS) {
    return `too many quantifiers, max ${MAX_REGEX_QUANTIFIERS}`;
  }
  if (groupCount > MAX_REGEX_GROUPS) {
    return `too many groups, max ${MAX_REGEX_GROUPS}`;
  }
  return null;
}

export function isValidFilterRule(rule) {
  if (!rule || typeof rule.value !== 'string' || rule.value.length === 0) {
    return false;
  }
  if (rule.matchType === 'regex') {
    const { pattern, flags } = parseRegexValue(rule.value);
    try {
      new RegExp(pattern, flags);
    } catch (_) {
      return false;
    }
    if (findUnsafeRegexReason(pattern)) {
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
 *          field: 'name'|'description'|'location', value: string }
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
    const { pattern, flags } = parseRegexValue(rule.value);
    try {
      new RegExp(pattern, flags);
    } catch (e) {
      return e.message;
    }
    const unsafeReason = findUnsafeRegexReason(pattern);
    if (unsafeReason) {
      return `potentially unsafe pattern (${unsafeReason})`;
    }
    return null;
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
        {
          ' Regex patterns use JavaScript (ECMAScript) regular expression syntax, matched case-sensitively unless you wrap the pattern as a literal with flags, e.g. /foo/i.'
        }
        {
          ' The description field falls back to the item name when the source has no separate description.'
        }
        {
          ' The location field matches the provider-side path shown in the preview table, e.g. gitlab:projects/42/access_tokens/7.'
        }
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
                    <option value='location'>Location</option>
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
