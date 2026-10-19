import { useEffect, useMemo, useState } from 'react';
import {
  Accordion,
  AccordionButton,
  AccordionIcon,
  AccordionItem,
  AccordionPanel,
  Box,
  Checkbox,
  FormControl,
  FormErrorMessage,
  FormHelperText,
  FormLabel,
  HStack,
  Input,
  Radio,
  RadioGroup,
  Select,
  SimpleGrid,
  Text,
  Textarea,
  VStack,
} from '@chakra-ui/react';
import { DashboardErrorAlert } from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import StepFrame from './StepFrame.jsx';
import PrimaryButton from './PrimaryButton.jsx';
import { runIdempotent } from './operations.js';
import {
  FIELD_LABELS,
  TOKEN_CATEGORIES,
  buildAssetPayload,
  categoryOf,
  emptyAsset,
  fieldsFor,
  validateAsset,
} from './assetModel.js';
import { onboardingActions } from '../../utils/onboardingActions.js';

function dayKey(value) {
  return Math.floor(new Date(value).getTime() / 86400000);
}

const TEXTAREA_FIELDS = new Set(['description']);
const DATE_FIELDS = new Set(['renewal_date']);
const NUMBER_FIELDS = new Set(['cost', 'key_size']);

/**
 * Adds one asset with the same model as the main "Create New Token" form:
 * four categories with their own fields, an optional expiry and contact
 * groups. The common choices come first and the rest sits under "More
 * details" so a first asset takes seconds.
 */
export function AssetStep({ ctx }) {
  const { muted } = useDashboardTheme();
  const [asset, setAsset] = useState(emptyAsset);
  const [errors, setErrors] = useState({});
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [groups, setGroups] = useState([]);
  const [added, setAdded] = useState([]);

  useEffect(() => {
    let live = true;
    onboardingActions
      .getAlertSettings(ctx.workspaceId)
      .then(settings => {
        if (!live) return;
        const list = Array.isArray(settings.contact_groups)
          ? settings.contact_groups
          : [];
        setGroups(list);
        const def = String(settings.default_contact_group_id || '');
        // The main form preselects the default group; so does this.
        if (def && list.some(g => String(g.id) === def)) {
          setAsset(a =>
            a.contactGroupIds.length ? a : { ...a, contactGroupIds: [def] }
          );
        }
      })
      .catch(() => {});
    return () => {
      live = false;
    };
  }, [ctx.workspaceId]);

  const cat = categoryOf(asset.category);
  const extra = useMemo(
    () => fieldsFor(asset.category, asset.type),
    [asset.category, asset.type]
  );
  const set = patch => setAsset(a => ({ ...a, ...patch }));
  const setField = (key, value) =>
    setAsset(a => ({ ...a, fields: { ...a.fields, [key]: value } }));

  const changeCategory = value => {
    const next = categoryOf(value);
    set({ category: value, type: next?.types[0]?.value || '', fields: {} });
  };
  const toggleGroup = id =>
    setAsset(a => {
      const has = a.contactGroupIds.includes(id);
      return {
        ...a,
        contactGroupIds: has
          ? a.contactGroupIds.filter(x => x !== id)
          : [...a.contactGroupIds, id],
      };
    });

  const submit = async () => {
    const check = validateAsset(asset);
    setErrors(check.errors);
    if (!check.ok) {
      setError('Fix the highlighted fields.');
      return;
    }
    setBusy(true);
    setError('');
    const payload = buildAssetPayload(asset, ctx.workspaceId);
    // Identity carries no free text beyond what already identifies the asset.
    const identity = {
      name: payload.name,
      location: payload.location || '',
      category: payload.category,
      type: payload.type,
      expiresAt: payload.expiresAt,
    };
    try {
      await runIdempotent({
        controller: ctx.controller,
        kind: 'asset',
        identity,
        // Empty locations never conflict server-side, so reconcile by identity.
        find: async id => {
          const items = await onboardingActions.findTokens(
            ctx.workspaceId,
            id.name
          );
          return (
            items.find(
              t =>
                t.name === id.name &&
                (t.location || '') === id.location &&
                t.category === id.category &&
                t.type === id.type &&
                Math.abs(dayKey(t.expiresAt) - dayKey(id.expiresAt)) <= 1
            ) || null
          );
        },
        create: () => onboardingActions.createToken(payload),
        record: (refs, created) => ({
          tokenIds: Array.from(
            new Set([...(refs.tokenIds || []), created.id].filter(Boolean))
          ),
        }),
      });
      setAdded(list => [...list, payload.name]);
      setAsset(a => ({
        ...emptyAsset(),
        category: a.category,
        type: a.type,
        contactGroupIds: a.contactGroupIds,
      }));
      setErrors({});
      await ctx.refresh();
      ctx.onDone?.();
    } catch (e) {
      setError(e.message || 'Could not create this asset.');
    } finally {
      setBusy(false);
    }
  };

  const renderField = key => {
    const label = FIELD_LABELS[key] || key;
    const common = {
      size: 'sm',
      value: asset.fields[key] || '',
      onChange: e => setField(key, e.target.value),
      autoComplete: 'off',
    };
    return (
      <FormControl key={key} isInvalid={Boolean(errors[key])}>
        <FormLabel fontSize='sm'>{label}</FormLabel>
        {TEXTAREA_FIELDS.has(key) ? (
          <Textarea {...common} rows={2} maxLength={2000} />
        ) : (
          <Input
            {...common}
            type={
              DATE_FIELDS.has(key)
                ? 'date'
                : NUMBER_FIELDS.has(key)
                  ? 'number'
                  : 'text'
            }
            maxLength={500}
          />
        )}
        <FormErrorMessage>{errors[key]}</FormErrorMessage>
      </FormControl>
    );
  };

  return (
    <StepFrame
      kind='ui'
      title='Add an asset'
      description='Record the details of a certificate, key, secret, license or anything else that expires. Never paste the secret value itself.'
      docs={[
        ...ctx.docs('tokens.adding', 'Adding assets'),
        ...ctx.docs('tokens.fields', 'Asset fields'),
      ]}
      actions={
        <PrimaryButton onClick={submit} isLoading={busy}>
          Create asset
        </PrimaryButton>
      }
    >
      <VStack align='stretch' spacing={4}>
        {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
        {added.length ? (
          <Text fontSize='sm' color='green.400' data-testid='added-assets'>
            Added: {added.join(', ')}. You can add another below.
          </Text>
        ) : null}

        <FormControl>
          <FormLabel fontSize='sm'>What kind of asset is it?</FormLabel>
          <RadioGroup value={asset.category} onChange={changeCategory}>
            <SimpleGrid columns={{ base: 1, sm: 2 }} spacing={2}>
              {TOKEN_CATEGORIES.map(c => (
                <Box
                  key={c.value}
                  borderWidth='1px'
                  borderRadius='md'
                  p={2}
                  borderColor={
                    asset.category === c.value ? 'blue.400' : undefined
                  }
                >
                  <Radio value={c.value} size='sm'>
                    <Text fontSize='sm' fontWeight='semibold'>
                      {c.label}
                    </Text>
                    <Text fontSize='xs' color={muted}>
                      {c.description}
                    </Text>
                  </Radio>
                </Box>
              ))}
            </SimpleGrid>
          </RadioGroup>
        </FormControl>

        <HStack align='start' spacing={3} flexWrap='wrap'>
          <FormControl flex='2 1 240px' isRequired isInvalid={!!errors.name}>
            <FormLabel fontSize='sm'>Name</FormLabel>
            <Input
              size='sm'
              value={asset.name}
              onChange={e => set({ name: e.target.value })}
              maxLength={255}
              autoComplete='off'
              placeholder='Payments API key'
            />
            <FormErrorMessage>{errors.name}</FormErrorMessage>
          </FormControl>
          <FormControl flex='1 1 180px' isInvalid={!!errors.type}>
            <FormLabel fontSize='sm'>Type</FormLabel>
            <Select
              size='sm'
              value={asset.type}
              onChange={e => set({ type: e.target.value })}
            >
              {(cat?.types || []).map(t => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </Select>
            <FormErrorMessage>{errors.type}</FormErrorMessage>
          </FormControl>
        </HStack>

        <FormControl isInvalid={!!errors.expiresAt}>
          <FormLabel fontSize='sm'>Expires on</FormLabel>
          <HStack spacing={4} flexWrap='wrap'>
            <Input
              size='sm'
              type='date'
              maxW='220px'
              value={asset.expiresAt}
              isDisabled={asset.neverExpires}
              onChange={e => set({ expiresAt: e.target.value })}
            />
            <Checkbox
              size='sm'
              isChecked={asset.neverExpires}
              onChange={e => set({ neverExpires: e.target.checked })}
            >
              Does not expire or unknown
            </Checkbox>
          </HStack>
          <FormHelperText fontSize='xs'>
            Optional. Without a date the asset is tracked but never alerts on
            expiry.
          </FormHelperText>
          <FormErrorMessage>{errors.expiresAt}</FormErrorMessage>
        </FormControl>

        {groups.length > 0 ? (
          <FormControl>
            <FormLabel fontSize='sm'>Who gets alerted</FormLabel>
            <VStack align='start' spacing={1}>
              {groups.map(g => (
                <Checkbox
                  key={g.id}
                  size='sm'
                  isChecked={asset.contactGroupIds.includes(String(g.id))}
                  onChange={() => toggleGroup(String(g.id))}
                >
                  {g.name}
                </Checkbox>
              ))}
            </VStack>
          </FormControl>
        ) : (
          <Text fontSize='xs' color={muted}>
            No contact group yet. You choose who gets alerted in the next step.
          </Text>
        )}

        <Accordion allowToggle>
          <AccordionItem border='none'>
            <AccordionButton px={0}>
              <Box
                flex='1'
                textAlign='left'
                fontSize='sm'
                fontWeight='semibold'
              >
                More details (optional)
              </Box>
              <AccordionIcon />
            </AccordionButton>
            <AccordionPanel px={0}>
              <VStack align='stretch' spacing={3}>
                <SimpleGrid columns={{ base: 1, md: 2 }} spacing={3}>
                  {extra.map(renderField)}
                </SimpleGrid>
                <FormControl>
                  <FormLabel fontSize='sm'>
                    Sections (comma separated)
                  </FormLabel>
                  <Input
                    size='sm'
                    value={asset.section}
                    onChange={e => set({ section: e.target.value })}
                    autoComplete='off'
                    placeholder='production, billing'
                  />
                </FormControl>
                <FormControl>
                  <FormLabel fontSize='sm'>Notes</FormLabel>
                  <Textarea
                    size='sm'
                    rows={3}
                    value={asset.notes}
                    onChange={e => set({ notes: e.target.value })}
                    maxLength={10000}
                  />
                </FormControl>
              </VStack>
            </AccordionPanel>
          </AccordionItem>
        </Accordion>
      </VStack>
    </StepFrame>
  );
}
