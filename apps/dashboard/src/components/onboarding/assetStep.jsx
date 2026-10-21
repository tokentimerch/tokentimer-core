import { useEffect, useMemo, useRef, useState } from 'react';
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
  IconButton,
  Input,
  Radio,
  RadioGroup,
  Select,
  SimpleGrid,
  Text,
  Textarea,
  VStack,
} from '@chakra-ui/react';
import { FiPlus, FiX } from 'react-icons/fi';
import {
  DashboardActionButton,
  DashboardErrorAlert,
} from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import StepFrame from './StepFrame.jsx';
import PrimaryButton from './PrimaryButton.jsx';
import { ContinueHint, ErrorText } from './blocks.jsx';
import { runIdempotent } from './operations.js';
import { withAssetTokenId } from './assetRefs.js';
import {
  FIELD_LABELS,
  MAX_STAGED_ASSETS,
  TOKEN_CATEGORIES,
  assetKey,
  buildAssetPayload,
  categoryOf,
  changeAssetCategory,
  describeAsset,
  emptyAsset,
  fieldsFor,
  validateAsset,
} from './assetModel.js';
import { mergeRefs } from './monitorModel.js';
import { onboardingActions } from '../../utils/onboardingActions.js';
import ContactGroupCheckboxGroup from '../ContactGroupCheckboxGroup.jsx';
import { AlertsGoTo } from './alertsGoTo.jsx';

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
  const [defaultGroupId, setDefaultGroupId] = useState('');
  const pickerRef = useRef(null);
  const [added, setAdded] = useState([]);
  const [existing, setExisting] = useState([]);
  const [staged, setStaged] = useState([]);
  const [rowErrors, setRowErrors] = useState({});
  const [progress, setProgress] = useState(null);

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
          setDefaultGroupId(def);
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
  const defaultGroup = defaultGroupId
    ? groups.find(g => String(g.id) === defaultGroupId)
    : null;
  const extra = useMemo(
    () => fieldsFor(asset.category, asset.type),
    [asset.category, asset.type]
  );
  const set = patch => setAsset(a => ({ ...a, ...patch }));
  const setField = (key, value) =>
    setAsset(a => ({ ...a, fields: { ...a.fields, [key]: value } }));

  const changeCategory = value => setAsset(a => changeAssetCategory(a, value));

  // The list and the form live only in this page, so a reload would drop
  // them. Not while creating: the batch is already running.
  const warnOnLeave = (staged.length > 0 || asset.name.trim() !== '') && !busy;
  useEffect(() => {
    if (!warnOnLeave) return undefined;
    const onBeforeUnload = event => {
      event.preventDefault();
      event.returnValue = '';
    };
    window.addEventListener('beforeunload', onBeforeUnload);
    return () => window.removeEventListener('beforeunload', onBeforeUnload);
  }, [warnOnLeave]);

  /** Validates the form and puts the asset on the list. Nothing is created yet. */
  const stageCurrent = () => {
    const check = validateAsset(asset);
    setErrors(check.errors);
    if (!check.ok) {
      setError('Fix the highlighted fields.');
      return false;
    }
    if (staged.some(s => assetKey(s.asset) === assetKey(asset))) {
      setError('This asset is already in the list.');
      return false;
    }
    if (staged.length >= MAX_STAGED_ASSETS) {
      setError(
        `Add up to ${MAX_STAGED_ASSETS} assets at a time, then create them.`
      );
      return false;
    }
    setStaged(list => [
      ...list,
      { id: `d${Date.now()}-${list.length}`, asset },
    ]);
    // Keep the kind and the groups: the next one is usually alike.
    setAsset(a => ({
      ...emptyAsset(),
      category: a.category,
      type: a.type,
      contactGroupIds: a.contactGroupIds,
    }));
    setErrors({});
    setError('');
    return true;
  };

  const removeStaged = id => {
    setStaged(list => list.filter(s => s.id !== id));
    setRowErrors(errs => {
      const { [id]: _gone, ...rest } = errs;
      return rest;
    });
  };

  const createOne = async draft => {
    const payload = buildAssetPayload(draft, ctx.workspaceId);
    // Identity carries no free text beyond what already identifies the asset.
    const identity = {
      name: payload.name,
      location: payload.location || '',
      category: payload.category,
      type: payload.type,
      expiresAt: payload.expiresAt,
    };
    const { adopted } = await runIdempotent({
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
        tokenIds: mergeRefs(refs.tokenIds, [created.id]),
        assetTokenIds: mergeRefs(withAssetTokenId(refs, created.id), []),
      }),
    });
    return { name: payload.name, adopted };
  };

  // Keeps the kind and the groups: the next asset is usually alike.
  const resetForm = () => {
    setAsset(a => ({
      ...emptyAsset(),
      category: a.category,
      type: a.type,
      contactGroupIds: a.contactGroupIds,
    }));
    setErrors({});
  };

  const submit = async () => {
    setError('');
    // A form that is filled in but not yet listed counts, so the button never
    // silently ignores what the person typed.
    let drafts = staged;
    if (asset.name.trim()) {
      const check = validateAsset(asset);
      setErrors(check.errors);
      if (!check.ok) {
        setError('Fix the highlighted fields.');
        return;
      }
      if (!staged.some(s => assetKey(s.asset) === assetKey(asset))) {
        if (staged.length >= MAX_STAGED_ASSETS) {
          setError(
            `Add up to ${MAX_STAGED_ASSETS} assets at a time, then create them.`
          );
          return;
        }
        drafts = [...staged, { id: `d${Date.now()}-last`, asset }];
      }
    }
    if (drafts.length === 0) {
      setError('Give the asset a name.');
      setErrors({ name: 'Name is required.' });
      return;
    }

    setBusy(true);
    setRowErrors({});
    const done = [];
    const failed = {};
    for (let i = 0; i < drafts.length; i += 1) {
      setProgress({ index: i + 1, total: drafts.length });
      try {
        done.push(await createOne(drafts[i].asset));
      } catch (e) {
        failed[drafts[i].id] = e.message || 'Could not create this asset.';
      }
    }
    setProgress(null);

    const failedIds = Object.keys(failed);
    const created = done.filter(d => !d.adopted).map(d => d.name);
    const adoptedNames = done.filter(d => d.adopted).map(d => d.name);
    if (created.length) setAdded(list => [...list, ...created]);
    if (adoptedNames.length) setExisting(list => [...list, ...adoptedNames]);
    // The form was part of the batch, so it now lives in the list (failed) or
    // was created. Clearing it keeps the button count honest.
    if (asset.name.trim()) resetForm();
    if (failedIds.length) {
      // Only the failures stay, so a retry never repeats what worked.
      setStaged(drafts.filter(d => failedIds.includes(d.id)));
      setRowErrors(failed);
      setError(
        done.length
          ? `Created ${done.length} of ${drafts.length}. Fix or remove the others, then try again.`
          : 'None of the assets could be created.'
      );
    } else {
      setStaged([]);
      resetForm();
    }
    try {
      await ctx.refresh();
      if (!failedIds.length) ctx.onDone?.();
    } catch (e) {
      setError(e.message || 'Could not refresh your progress.');
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
      title='Add your assets'
      description='Record the details of a certificate, key, secret, license or anything else that expires. Never paste the secret value itself.'
      docs={[
        ...ctx.docs('tokens.adding', 'Adding assets'),
        ...ctx.docs('tokens.fields', 'Asset fields'),
      ]}
      actions={
        <PrimaryButton
          onClick={submit}
          isLoading={busy}
          loadingText={
            progress
              ? `Creating ${progress.index} of ${progress.total}`
              : 'Creating'
          }
          isDisabled={staged.length === 0 && !asset.name.trim()}
        >
          {staged.length + (asset.name.trim() ? 1 : 0) > 1
            ? `Create ${staged.length + (asset.name.trim() ? 1 : 0)} assets`
            : 'Create asset'}
        </PrimaryButton>
      }
      actionHint={
        staged.length === 0 && !asset.name.trim() ? (
          <ContinueHint>give the asset a name.</ContinueHint>
        ) : null
      }
    >
      <VStack align='stretch' spacing={4}>
        {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
        {added.length ? (
          <Text fontSize='sm' color='green.400' data-testid='added-assets'>
            Created: {added.join(', ')}. You can add more below.
          </Text>
        ) : null}
        {existing.length ? (
          <Text fontSize='sm' color={muted} data-testid='existing-assets'>
            Already existed: {existing.join(', ')}. Nothing new was created for{' '}
            {existing.length === 1 ? 'it' : 'them'}.
          </Text>
        ) : null}

        {staged.length > 0 ? (
          <Box
            borderWidth='1px'
            borderRadius='md'
            role='list'
            aria-label='Assets to create'
          >
            {staged.map((s, index) => {
              const d = describeAsset(s.asset);
              return (
                <HStack
                  key={s.id}
                  role='listitem'
                  justify='space-between'
                  align='flex-start'
                  px={3}
                  py={2}
                  borderTopWidth={index === 0 ? 0 : '1px'}
                >
                  <Box minW={0}>
                    <Text
                      fontSize='sm'
                      fontWeight='semibold'
                      wordBreak='break-word'
                    >
                      {d.title}
                    </Text>
                    <Text fontSize='xs' color={muted}>
                      {d.detail}
                    </Text>
                    {rowErrors[s.id] ? (
                      <ErrorText>{rowErrors[s.id]}</ErrorText>
                    ) : null}
                  </Box>
                  <IconButton
                    aria-label={`Remove ${d.title}`}
                    size='xs'
                    variant='outline'
                    icon={<FiX />}
                    isDisabled={busy}
                    onClick={() => removeStaged(s.id)}
                  />
                </HStack>
              );
            })}
          </Box>
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

        <FormControl>
          <FormLabel fontSize='sm'>Who gets alerted</FormLabel>
          <Box ref={pickerRef}>
            <ContactGroupCheckboxGroup
              contactGroups={groups}
              value={asset.contactGroupIds}
              onChange={contactGroupIds => set({ contactGroupIds })}
              isDisabled={busy}
              defaultContactGroupId={defaultGroupId}
              emptyText='No contact group yet. You choose who gets alerted in the next step.'
              helperText=''
            />
          </Box>
          <AlertsGoTo
            selectedIds={asset.contactGroupIds}
            groups={groups}
            defaultId={defaultGroupId}
            pickerRef={pickerRef}
          />
          {groups.length > 0 && asset.contactGroupIds.length === 0 ? (
            <FormHelperText fontSize='xs' data-testid='no-group-hint'>
              {defaultGroup
                ? `No group selected: alerts go to the default group (${defaultGroup.name}).`
                : 'No group selected: alerts have no recipient until a contact group is set.'}
            </FormHelperText>
          ) : null}
        </FormControl>

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

        <HStack justify='flex-end'>
          <DashboardActionButton
            variant='outline'
            leftIcon={<FiPlus />}
            onClick={stageCurrent}
            isDisabled={busy || !asset.name.trim()}
          >
            Add to the list
          </DashboardActionButton>
        </HStack>
      </VStack>
    </StepFrame>
  );
}
