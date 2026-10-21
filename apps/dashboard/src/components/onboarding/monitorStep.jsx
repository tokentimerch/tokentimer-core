import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Accordion,
  AccordionButton,
  AccordionIcon,
  AccordionItem,
  AccordionPanel,
  Badge,
  Box,
  Checkbox,
  FormControl,
  FormErrorMessage,
  FormHelperText,
  FormLabel,
  HStack,
  IconButton,
  Input,
  InputGroup,
  InputLeftElement,
  NumberInput,
  NumberInputField,
  Select,
  Spinner,
  Switch,
  Text,
  VStack,
} from '@chakra-ui/react';
import { FiPlus, FiSearch, FiX } from 'react-icons/fi';
import {
  DashboardActionButton,
  DashboardErrorAlert,
} from '../DashboardPrimitives';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import StepFrame from './StepFrame.jsx';
import PrimaryButton from './PrimaryButton.jsx';
import { ContinueHint, ErrorText } from './blocks.jsx';
import ContactGroupCheckboxGroup from '../ContactGroupCheckboxGroup.jsx';
import { AlertsGoTo } from './alertsGoTo.jsx';
import { runIdempotent } from './operations.js';
import {
  ALERT_AFTER_MAX,
  ALERT_AFTER_MIN,
  CHECK_INTERVALS,
  DEFAULT_MONITOR_SETTINGS,
  MAX_STAGED_WEBSITES,
  discoveredHostnames,
  discoveryErrorMessage,
  discoveryNotices,
  filterHostnames,
  hostToUrl,
  normalizeRootDomain,
  paginate,
  selectableHosts,
  stageMany,
  stageWebsite,
  storedMonitorSettings,
  validateMonitorSettings,
} from './monitorModel.js';
import { onboardingActions } from '../../utils/onboardingActions.js';

const union = (a, b) =>
  Array.from(new Set([...(a || []), ...b.filter(Boolean)]));

/**
 * The checks the product runs on a website: how often, and whether to alert
 * when it stops answering. Shown to everyone so nothing is hidden behind
 * defaults.
 */
function CheckSettings({ settings, errors, onChange, disabled }) {
  const { muted, border } = useDashboardTheme();
  return (
    <Box borderWidth='1px' borderColor={border} borderRadius='md' p={3}>
      <Text fontSize='sm' fontWeight='semibold' mb={2}>
        How to check
      </Text>
      <HStack align='flex-start' spacing={4} flexWrap='wrap'>
        <FormControl
          flex='1 1 180px'
          isInvalid={Boolean(errors.checkInterval)}
          isDisabled={disabled}
        >
          <FormLabel fontSize='sm'>Check every</FormLabel>
          <Select
            size='sm'
            value={settings.checkInterval}
            onChange={e => onChange({ checkInterval: e.target.value })}
          >
            {CHECK_INTERVALS.map(i => (
              <option key={i.value} value={i.value}>
                {i.value === DEFAULT_MONITOR_SETTINGS.checkInterval
                  ? `${i.label} (recommended)`
                  : i.label}
              </option>
            ))}
          </Select>
          <FormErrorMessage>{errors.checkInterval}</FormErrorMessage>
        </FormControl>
        <FormControl
          flex='1 1 240px'
          isDisabled={disabled}
          display='flex'
          alignItems='center'
          pt={{ base: 0, md: 7 }}
        >
          <Switch
            id='monitor-health-check'
            size='md'
            isChecked={settings.healthCheckEnabled}
            onChange={e => onChange({ healthCheckEnabled: e.target.checked })}
          />
          <FormLabel
            htmlFor='monitor-health-check'
            fontSize='sm'
            mb={0}
            ml={2}
            cursor='pointer'
          >
            Alert me if a website is down
          </FormLabel>
        </FormControl>
        {settings.healthCheckEnabled ? (
          <FormControl
            flex='0 1 190px'
            isInvalid={Boolean(errors.alertAfterFailures)}
            isDisabled={disabled}
          >
            <FormLabel fontSize='sm'>After failed checks in a row</FormLabel>
            <NumberInput
              size='sm'
              min={ALERT_AFTER_MIN}
              max={ALERT_AFTER_MAX}
              value={settings.alertAfterFailures}
              onChange={(_, n) =>
                onChange({
                  alertAfterFailures: Number.isFinite(n) ? n : '',
                })
              }
            >
              <NumberInputField />
            </NumberInput>
            <FormErrorMessage>{errors.alertAfterFailures}</FormErrorMessage>
          </FormControl>
        ) : null}
      </HStack>
      <Text fontSize='xs' color={muted} mt={2}>
        Applies to every website in the list.
      </Text>
      <Accordion allowToggle mt={2} reduceMotion>
        <AccordionItem border='0'>
          <AccordionButton px={0} py={1}>
            <Box flex='1' textAlign='left' fontSize='sm'>
              More options
            </Box>
            <AccordionIcon />
          </AccordionButton>
          <AccordionPanel px={0} pb={0}>
            <FormControl
              isInvalid={Boolean(errors.section)}
              isDisabled={disabled}
            >
              <FormLabel fontSize='sm'>Sections (optional)</FormLabel>
              <Input
                size='sm'
                value={settings.section}
                placeholder='production, public sites'
                onChange={e => onChange({ section: e.target.value })}
                autoComplete='off'
              />
              <FormHelperText fontSize='xs'>
                Labels to group these websites by, separated by commas.
              </FormHelperText>
              <FormErrorMessage>{errors.section}</FormErrorMessage>
            </FormControl>
          </AccordionPanel>
        </AccordionItem>
      </Accordion>
    </Box>
  );
}

/** Public subdomain lookup for a root domain, feeding the same list. */
function DiscoveryPanel({
  workspaceId,
  staged,
  monitored,
  onAdd,
  disabled,
  attempt = 0,
}) {
  const { muted, border } = useDashboardTheme();
  const [domain, setDomain] = useState('');
  const [includeAll, setIncludeAll] = useState(false);
  const [finding, setFinding] = useState(false);
  const [error, setError] = useState('');
  const [found, setFound] = useState(null);
  const [selected, setSelected] = useState(() => new Set());
  const [note, setNote] = useState('');
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(0);
  const running = useRef(null);

  // Leaving the step abandons a search that is still waiting for an answer.
  useEffect(() => () => running.current?.abort(), []);

  // "Added 3 to the list." is stale once the list has been submitted.
  useEffect(() => {
    if (attempt > 0) setNote('');
  }, [attempt]);

  const stagedSet = useMemo(
    () => new Set(staged.map(u => u.toLowerCase())),
    [staged]
  );
  const monitoredSet = useMemo(
    () => new Set(monitored.map(u => String(u).toLowerCase())),
    [monitored]
  );
  const status = host => {
    const url = hostToUrl(host);
    if (monitoredSet.has(url)) return 'monitored';
    if (stagedSet.has(url)) return 'listed';
    return null;
  };
  const room = Math.max(0, MAX_STAGED_WEBSITES - staged.length);

  const filtered = useMemo(
    () => filterHostnames(found?.hosts, query),
    [found, query]
  );
  const view = paginate(filtered, page);
  const taken = found ? found.hosts.filter(h => status(h)).length : 0;

  const find = async () => {
    const root = normalizeRootDomain(domain);
    if (!root) {
      setError('Enter a domain such as example.com.');
      return;
    }
    const controller = new AbortController();
    running.current = controller;
    setFinding(true);
    setError('');
    setNote('');
    setFound(null);
    setSelected(new Set());
    setQuery('');
    setPage(0);
    try {
      const res = await onboardingActions.discoverHostnames(workspaceId, root, {
        includeAllSources: includeAll,
        signal: controller.signal,
      });
      const hosts = discoveredHostnames(res.items, root);
      setFound({
        root,
        hosts,
        partial: res.partial,
        truncated: res.truncated,
        cap: res.cap,
        failedCodes: res.failedCodes,
      });
      if (hosts.length === 0)
        setNote('No websites were found for this domain.');
    } catch (e) {
      if (e?.code === 'ERR_CANCELED') setNote('Search cancelled.');
      else setError(discoveryErrorMessage(e));
    } finally {
      if (running.current === controller) {
        running.current = null;
        setFinding(false);
      }
    }
  };

  const cancel = () => running.current?.abort();

  const toggle = host =>
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(host)) next.delete(host);
      else if (next.size < room) next.add(host);
      return next;
    });

  // Applies to every match of the filter, across pages, within what fits.
  const selectAll = () =>
    setSelected(prev => {
      const next = new Set(prev);
      for (const host of selectableHosts(filtered, h => status(h), room)) {
        if (next.size >= room) break;
        next.add(host);
      }
      return next;
    });

  const add = () => {
    const urls = Array.from(selected).map(hostToUrl);
    const r = onAdd(urls);
    setSelected(new Set());
    setNote(
      [
        r.added ? `Added ${r.added} to the list.` : '',
        r.duplicates ? `${r.duplicates} already in the list.` : '',
        r.overLimit
          ? `${r.overLimit} did not fit: a batch holds up to ${MAX_STAGED_WEBSITES}.`
          : '',
      ]
        .filter(Boolean)
        .join(' ')
    );
  };

  const notices = found ? discoveryNotices(found) : [];

  return (
    <Accordion allowToggle>
      <AccordionItem borderWidth='1px' borderColor={border} borderRadius='md'>
        <AccordionButton px={3} py={2}>
          <Box flex='1' textAlign='left' fontSize='sm' fontWeight='semibold'>
            Find the websites on my domain
          </Box>
          <AccordionIcon />
        </AccordionButton>
        <AccordionPanel px={3} pb={3}>
          <VStack align='stretch' spacing={3}>
            <Text fontSize='xs' color={muted}>
              Looks up the public subdomains of a domain. Your domain name is
              sent to public lookup services. This can take a minute or two.
              Pick the ones to monitor and they join the list above.
            </Text>
            <HStack align='flex-start' spacing={2}>
              <FormControl isDisabled={disabled || finding}>
                <Input
                  size='sm'
                  aria-label='Domain to search'
                  placeholder='example.com'
                  value={domain}
                  onChange={e => setDomain(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      if (domain.trim() && !finding) find();
                    }
                  }}
                  autoComplete='off'
                />
              </FormControl>
              <DashboardActionButton
                variant='outline'
                leftIcon={<FiSearch />}
                onClick={find}
                isLoading={finding}
                loadingText='Searching'
                isDisabled={disabled || !domain.trim()}
                flexShrink={0}
              >
                Find websites
              </DashboardActionButton>
            </HStack>
            <FormControl isDisabled={disabled || finding}>
              <Checkbox
                size='sm'
                isChecked={includeAll}
                onChange={e => setIncludeAll(e.target.checked)}
              >
                Include all sources
              </Checkbox>
              <FormHelperText fontSize='xs' mt={1}>
                Asks every source, not only the default ones. It finds more but
                is slower, and it can list old names that no longer exist.
              </FormHelperText>
            </FormControl>
            {finding ? (
              <HStack
                role='status'
                spacing={3}
                align='flex-start'
                borderWidth='1px'
                borderColor={border}
                borderRadius='md'
                p={2}
              >
                <Spinner size='sm' mt='2px' flexShrink={0} />
                <Text fontSize='xs' color={muted} flex='1'>
                  Searching. This can take a minute or two. You can keep adding
                  websites by address meanwhile.
                </Text>
                <DashboardActionButton
                  size='xs'
                  variant='outline'
                  onClick={cancel}
                  flexShrink={0}
                >
                  Cancel
                </DashboardActionButton>
              </HStack>
            ) : null}
            {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}
            {found && found.hosts.length > 0 ? (
              <VStack align='stretch' spacing={2}>
                <Box>
                  <Text fontSize='sm'>
                    {found.hosts.length} found for {found.root}
                  </Text>
                  <Text fontSize='xs' color={muted}>
                    {found.hosts.length - taken} can be added
                    {taken ? `, ${taken} already monitored or in the list` : ''}
                    .
                  </Text>
                </Box>
                {notices.map(text => (
                  <Text key={text} fontSize='xs' color={muted}>
                    {text}
                  </Text>
                ))}
                <HStack spacing={0} gap={2} flexWrap='wrap'>
                  <InputGroup size='sm' flex='1 1 160px' minW='160px'>
                    <InputLeftElement pointerEvents='none'>
                      <FiSearch />
                    </InputLeftElement>
                    <Input
                      aria-label='Filter found websites'
                      placeholder='Filter by name'
                      value={query}
                      onChange={e => {
                        setQuery(e.target.value);
                        setPage(0);
                      }}
                      autoComplete='off'
                    />
                  </InputGroup>
                  <DashboardActionButton
                    size='xs'
                    variant='outline'
                    onClick={selectAll}
                    isDisabled={disabled || room === 0 || filtered.length === 0}
                    flexShrink={0}
                  >
                    {query.trim() ? 'Select all matching' : 'Select all'}
                  </DashboardActionButton>
                  <DashboardActionButton
                    size='xs'
                    variant='outline'
                    onClick={() => setSelected(new Set())}
                    isDisabled={selected.size === 0}
                    flexShrink={0}
                  >
                    Clear
                  </DashboardActionButton>
                </HStack>
                <Text fontSize='xs' color={muted} aria-live='polite'>
                  {`${selected.size} selected, up to ${room} fit in the list.`}
                </Text>
                <Box
                  maxH='220px'
                  overflowY='auto'
                  borderWidth='1px'
                  borderColor={border}
                  borderRadius='md'
                  p={2}
                  role='group'
                  aria-label='Websites found'
                >
                  {view.items.length === 0 ? (
                    <Text fontSize='sm' color={muted}>
                      No websites match this filter.
                    </Text>
                  ) : (
                    <VStack align='stretch' spacing={1}>
                      {view.items.map(host => {
                        const state = status(host);
                        return (
                          <HStack key={host} justify='space-between'>
                            <Checkbox
                              size='sm'
                              minW={0}
                              isChecked={selected.has(host)}
                              isDisabled={
                                disabled ||
                                Boolean(state) ||
                                (!selected.has(host) && selected.size >= room)
                              }
                              onChange={() => toggle(host)}
                            >
                              <Text as='span' wordBreak='break-all'>
                                {host}
                              </Text>
                            </Checkbox>
                            {state ? (
                              <Badge
                                flexShrink={0}
                                colorScheme={
                                  state === 'monitored' ? 'green' : 'blue'
                                }
                              >
                                {state === 'monitored'
                                  ? 'Already monitored'
                                  : 'In the list'}
                              </Badge>
                            ) : null}
                          </HStack>
                        );
                      })}
                    </VStack>
                  )}
                </Box>
                {view.pages > 1 ? (
                  <HStack justify='space-between' spacing={2}>
                    <DashboardActionButton
                      size='xs'
                      variant='outline'
                      onClick={() => setPage(view.page - 1)}
                      isDisabled={view.page === 0}
                    >
                      Previous
                    </DashboardActionButton>
                    <Text fontSize='xs' color={muted} aria-live='polite'>
                      {`${view.from} to ${view.to} of ${view.total}`}
                    </Text>
                    <DashboardActionButton
                      size='xs'
                      variant='outline'
                      onClick={() => setPage(view.page + 1)}
                      isDisabled={view.page >= view.pages - 1}
                    >
                      Next
                    </DashboardActionButton>
                  </HStack>
                ) : null}
                <HStack justify='flex-end'>
                  <DashboardActionButton
                    variant='outline'
                    leftIcon={<FiPlus />}
                    onClick={add}
                    isDisabled={disabled || selected.size === 0}
                  >
                    {`Add ${selected.size} to the list`}
                  </DashboardActionButton>
                </HStack>
              </VStack>
            ) : null}
            {note ? (
              <Text fontSize='xs' color={muted} aria-live='polite'>
                {note}
              </Text>
            ) : null}
          </VStack>
        </AccordionPanel>
      </AccordionItem>
    </Accordion>
  );
}

/**
 * Adds one or many websites with visible check settings. Websites are
 * gathered into a list and created together, so the guide does not jump ahead
 * after the first one. Each address goes through the same resume-safe helper
 * as before, so an interrupted batch can be retried without duplicates.
 */
export function MonitorStep({ ctx }) {
  const { muted, border } = useDashboardTheme();
  const [input, setInput] = useState('');
  const [staged, setStaged] = useState([]);
  // Prefilled with what the last batch used, so reopening the step shows it.
  const [settings, setSettings] = useState(() => ({
    ...storedMonitorSettings(
      ctx.controller?.session?.operationRefs?.monitorSettings
    ),
    section: '',
  }));
  const [settingsErrors, setSettingsErrors] = useState({});
  const [rowErrors, setRowErrors] = useState({});
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState(null);
  const [attempt, setAttempt] = useState(0);
  // Same shared picker as the asset step, with the same default: the
  // workspace default group starts ticked, as in the main Create form.
  const [groups, setGroups] = useState([]);
  const [defaultGroupId, setDefaultGroupId] = useState('');
  const [contactGroupIds, setContactGroupIds] = useState([]);
  const pickerRef = useRef(null);
  useEffect(() => {
    let live = true;
    Promise.resolve()
      .then(() => onboardingActions.getAlertSettings(ctx.workspaceId))
      .then(alerts => {
        if (!live) return;
        const list = Array.isArray(alerts?.contact_groups)
          ? alerts.contact_groups
          : [];
        setGroups(list);
        const def = String(alerts?.default_contact_group_id || '');
        if (def && list.some(g => String(g.id) === def)) {
          setDefaultGroupId(def);
          setContactGroupIds(ids => (ids.length ? ids : [def]));
        }
      })
      .catch(() => {});
    return () => {
      live = false;
    };
  }, [ctx.workspaceId]);

  const monitored = (ctx.summary?.monitors?.items || [])
    .map(m => m?.url)
    .filter(Boolean);
  const defaultGroup = defaultGroupId
    ? groups.find(g => String(g.id) === defaultGroupId)
    : null;

  const stageInput = () => {
    if (!input.trim()) return;
    const r = stageWebsite(staged, input);
    if (r.ok) {
      setStaged(r.list);
      setInput('');
      setError('');
    } else if (r.duplicate) {
      setInput('');
    } else {
      setError(r.error);
    }
  };

  const remove = url => {
    setStaged(list => list.filter(u => u !== url));
    setRowErrors(errs => {
      const { [url]: _gone, ...rest } = errs;
      return rest;
    });
  };

  const addDiscovered = urls => {
    const r = stageMany(staged, urls);
    setStaged(r.list);
    return r;
  };

  // What the button would create, counting a typed address not yet listed.
  const typed = input.trim() ? stageWebsite(staged, input) : null;
  const count = staged.length + (typed?.ok ? 1 : 0);

  // The list and the typed address live only in this page, so a reload would
  // drop them. Not while creating: the batch is already running.
  const hasUnsavedWork = staged.length > 0 || input.trim() !== '';
  const warnOnLeave = hasUnsavedWork && !busy;
  useEffect(() => {
    if (!warnOnLeave) return undefined;
    const onBeforeUnload = event => {
      event.preventDefault();
      event.returnValue = '';
    };
    window.addEventListener('beforeunload', onBeforeUnload);
    return () => window.removeEventListener('beforeunload', onBeforeUnload);
  }, [warnOnLeave]);

  const submit = async () => {
    setError('');
    const check = validateMonitorSettings(settings);
    setSettingsErrors(check.errors);
    if (!check.ok) {
      setError('Fix the highlighted settings.');
      return;
    }
    let list = staged;
    if (input.trim()) {
      const r = stageWebsite(list, input);
      if (r.ok) ({ list } = r);
      else if (!r.duplicate) {
        setError(r.error);
        return;
      }
    }
    if (list.length === 0) {
      setError('Enter a valid HTTPS address, for example https://example.com');
      return;
    }

    setBusy(true);
    setRowErrors({});
    const created = [];
    let madeNow = 0;
    const failed = {};
    // Read what exists once, up front. An address that already exists is done
    // and must not set the "pending" marker: the page adopts a pending marker
    // as soon as its address is in the server snapshot, which would end this
    // step in the middle of the batch.
    let known;
    try {
      known = await onboardingActions.listMonitors(ctx.workspaceId);
    } catch (e) {
      setError(e.message || 'Could not read your existing websites.');
      setBusy(false);
      return;
    }
    const existing = url =>
      known.find(m => String(m.url).toLowerCase() === url.toLowerCase()) ||
      null;
    for (let i = 0; i < list.length; i += 1) {
      const url = list[i];
      setProgress({ index: i + 1, total: list.length });
      const already = existing(url);
      if (already) {
        created.push(already);
        continue;
      }
      try {
        const { result } = await runIdempotent({
          controller: ctx.controller,
          kind: 'monitor',
          identity: { url },
          find: identity => Promise.resolve(existing(identity.url)),
          create: async identity => {
            const made = await onboardingActions.createMonitor(
              ctx.workspaceId,
              { url: identity.url, contactGroupIds, ...check.value }
            );
            known.push(made);
            madeNow += 1;
            return made;
          },
          // Nothing is marked done until the whole batch has succeeded.
          record: () => ({}),
        });
        created.push(result);
      } catch (e) {
        failed[url] = e.message || 'Could not add this website.';
      }
    }
    setProgress(null);
    setAttempt(n => n + 1);

    const failedUrls = Object.keys(failed);
    try {
      if (created.length) {
        await ctx.controller.update(session => ({
          operation_refs: {
            ...session.operationRefs,
            ...(failedUrls.length ? {} : { monitorUrl: list[0] }),
            monitorIds: union(
              session.operationRefs?.monitorIds,
              created.map(c => c.id)
            ),
            tokenIds: union(
              session.operationRefs?.tokenIds,
              created.map(c => c.token_id)
            ),
            // Only when this batch created something: websites that already
            // existed were not given these settings.
            ...(madeNow > 0
              ? {
                  monitorSettings: {
                    checkInterval: check.value.checkInterval,
                    healthCheckEnabled: check.value.healthCheckEnabled,
                    alertAfterFailures: check.value.alertAfterFailures,
                  },
                }
              : {}),
          },
        }));
      }
      if (failedUrls.length) {
        setStaged(failedUrls);
        setInput('');
        setRowErrors(failed);
        setError(
          created.length
            ? `Added ${created.length} of ${list.length}. Fix or remove the others, then try again.`
            : 'None of the websites could be added.'
        );
        // Refresh the snapshot so "Already monitoring" and the discovery
        // badges reflect what was created. monitorUrl is not set on this
        // path, so the planner does not treat the step as done.
        if (created.length) await ctx.refresh().catch(() => {});
      } else {
        setStaged([]);
        setInput('');
        await ctx.refresh();
      }
    } catch (e) {
      setError(e.message || 'Could not save your progress.');
    } finally {
      setBusy(false);
    }
  };

  const label =
    count > 1 ? `Monitor ${count} websites` : 'Monitor this website';

  return (
    <StepFrame
      kind='ui'
      title='Add the websites to monitor'
      description='TokenTimer reads each certificate over HTTPS, tracks its expiry and checks that the site answers.'
      docs={[
        ...ctx.docs('monitoring.endpoint', 'About endpoint monitoring'),
        ...ctx.docs('monitoring.network', 'Network requirements'),
      ]}
      actions={
        <PrimaryButton
          onClick={submit}
          isLoading={busy}
          loadingText={
            progress
              ? `Adding ${progress.index} of ${progress.total}`
              : 'Adding'
          }
          isDisabled={count === 0}
        >
          {label}
        </PrimaryButton>
      }
      actionHint={
        count === 0 ? (
          <ContinueHint>
            enter a website address, for example https://example.com.
          </ContinueHint>
        ) : null
      }
    >
      <VStack align='stretch' spacing={4}>
        {error ? <DashboardErrorAlert>{error}</DashboardErrorAlert> : null}

        <FormControl isDisabled={busy}>
          <FormLabel fontSize='sm'>Website address</FormLabel>
          <HStack align='flex-start' spacing={2}>
            <Input
              size='sm'
              placeholder='https://example.com'
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  stageInput();
                }
              }}
              autoComplete='off'
            />
            <DashboardActionButton
              variant='outline'
              leftIcon={<FiPlus />}
              onClick={stageInput}
              isDisabled={busy || !input.trim()}
              flexShrink={0}
            >
              Add website
            </DashboardActionButton>
          </HStack>
          <FormHelperText fontSize='xs'>
            Add as many as you like, then start monitoring. Each address must be
            reachable from where TokenTimer runs.
          </FormHelperText>
        </FormControl>

        {staged.length > 0 ? (
          <Box
            borderWidth='1px'
            borderColor={border}
            borderRadius='md'
            role='list'
            aria-label='Websites to monitor'
          >
            {staged.map((url, index) => (
              <HStack
                key={url}
                role='listitem'
                justify='space-between'
                px={3}
                py={2}
                borderTopWidth={index === 0 ? 0 : '1px'}
                borderColor={border}
                align='flex-start'
              >
                <Box minW={0}>
                  <Text fontSize='sm' wordBreak='break-all'>
                    {url}
                  </Text>
                  {rowErrors[url] ? (
                    <ErrorText>{rowErrors[url]}</ErrorText>
                  ) : null}
                </Box>
                <IconButton
                  aria-label={`Remove ${url}`}
                  size='xs'
                  variant='outline'
                  icon={<FiX />}
                  isDisabled={busy}
                  onClick={() => remove(url)}
                />
              </HStack>
            ))}
          </Box>
        ) : null}

        <CheckSettings
          settings={settings}
          errors={settingsErrors}
          disabled={busy}
          onChange={patch => setSettings(s => ({ ...s, ...patch }))}
        />

        <FormControl>
          <FormLabel fontSize='sm'>Who gets alerted</FormLabel>
          <Box ref={pickerRef}>
            <ContactGroupCheckboxGroup
              contactGroups={groups}
              value={contactGroupIds}
              onChange={setContactGroupIds}
              isDisabled={busy}
              defaultContactGroupId={defaultGroupId}
              helperText=''
            />
          </Box>
          <AlertsGoTo
            selectedIds={contactGroupIds}
            groups={groups}
            defaultId={defaultGroupId}
            pickerRef={pickerRef}
          />
          {groups.length > 0 && contactGroupIds.length === 0 ? (
            <FormHelperText fontSize='xs' data-testid='no-group-hint'>
              {defaultGroup
                ? `No group selected: alerts go to the default group (${defaultGroup.name}).`
                : 'No group selected: alerts have no recipient until a contact group is set.'}
            </FormHelperText>
          ) : null}
        </FormControl>

        <DiscoveryPanel
          workspaceId={ctx.workspaceId}
          staged={staged}
          monitored={monitored}
          onAdd={addDiscovered}
          attempt={attempt}
          disabled={busy}
        />

        {monitored.length > 0 ? (
          <Text fontSize='xs' color={muted}>
            Already monitoring {monitored.length}{' '}
            {monitored.length === 1 ? 'website' : 'websites'} in this workspace.
          </Text>
        ) : null}
      </VStack>
    </StepFrame>
  );
}
