import { useEffect, useState } from 'react';
import {
  Alert,
  AlertIcon,
  Badge,
  Box,
  Checkbox,
  FormControl,
  FormHelperText,
  FormLabel,
  HStack,
  Input,
  SimpleGrid,
  Switch,
  Tooltip,
  IconButton,
  Text,
  VStack,
  useColorModeValue,
} from '@chakra-ui/react';
import { InfoOutlineIcon } from '@chakra-ui/icons';
import apiClient from '../utils/apiClient';
import { DashboardActionButton } from './DashboardPrimitives';
import { METRIC_LABEL_CHOICES } from './imports/AutoSyncMetricSettings.jsx';
const EXTRA = ['asset_name', 'project', 'group'];
export default function AutoSyncSystemMetricSettings({ onConfiguredChange }) {
  const muted = useColorModeValue('gray.600', 'gray.400');

  const [policy, setPolicy] = useState(null),
    [error, setError] = useState(''),
    [saving, setSaving] = useState(false),
    [saved, setSaved] = useState(false);
  useEffect(() => {
    let active = true;
    apiClient
      .get('/api/v1/admin/auto-sync/metrics')
      .then(r => {
        if (active) {
          setPolicy(r.data);
          onConfiguredChange?.(
            r.data.override_metrics || r.data.override_monitoring_group
          );
        }
      })
      .catch(() => {
        if (active) setError('Unable to load auto-sync settings.');
      });
    return () => {
      active = false;
    };
  }, [onConfiguredChange]);
  const change = patch => {
    setPolicy({ ...policy, ...patch });
    setSaved(false);
  };
  async function save() {
    setSaving(true);
    setError('');
    setSaved(false);
    try {
      const r = await apiClient.put('/api/v1/admin/auto-sync/metrics', {
        override_metrics: policy.override_metrics,
        enabled: policy.enabled === true,
        labels: policy.labels,
        override_monitoring_group: policy.override_monitoring_group,
        monitoring_group: policy.monitoring_group,
      });
      setPolicy(r.data);
      onConfiguredChange?.(
        r.data.override_metrics || r.data.override_monitoring_group
      );
      setSaved(true);
    } catch {
      setError('Unable to save auto-sync settings.');
    } finally {
      setSaving(false);
    }
  }
  if (!policy)
    return <Text fontSize='sm'>{error || 'Loading auto-sync settings…'}</Text>;
  return (
    <VStack
      align='stretch'
      spacing={4}
      fontSize='sm'
      sx={{ '& .chakra-checkbox__label': { fontSize: 'sm' } }}
    >
      <Text fontSize='sm'>
        Global overrides apply to every integration and lock the corresponding
        connection controls. Turn an override off to restore each integration’s
        saved settings.
      </Text>
      <Box borderWidth='1px' borderRadius='md' p={4}>
        <VStack align='stretch' spacing={3}>
          <HStack justify='space-between' flexWrap='wrap'>
            <FormControl
              display='flex'
              alignItems='center'
              gap={3}
              width='auto'
            >
              <Switch
                id='override-integration-metrics'
                size='md'
                colorScheme='blue'
                isChecked={policy.override_metrics}
                isDisabled={saving || policy.locked}
                onChange={e => change({ override_metrics: e.target.checked })}
              />
              <FormLabel
                htmlFor='override-integration-metrics'
                mb={0}
                fontSize='sm'
                fontWeight='semibold'
              >
                Override integration metrics
              </FormLabel>
              <Tooltip
                hasArrow
                label='When saved, applies the additional metrics switch and selected labels below to every integration and locks their metric controls. Turn this off and save to restore each integration’s saved choices. Monitoring group is overridden separately; environment restrictions always take priority.'
              >
                <IconButton
                  size='xs'
                  variant='ghost'
                  aria-label='About overriding integration metrics'
                  icon={<InfoOutlineIcon />}
                />
              </Tooltip>
            </FormControl>
            {policy.locked ? <Badge>Set by environment</Badge> : null}
          </HStack>
          <Checkbox
            isChecked={policy.enabled === true}
            isDisabled={saving || !policy.override_metrics || policy.locked}
            onChange={e => change({ enabled: e.target.checked })}
          >
            Enable additional auto-sync metrics
          </Checkbox>
          <SimpleGrid columns={{ base: 1, md: 2 }} spacing={2}>
            {METRIC_LABEL_CHOICES.map(([key, title]) => {
              const permitted =
                !EXTRA.includes(key) || policy.extra_labels.includes(key);
              return (
                <Checkbox
                  key={key}
                  isChecked={permitted && policy.labels.includes(key)}
                  isDisabled={
                    saving ||
                    !policy.override_metrics ||
                    !policy.enabled ||
                    !permitted ||
                    (EXTRA.includes(key) && policy.extra_labels_locked)
                  }
                  onChange={e =>
                    change({
                      labels: e.target.checked
                        ? [...policy.labels, key]
                        : policy.labels.filter(label => label !== key),
                    })
                  }
                >
                  {title}
                </Checkbox>
              );
            })}
          </SimpleGrid>
          {policy.extra_labels_locked ? (
            <Badge alignSelf='start'>Labels set by environment</Badge>
          ) : null}
          <Text fontSize='xs' color={muted}>
            Combining labels increases time series and alerts and exposes
            metadata. Asset labels are off by default; environment restrictions
            take priority.
          </Text>
        </VStack>
      </Box>
      <Box borderWidth='1px' borderRadius='md' p={4}>
        <VStack align='stretch' spacing={3}>
          <HStack justify='space-between' flexWrap='wrap'>
            <FormControl
              display='flex'
              alignItems='center'
              gap={3}
              width='auto'
            >
              <Switch
                id='override-monitoring-group'
                size='md'
                colorScheme='blue'
                isChecked={policy.override_monitoring_group}
                isDisabled={saving || policy.monitoring_group_locked}
                onChange={e =>
                  change({ override_monitoring_group: e.target.checked })
                }
              />
              <FormLabel
                htmlFor='override-monitoring-group'
                mb={0}
                fontSize='sm'
                fontWeight='semibold'
              >
                Override monitoring group
              </FormLabel>
              <Tooltip
                hasArrow
                label='When saved, applies this monitoring group to every integration and locks their group controls. An empty value clears the group. Turn this off and save to restore each integration’s saved group. The group appears in metrics only when its label is selected; environment settings take priority.'
              >
                <IconButton
                  size='xs'
                  variant='ghost'
                  aria-label='About overriding monitoring group'
                  icon={<InfoOutlineIcon />}
                />
              </Tooltip>
            </FormControl>
            {policy.monitoring_group_locked ? (
              <Badge>Set by environment</Badge>
            ) : null}
          </HStack>
          <FormControl>
            <FormLabel fontSize='sm'>Monitoring group label</FormLabel>
            <Input
              size='sm'
              placeholder='e.g. critical'
              maxLength={64}
              value={policy.monitoring_group}
              isDisabled={
                saving ||
                !policy.override_monitoring_group ||
                policy.monitoring_group_locked
              }
              onChange={e => change({ monitoring_group: e.target.value })}
            />
            <FormHelperText fontSize='xs'>
              The group is exposed when its metric label is selected. An empty
              override clears the group.
            </FormHelperText>
          </FormControl>
        </VStack>
      </Box>
      {error ? (
        <Alert status='error'>
          <AlertIcon />
          {error}
        </Alert>
      ) : null}
      {saved ? (
        <Text role='status' fontSize='sm'>
          Auto-sync settings saved.
        </Text>
      ) : null}
      <DashboardActionButton
        alignSelf='start'
        isLoading={saving}
        onClick={save}
      >
        Save auto-sync settings
      </DashboardActionButton>
    </VStack>
  );
}
