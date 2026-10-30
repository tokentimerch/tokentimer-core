import { useEffect, useState } from 'react';
import {
  Alert,
  AlertIcon,
  Badge,
  Checkbox,
  SimpleGrid,
  Text,
  VStack,
} from '@chakra-ui/react';
import apiClient from '../utils/apiClient';
import { DashboardActionButton } from './DashboardPrimitives';
import { METRIC_LABEL_CHOICES } from './imports/AutoSyncMetricSettings.jsx';
const EXTRA = ['asset_name', 'project', 'group'];
export default function AutoSyncSystemMetricSettings() {
  const [policy, setPolicy] = useState(null),
    [error, setError] = useState(''),
    [saving, setSaving] = useState(false),
    [saved, setSaved] = useState(false);
  useEffect(() => {
    let active = true;
    apiClient
      .get('/api/v1/admin/auto-sync/metrics')
      .then(r => {
        if (active) setPolicy(r.data);
      })
      .catch(() => {
        if (active) setError('Unable to load auto-sync metric settings.');
      });
    return () => {
      active = false;
    };
  }, []);
  async function save() {
    setSaving(true);
    setError('');
    setSaved(false);
    try {
      const r = await apiClient.put('/api/v1/admin/auto-sync/metrics', {
        enabled: policy.enabled,
        labels: policy.labels,
      });
      setPolicy(r.data);
      setSaved(true);
    } catch {
      setError('Unable to save auto-sync metric settings.');
    } finally {
      setSaving(false);
    }
  }
  if (!policy)
    return <Text>{error || 'Loading auto-sync metric settings…'}</Text>;
  return (
    <VStack align='stretch' spacing={3}>
      <Checkbox
        isChecked={policy.enabled}
        isDisabled={saving || policy.locked}
        onChange={e => {
          setPolicy({ ...policy, enabled: e.target.checked });
          setSaved(false);
        }}
      >
        Enable additional auto-sync metrics
      </Checkbox>
      {policy.locked ? (
        <Badge alignSelf='start'>Set by environment</Badge>
      ) : null}
      <Text fontSize='sm'>
        Applies to existing and new configurations using system settings.
        Configuration overrides can disable exposure or use fewer labels.
      </Text>
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
                !policy.enabled ||
                !permitted ||
                (EXTRA.includes(key) && policy.extra_labels_locked)
              }
              onChange={e => {
                setPolicy({
                  ...policy,
                  labels: e.target.checked
                    ? [...policy.labels, key]
                    : policy.labels.filter(label => label !== key),
                });
                setSaved(false);
              }}
            >
              {title}
            </Checkbox>
          );
        })}
      </SimpleGrid>
      {policy.extra_labels_locked ? (
        <Badge alignSelf='start'>Labels set by environment</Badge>
      ) : null}
      <Text fontSize='sm'>
        Environment settings take precedence over saved choices. Combining
        labels increases series and alert cardinality and exposes metadata.
      </Text>
      {error ? (
        <Alert status='error'>
          <AlertIcon />
          {error}
        </Alert>
      ) : null}
      {saved ? (
        <Text role='status'>Auto-sync metric settings saved.</Text>
      ) : null}
      <DashboardActionButton
        alignSelf='start'
        onClick={save}
        isLoading={saving}
      >
        Save auto-sync metrics
      </DashboardActionButton>
    </VStack>
  );
}
