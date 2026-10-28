import {
  Alert,
  AlertIcon,
  Box,
  Checkbox,
  FormControl,
  FormLabel,
  Input,
  SimpleGrid,
  Text,
  VStack,
} from '@chakra-ui/react';

export const DEFAULT_METRIC_SETTINGS = {
  enabled: false,
  labels: [],
  monitoring_group: '',
};
const CHOICES = [
  ['configuration_name', 'Configuration name'],
  ['monitoring_group', 'Monitoring group'],
  ['kind', 'Asset type'],
  ['asset_name', 'Token / asset name'],
  ['project', 'Project / repository'],
  ['group', 'Source group'],
];
export default function AutoSyncMetricSettings({
  value = DEFAULT_METRIC_SETTINGS,
  onChange,
}) {
  const settings = { ...DEFAULT_METRIC_SETTINGS, ...value };
  const selected = settings.labels || [];
  const detailed = selected.some(label =>
    ['asset_name', 'project', 'group'].includes(label)
  );
  return (
    <Box borderWidth='1px' borderRadius='md' p={3}>
      <VStack align='stretch' spacing={3}>
        <Checkbox
          isChecked={settings.enabled}
          onChange={event =>
            onChange({
              ...settings,
              enabled: event.target.checked,
              labels:
                event.target.checked && selected.length === 0
                  ? ['configuration_name', 'monitoring_group', 'kind']
                  : selected,
            })
          }
        >
          Expose additional auto-sync metrics
        </Checkbox>
        {settings.enabled ? (
          <>
            <Text fontSize='sm'>
              Configuration ID is always included. Select the additional labels
              to expose:
            </Text>
            <SimpleGrid columns={{ base: 1, md: 2 }} spacing={2}>
              {CHOICES.map(([label, title]) => (
                <Checkbox
                  key={label}
                  isChecked={selected.includes(label)}
                  onChange={event =>
                    onChange({
                      ...settings,
                      labels: event.target.checked
                        ? [...selected, label]
                        : selected.filter(item => item !== label),
                    })
                  }
                >
                  {title}
                </Checkbox>
              ))}
            </SimpleGrid>
            {selected.includes('monitoring_group') ? (
              <FormControl>
                <FormLabel fontSize='sm'>Monitoring group label</FormLabel>
                <Input
                  size='sm'
                  placeholder='e.g. critical'
                  maxLength={64}
                  value={settings.monitoring_group}
                  onChange={event =>
                    onChange({
                      ...settings,
                      monitoring_group: event.target.value,
                    })
                  }
                />
              </FormControl>
            ) : null}
            <Alert
              status={detailed ? 'warning' : 'info'}
              fontSize='sm'
              borderRadius='md'
            >
              <AlertIcon />
              Each different label combination creates a time series for each
              scraped replica. Token names and project/group labels can
              significantly increase the number of series and alerts.
            </Alert>
            <Text fontSize='xs'>
              Selected metadata is visible to readers of the metrics endpoint;
              token secrets are never included. Asset names and project/group
              details are captured for future creations only. Changing labels,
              configuration names or monitoring groups can start new series.
              Disabling exposure hides the additional metrics; previous samples
              remain until Prometheus retention expires.
            </Text>
          </>
        ) : null}
      </VStack>
    </Box>
  );
}
