import {
  Accordion,
  AccordionItem,
  AccordionButton,
  AccordionPanel,
  AccordionIcon,
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
  inherit_system: true,
};
export const METRIC_LABEL_CHOICES = [
  ['configuration_name', 'Configuration name'],
  ['monitoring_group', 'Monitoring group'],
  ['kind', 'Asset type'],
  ['asset_name', 'Token / asset name'],
  ['project', 'Project / repository'],
  ['group', 'Source group'],
];
const EXTRA = ['asset_name', 'project', 'group'];
export default function AutoSyncMetricSettings({
  value = DEFAULT_METRIC_SETTINGS,
  onChange,
  allowedExtraLabels = [],
  systemPolicy = {
    enabled: null,
    labels: ['configuration_name', 'monitoring_group', 'kind'],
  },
}) {
  const settings = { ...DEFAULT_METRIC_SETTINGS, ...value };
  const inherits = value.inherit_system ?? !value.enabled;
  const enabled =
    systemPolicy.enabled === false
      ? false
      : inherits
        ? systemPolicy.enabled === true
        : settings.enabled;
  const available = METRIC_LABEL_CHOICES.map(([key]) => key).filter(
    key =>
      (!EXTRA.includes(key) || allowedExtraLabels.includes(key)) &&
      (systemPolicy.enabled === null || systemPolicy.labels.includes(key))
  );
  const selected = inherits ? systemPolicy.labels : settings.labels;
  const change = patch => onChange({ ...settings, ...patch });
  return (
    <Accordion allowToggle w='full'>
      <AccordionItem borderWidth='1px' borderRadius='md'>
        <AccordionButton>
          <Box flex='1' textAlign='left' fontWeight='medium'>
            Auto-sync metrics
          </Box>
          <AccordionIcon />
        </AccordionButton>
        <AccordionPanel>
          <VStack align='stretch' spacing={3}>
            <Checkbox
              isChecked={inherits}
              onChange={e =>
                change({
                  inherit_system: e.target.checked,
                  ...(e.target.checked
                    ? {}
                    : {
                        enabled,
                        labels: selected.filter(key => available.includes(key)),
                      }),
                })
              }
            >
              Use system settings
            </Checkbox>
            <Text fontSize='sm'>
              System Settings controls metric availability. This configuration{' '}
              {inherits ? 'inherits the selected labels' : 'uses an override'}.
            </Text>
            <Checkbox
              isChecked={enabled}
              isDisabled={inherits || systemPolicy.enabled === false}
              onChange={e =>
                change({
                  enabled: e.target.checked,
                  labels: settings.labels.length
                    ? settings.labels
                    : available.filter(key => !EXTRA.includes(key)),
                })
              }
            >
              Expose additional auto-sync metrics
            </Checkbox>
            {systemPolicy.enabled === false || (inherits && !enabled) ? (
              <Text fontSize='sm'>
                Additional metrics are disabled in System Settings.
              </Text>
            ) : null}
            <Text fontSize='sm'>
              Configuration ID is always included. Select the additional labels
              to expose:
            </Text>
            <SimpleGrid columns={{ base: 1, md: 2 }} spacing={2}>
              {METRIC_LABEL_CHOICES.map(([key, title]) => (
                <Checkbox
                  key={key}
                  isChecked={
                    enabled && available.includes(key) && selected.includes(key)
                  }
                  isDisabled={inherits || !enabled || !available.includes(key)}
                  onChange={e =>
                    change({
                      labels: e.target.checked
                        ? [...settings.labels, key]
                        : settings.labels.filter(label => label !== key),
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
                  onChange={e => change({ monitoring_group: e.target.value })}
                />
              </FormControl>
            ) : null}
            <Alert
              status={
                selected.some(
                  key => EXTRA.includes(key) && available.includes(key)
                )
                  ? 'warning'
                  : 'info'
              }
              fontSize='sm'
              borderRadius='md'
            >
              <AlertIcon />
              Each different label combination creates a time series for each
              scraped replica and can multiply alerts. Selected metadata is
              visible to metrics readers; token secrets are never included.
            </Alert>
            <Text fontSize='xs'>
              Asset names and project/group details cover future creations only.
              Changing labels can start new series; previous samples remain
              until Prometheus retention expires.
            </Text>
          </VStack>
        </AccordionPanel>
      </AccordionItem>
    </Accordion>
  );
}
