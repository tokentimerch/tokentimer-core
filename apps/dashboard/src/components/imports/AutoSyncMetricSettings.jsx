import { useId } from 'react';
import {
  Accordion,
  AccordionItem,
  AccordionButton,
  AccordionPanel,
  AccordionIcon,
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
  Text,
  Tooltip,
  VStack,
  VisuallyHidden,
  useColorModeValue,
} from '@chakra-ui/react';
export const DEFAULT_METRIC_SETTINGS = {
  enabled: false,
  labels: [],
  monitoring_group: '',
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
  systemPolicy = {},
}) {
  const muted = useColorModeValue('gray.600', 'gray.400');
  const managementDescriptionId = useId();

  const settings = { ...DEFAULT_METRIC_SETTINGS, ...value };
  const managed = systemPolicy.override_metrics === true;
  const groupManaged = systemPolicy.override_monitoring_group === true;
  const labelsRestricted = systemPolicy.extra_labels_locked === true;
  const metricManagement = systemPolicy.locked
    ? 'Metric exposure: AUTO_SYNC_METRICS_ENABLED (Helm/Compose); other labels: System Settings → Auto-sync.'
    : 'Metrics: System Settings → Auto-sync.';
  const groupManagement = systemPolicy.monitoring_group_locked
    ? 'Monitoring group: AUTO_SYNC_METRICS_MONITORING_GROUP (Helm/Compose).'
    : 'Monitoring group: System Settings → Auto-sync.';
  const labelManagement =
    'Extra asset labels: AUTO_SYNC_METRICS_EXTRA_LABELS (Helm/Compose).';
  const managementSummary = [
    managed && metricManagement,
    groupManaged && groupManagement,
    labelsRestricted && labelManagement,
  ]
    .filter(Boolean)
    .join(' ');
  const enabled = managed ? systemPolicy.enabled === true : settings.enabled;
  const selected = managed ? systemPolicy.labels : settings.labels;
  const change = patch => onChange({ ...settings, ...patch });
  return (
    <Accordion allowToggle w='full'>
      <AccordionItem borderWidth='1px' borderRadius='md' overflow='hidden'>
        {managementSummary ? (
          <VisuallyHidden id={managementDescriptionId}>
            {managementSummary}
          </VisuallyHidden>
        ) : null}
        <AccordionButton
          px={3}
          py={3}
          aria-describedby={
            managementSummary ? managementDescriptionId : undefined
          }
        >
          <HStack flex='1' spacing={2} textAlign='left'>
            <Text fontSize='sm' fontWeight='semibold'>
              Auto-sync metrics
            </Text>
            {managementSummary ? (
              <Tooltip hasArrow placement='top' label={managementSummary}>
                <Box
                  as='span'
                  display='inline-block'
                  data-testid='auto-sync-management-source'
                >
                  <Badge colorScheme='blue' fontSize='xs' cursor='help'>
                    Managed
                  </Badge>
                </Box>
              </Tooltip>
            ) : null}
          </HStack>
          <AccordionIcon />
        </AccordionButton>
        <AccordionPanel px={3} pb={4}>
          <VStack align='stretch' spacing={4} fontSize='sm'>
            <Text color={muted} fontSize='sm'>
              Environment settings take priority over active global overrides in
              System Settings → Auto-sync. Otherwise, this integration’s saved
              choices apply.
            </Text>
            <Checkbox
              isChecked={enabled}
              isDisabled={managed}
              onChange={e =>
                change({
                  enabled: e.target.checked,
                  labels: settings.labels.length
                    ? settings.labels
                    : METRIC_LABEL_CHOICES.map(([key]) => key).filter(
                        key => !EXTRA.includes(key)
                      ),
                })
              }
            >
              Expose additional auto-sync metrics
            </Checkbox>
            <Box>
              <Text fontSize='sm' mb={2}>
                Additional labels
              </Text>
              <SimpleGrid columns={{ base: 1, md: 2 }} spacing={2}>
                {METRIC_LABEL_CHOICES.map(([key, title]) => {
                  const permitted =
                    !EXTRA.includes(key) || allowedExtraLabels.includes(key);
                  return (
                    <Checkbox
                      key={key}
                      isChecked={enabled && permitted && selected.includes(key)}
                      isDisabled={managed || !enabled || !permitted}
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
                  );
                })}
              </SimpleGrid>
              <Text fontSize='xs' color={muted} mt={2}>
                Configuration ID is always included.
              </Text>
            </Box>
            <FormControl>
              <HStack mb={2}>
                <FormLabel fontSize='sm' mb={0}>
                  Monitoring group label
                </FormLabel>
                {groupManaged ? (
                  <Tooltip hasArrow placement='top' label={groupManagement}>
                    <Box
                      as='span'
                      display='inline-block'
                      tabIndex={0}
                      data-testid='auto-sync-group-management-source'
                    >
                      <Badge colorScheme='blue' fontSize='xs' cursor='help'>
                        Managed
                      </Badge>
                    </Box>
                  </Tooltip>
                ) : null}
              </HStack>
              <Input
                size='sm'
                placeholder='e.g. critical'
                maxLength={64}
                isDisabled={groupManaged}
                value={
                  groupManaged
                    ? systemPolicy.monitoring_group
                    : settings.monitoring_group
                }
                onChange={e => change({ monitoring_group: e.target.value })}
              />
              <FormHelperText fontSize='xs'>
                {groupManaged
                  ? groupManagement
                  : 'Used when the Monitoring group label is selected.'}
              </FormHelperText>
            </FormControl>
            <Alert
              status={
                selected.some(key => EXTRA.includes(key)) ? 'warning' : 'info'
              }
              fontSize='sm'
              borderRadius='md'
              alignItems='start'
            >
              <AlertIcon mt={0.5} />
              <Text fontSize='sm'>
                Combining labels increases time series and alerts. Selected
                metadata is visible to metrics readers; token secrets are never
                included.
              </Text>
            </Alert>
            <Text fontSize='xs' color={muted}>
              Asset names and project/group details cover future creations only.
              Previous samples remain until Prometheus retention expires.
            </Text>
          </VStack>
        </AccordionPanel>
      </AccordionItem>
    </Accordion>
  );
}
