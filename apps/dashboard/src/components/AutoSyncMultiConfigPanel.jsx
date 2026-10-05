import { useEffect, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Checkbox,
  HStack,
  Text,
  VStack,
} from '@chakra-ui/react';
import { SettingsFormWidth } from './SettingsPageShell.jsx';
import { DashboardActionButton } from './DashboardPrimitives';
import apiClient from '../utils/apiClient';
import { showSuccess, showWarning } from '../utils/toast.js';
import { useDashboardTheme } from '../hooks/useDashboardTheme';
import { logger } from '../utils/logger.js';

export default function AutoSyncMultiConfigPanel({ onEnabledChange }) {
  const { muted } = useDashboardTheme();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [enabled, setEnabled] = useState(false);
  const [workersDrained, setWorkersDrained] = useState(false);
  const [workerImageVerified, setWorkerImageVerified] = useState(false);

  function applyEnabled(nextEnabled) {
    setEnabled(nextEnabled);
    onEnabledChange?.(nextEnabled);
  }

  async function loadState() {
    try {
      setLoading(true);
      const res = await apiClient.get('/api/v1/admin/auto-sync/activation');
      applyEnabled(res.data?.enabled === true);
    } catch (e) {
      logger.error('Failed to load auto-sync activation', e);
      applyEnabled(false);
      showWarning(
        e?.response?.data?.error || 'Failed to load auto-sync activation'
      );
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadState();
  }, []);

  async function handleActivate() {
    try {
      setSaving(true);
      const res = await apiClient.post('/api/v1/admin/auto-sync/activation', {
        workers_drained: true,
        worker_image_verified: true,
      });
      applyEnabled(res.data?.enabled === true);
      showSuccess('Multiple auto-sync configurations are now allowed');
    } catch (e) {
      showWarning(
        e?.response?.data?.error || 'Failed to activate multiple configurations'
      );
    } finally {
      setSaving(false);
    }
  }

  if (!loading && enabled) return null;

  return (
    <SettingsFormWidth maxW='100%'>
      {loading ? (
        <Text fontSize='sm' color={muted}>
          Loading activation state...
        </Text>
      ) : (
        <VStack align='stretch' spacing={4}>
          <Alert status='warning' borderRadius='md'>
            <AlertIcon />
            <AlertDescription fontSize='sm'>
              Each workspace and provider starts with one configuration. Confirm
              old workers are gone and this release is running before allowing
              duplicates. Activation cannot be reversed while multiple
              configurations exist.
            </AlertDescription>
          </Alert>
          <Checkbox
            isChecked={workersDrained}
            onChange={e => setWorkersDrained(e.target.checked)}
          >
            Old auto-sync workers have been drained
          </Checkbox>
          <Checkbox
            isChecked={workerImageVerified}
            onChange={e => setWorkerImageVerified(e.target.checked)}
          >
            This deployment uses the fencing-aware worker image
          </Checkbox>
          <HStack justify='flex-end'>
            <DashboardActionButton
              colorScheme='blue'
              isLoading={saving}
              isDisabled={!workersDrained || !workerImageVerified}
              onClick={handleActivate}
              w={{ base: '100%', md: 'auto' }}
            >
              Allow multiple configurations
            </DashboardActionButton>
          </HStack>
        </VStack>
      )}
    </SettingsFormWidth>
  );
}
