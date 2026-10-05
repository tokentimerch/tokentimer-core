import { Link as ChakraLink } from '@chakra-ui/react';
import { Link as RouterLink } from 'react-router';
import { showToast, showWarning } from './toast.js';

export const AUTO_SYNC_MULTI_CONFIG_HASH = 'auto-sync-multi-config';
export const AUTO_SYNC_MULTI_CONFIG_HREF = `/system-settings#${AUTO_SYNC_MULTI_CONFIG_HASH}`;

export function isMultiConfigDisabledError(error) {
  return error?.response?.data?.code === 'MULTI_CONFIG_DISABLED';
}

export function showAutoSyncEnableError(error) {
  const data = error?.response?.data;
  if (!isMultiConfigDisabledError(error)) {
    showWarning(data?.error || 'Failed to enable auto-sync');
    return;
  }
  const href = data?.href || AUTO_SYNC_MULTI_CONFIG_HREF;
  showToast({
    status: 'warning',
    duration: 9000,
    title: data?.error || 'Multiple configurations require operator activation',
    description: (
      <ChakraLink as={RouterLink} to={href} textDecoration='underline'>
        Activate in System settings
      </ChakraLink>
    ),
  });
}
