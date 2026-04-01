import { createStandaloneToast } from '@chakra-ui/react';
import { theme } from '../styles/theme.js';

// Centralized toast with consistent defaults across the app
const { toast } = createStandaloneToast({ theme });

const DEFAULT_OPTIONS = {
  position: 'top-right',
  duration: 3000,
  isClosable: true,
  variant: 'subtle',
};

export function showToast(options = {}) {
  try {
    return toast({ ...DEFAULT_OPTIONS, ...options });
  } catch (_) {
    return null;
  }
}

export function showSuccess(title, description) {
  return showToast({ title, description, status: 'success' });
}

export function showWarning(title, description) {
  return showToast({ title, description, status: 'warning' });
}

export function showError(title, description) {
  return showToast({ title, description, status: 'error' });
}

export function showInfo(title, description) {
  return showToast({ title, description, status: 'info' });
}
