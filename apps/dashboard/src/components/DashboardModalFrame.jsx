import { useMemo } from 'react';
import { ModalContent, useColorModeValue } from '@chakra-ui/react';

const DASHBOARD_MODAL_MAX_WIDTHS = {
  standard: 'xl',
  workflow: '6xl',
  danger: 'md',
  detail: '800px',
};

const dashboardModalTokenModes = Object.freeze({
  light: Object.freeze({
    overlayBg: 'rgba(15, 23, 42, 0.46)',
    surfaceBg: '#ffffff',
    fieldBg: '#f8fafc',
    headerBg: '#f8fafc',
    footerBg: '#f8fafc',
    border: 'rgba(148, 163, 184, 0.34)',
    text: '#0f172a',
    muted: '#64748b',
    subtleText: '#475569',
    inputBg: '#ffffff',
    inputBorder: 'rgba(100, 116, 139, 0.5)',
    focusBorder: '#2563eb',
    sectionAccent: '#2563eb',
    buttonBorder: 'rgba(100, 116, 139, 0.48)',
    danger: '#dc2626',
    optionBg: '#ffffff',
    optionText: '#0f172a',
    shadow: '0 24px 70px rgba(0, 0, 0, 0.42)',
  }),
  dark: Object.freeze({
    overlayBg: 'rgba(2, 6, 23, 0.72)',
    surfaceBg: '#0d131a',
    fieldBg: '#0d131a',
    headerBg: '#0d131a',
    footerBg: '#0d131a',
    border: 'rgba(148, 163, 184, 0.18)',
    text: '#f8fafc',
    muted: '#94a3b8',
    subtleText: '#cbd5e1',
    inputBg: '#090d15',
    inputBorder: 'rgba(148, 163, 184, 0.28)',
    focusBorder: '#3b82f6',
    sectionAccent: '#60a5fa',
    buttonBorder: 'rgba(148, 163, 184, 0.34)',
    danger: '#f87171',
    optionBg: '#0f172a',
    optionText: '#f8fafc',
    shadow: '0 24px 70px rgba(0, 0, 0, 0.42)',
  }),
});

function createControlSx(dashboardModalTokens) {
  return {
    '.chakra-form__label': {
      color: dashboardModalTokens.muted,
      fontWeight: 600,
    },
    '.chakra-input, .chakra-select, .chakra-textarea': {
      bg: dashboardModalTokens.inputBg,
      borderColor: dashboardModalTokens.inputBorder,
      color: dashboardModalTokens.text,
      borderRadius: '10px',
    },
    '.chakra-input::placeholder, .chakra-textarea::placeholder': {
      color: dashboardModalTokens.muted,
      opacity: 1,
    },
    '.chakra-input:hover, .chakra-select:hover, .chakra-textarea:hover': {
      borderColor: dashboardModalTokens.focusBorder,
    },
    '.chakra-input:focus-visible, .chakra-select:focus-visible, .chakra-textarea:focus-visible':
      {
        borderColor: dashboardModalTokens.focusBorder,
        boxShadow: `0 0 0 1px ${dashboardModalTokens.focusBorder}`,
      },
    '.chakra-input[aria-invalid=true], .chakra-select[aria-invalid=true], .chakra-textarea[aria-invalid=true]':
      {
        borderColor: dashboardModalTokens.danger,
      },
    '.chakra-form__error-message': {
      color: dashboardModalTokens.danger,
    },
    '.chakra-table th': {
      color: dashboardModalTokens.muted,
      borderColor: dashboardModalTokens.border,
    },
    '.chakra-table td': {
      borderColor: dashboardModalTokens.border,
    },
    '.chakra-divider': {
      borderColor: dashboardModalTokens.border,
    },
    option: {
      background: dashboardModalTokens.optionBg,
      color: dashboardModalTokens.optionText,
    },
  };
}

export function useDashboardModalProps() {
  const dashboardModalTokens = useColorModeValue(
    dashboardModalTokenModes.light,
    dashboardModalTokenModes.dark
  );

  return useMemo(
    () => ({
      overlayProps: {
        bg: dashboardModalTokens.overlayBg,
      },
      contentProps: {
        bg: dashboardModalTokens.surfaceBg,
        color: dashboardModalTokens.text,
        border: '1px solid',
        borderColor: dashboardModalTokens.border,
        borderRadius: { base: '14px', md: '18px' },
        boxShadow: dashboardModalTokens.shadow,
        overflow: 'hidden',
      },
      headerProps: {
        bg: dashboardModalTokens.headerBg,
        borderBottom: '1px solid',
        borderColor: dashboardModalTokens.border,
        color: dashboardModalTokens.text,
        px: { base: 4, md: 6 },
        py: { base: 4, md: 5 },
        pr: { base: 12, md: 14 },
      },
      bodyProps: {
        bg: dashboardModalTokens.surfaceBg,
        color: dashboardModalTokens.text,
        px: { base: 4, md: 6 },
        py: { base: 5, md: 6 },
        sx: createControlSx(dashboardModalTokens),
      },
      footerProps: {
        bg: dashboardModalTokens.footerBg,
        borderTop: '1px solid',
        borderColor: dashboardModalTokens.border,
        px: { base: 4, md: 6 },
        py: { base: 4, md: 5 },
      },
      closeButtonProps: {
        color: dashboardModalTokens.muted,
        top: { base: 3, md: 4 },
        right: { base: 3, md: 4 },
        borderRadius: '10px',
        _hover: {
          bg: dashboardModalTokens.fieldBg,
          color: dashboardModalTokens.text,
        },
      },
      fieldProps: {
        bg: dashboardModalTokens.fieldBg,
        border: '1px solid',
        borderColor: dashboardModalTokens.border,
        borderRadius: '12px',
      },
      labelProps: {
        color: dashboardModalTokens.muted,
        fontWeight: 'semibold',
        fontSize: 'sm',
      },
      tokens: dashboardModalTokens,
    }),
    [dashboardModalTokens]
  );
}

export function DashboardModalFrame({ type = 'standard', children, ...rest }) {
  const maxW =
    DASHBOARD_MODAL_MAX_WIDTHS[type] ?? DASHBOARD_MODAL_MAX_WIDTHS.standard;
  const { contentProps } = useDashboardModalProps();

  return (
    <ModalContent maxW={maxW} {...contentProps} {...rest}>
      {children}
    </ModalContent>
  );
}
