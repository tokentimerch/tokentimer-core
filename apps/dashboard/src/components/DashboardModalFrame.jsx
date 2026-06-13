import { useMemo } from 'react';
import { ModalContent, useColorModeValue } from '@chakra-ui/react';

const DASHBOARD_MODAL_MAX_WIDTHS = {
  standard: 'xl',
  workflow: '6xl',
  danger: 'md',
  detail: '800px',
};

function useDashboardModalTokens() {
  const overlayBg = useColorModeValue(
    'rgba(15, 23, 42, 0.55)',
    'rgba(2, 6, 23, 0.72)'
  );
  const surfaceBg = useColorModeValue('#ffffff', '#0d131a');
  const fieldBg = useColorModeValue('#f8fafc', 'rgba(9, 13, 21, 0.66)');
  const headerBg = useColorModeValue('#ffffff', '#0d131a');
  const footerBg = useColorModeValue('#f8fafc', '#0b1118');
  const border = useColorModeValue('#e2e8f0', 'rgba(148, 163, 184, 0.18)');
  const outlineBorder = useColorModeValue(
    '#cbd5e1',
    'rgba(148, 163, 184, 0.34)'
  );
  const text = useColorModeValue('#0f172a', '#f8fafc');
  const muted = useColorModeValue('#64748b', '#94a3b8');
  const subtleText = useColorModeValue('#334155', '#cbd5e1');
  const inputBg = useColorModeValue('#ffffff', '#090d15');
  const inputBorder = useColorModeValue('#cbd5e1', 'rgba(148, 163, 184, 0.28)');
  const focusBorder = '#3b82f6';
  const optionBg = useColorModeValue('#ffffff', '#0f172a');
  const contentShadow = useColorModeValue(
    '0 24px 60px -15px rgba(15, 23, 42, 0.4)',
    '0 24px 70px rgba(0, 0, 0, 0.42)'
  );

  return useMemo(
    () => ({
      overlayBg,
      surfaceBg,
      fieldBg,
      headerBg,
      footerBg,
      border,
      outlineBorder,
      text,
      muted,
      subtleText,
      inputBg,
      inputBorder,
      focusBorder,
      optionBg,
      contentShadow,
    }),
    [
      overlayBg,
      surfaceBg,
      fieldBg,
      headerBg,
      footerBg,
      border,
      outlineBorder,
      text,
      muted,
      subtleText,
      inputBg,
      inputBorder,
      focusBorder,
      optionBg,
      contentShadow,
    ]
  );
}

function buildControlSx(tokens) {
  return {
    '.chakra-form__label': {
      color: tokens.muted,
      fontWeight: 600,
    },
    '.chakra-input, .chakra-select, .chakra-textarea': {
      bg: tokens.inputBg,
      borderColor: tokens.inputBorder,
      color: tokens.text,
      borderRadius: '10px',
    },
    '.chakra-input::placeholder, .chakra-textarea::placeholder': {
      color: tokens.muted,
    },
    '.chakra-input:hover, .chakra-select:hover, .chakra-textarea:hover': {
      borderColor: tokens.focusBorder,
    },
    '.chakra-input:focus-visible, .chakra-select:focus-visible, .chakra-textarea:focus-visible':
      {
        borderColor: tokens.focusBorder,
        boxShadow: `0 0 0 1px ${tokens.focusBorder}`,
      },
    '.chakra-table th': {
      color: tokens.muted,
      borderColor: tokens.border,
    },
    '.chakra-table td': {
      borderColor: tokens.border,
    },
    '.chakra-divider': {
      borderColor: tokens.border,
    },
    option: {
      background: tokens.optionBg,
      color: tokens.text,
    },
  };
}

export function useDashboardModalProps() {
  const tokens = useDashboardModalTokens();

  return useMemo(
    () => ({
      overlayProps: {
        bg: tokens.overlayBg,
      },
      contentProps: {
        bg: tokens.surfaceBg,
        border: '1px solid',
        borderColor: tokens.border,
        borderRadius: { base: '14px', md: '18px' },
        boxShadow: tokens.contentShadow,
        overflow: 'hidden',
      },
      headerProps: {
        bg: tokens.headerBg,
        borderBottom: '1px solid',
        borderColor: tokens.border,
        color: tokens.text,
        px: { base: 4, md: 6 },
        py: { base: 4, md: 5 },
        pr: { base: 12, md: 14 },
      },
      bodyProps: {
        bg: tokens.surfaceBg,
        color: tokens.text,
        px: { base: 4, md: 6 },
        py: { base: 5, md: 6 },
        sx: buildControlSx(tokens),
      },
      footerProps: {
        bg: tokens.footerBg,
        borderTop: '1px solid',
        borderColor: tokens.border,
        px: { base: 4, md: 6 },
        py: { base: 4, md: 5 },
      },
      closeButtonProps: {
        color: tokens.muted,
        top: { base: 3, md: 4 },
        right: { base: 3, md: 4 },
        borderRadius: '10px',
        _hover: {
          bg: tokens.fieldBg,
          color: tokens.text,
        },
      },
      fieldProps: {
        bg: tokens.fieldBg,
        border: '1px solid',
        borderColor: tokens.border,
        borderRadius: '12px',
      },
      labelProps: {
        color: tokens.muted,
        fontWeight: 'semibold',
        fontSize: 'sm',
      },
      tokens,
    }),
    [tokens]
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
