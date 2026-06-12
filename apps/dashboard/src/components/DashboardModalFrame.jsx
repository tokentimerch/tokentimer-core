import { ModalContent } from '@chakra-ui/react';

const DASHBOARD_MODAL_MAX_WIDTHS = {
  standard: 'xl',
  workflow: '6xl',
  danger: 'md',
  detail: '800px',
};

const dashboardModalTokens = Object.freeze({
  overlayBg: 'rgba(2, 6, 23, 0.72)',
  surfaceBg: '#0d131a',
  fieldBg: 'rgba(9, 13, 21, 0.66)',
  headerBg: '#0d131a',
  footerBg: '#0b1118',
  border: 'rgba(148, 163, 184, 0.18)',
  text: '#f8fafc',
  muted: '#94a3b8',
  subtleText: '#cbd5e1',
  inputBg: '#090d15',
  inputBorder: 'rgba(148, 163, 184, 0.28)',
  focusBorder: '#3b82f6',
});

const controlSx = {
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
  },
  '.chakra-input:hover, .chakra-select:hover, .chakra-textarea:hover': {
    borderColor: dashboardModalTokens.focusBorder,
  },
  '.chakra-input:focus-visible, .chakra-select:focus-visible, .chakra-textarea:focus-visible':
    {
      borderColor: dashboardModalTokens.focusBorder,
      boxShadow: `0 0 0 1px ${dashboardModalTokens.focusBorder}`,
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
    background: '#0f172a',
    color: dashboardModalTokens.text,
  },
};

const DASHBOARD_MODAL_PROPS = Object.freeze({
  overlayProps: {
    bg: dashboardModalTokens.overlayBg,
  },
  contentProps: {
    bg: dashboardModalTokens.surfaceBg,
    border: '1px solid',
    borderColor: dashboardModalTokens.border,
    borderRadius: { base: '14px', md: '18px' },
    boxShadow: '0 24px 70px rgba(0, 0, 0, 0.42)',
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
    sx: controlSx,
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
});

export function useDashboardModalProps() {
  return DASHBOARD_MODAL_PROPS;
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
