import { ModalContent } from '@chakra-ui/react';

const DASHBOARD_MODAL_MAX_WIDTHS = {
  standard: 'xl',
  workflow: '6xl',
  danger: 'md',
  detail: '800px',
};

// Dialog appearance (surface, border, header/footer dividers, shadow) is owned
// by the global Modal theme in styles/theme.js so every modal is harmonized.
// These no-op prop bags are kept for backwards compatibility with callers that
// still spread them onto ModalContent / header / body / footer.
const EMPTY_MODAL_PROPS = Object.freeze({
  contentProps: {},
  headerProps: {},
  bodyProps: {},
  footerProps: {},
});

export function useDashboardModalProps() {
  return EMPTY_MODAL_PROPS;
}

export function DashboardModalFrame({ type = 'standard', children, ...rest }) {
  const maxW =
    DASHBOARD_MODAL_MAX_WIDTHS[type] ?? DASHBOARD_MODAL_MAX_WIDTHS.standard;

  return (
    <ModalContent maxW={maxW} {...rest}>
      {children}
    </ModalContent>
  );
}
