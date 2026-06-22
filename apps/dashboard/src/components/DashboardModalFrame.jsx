import { useMemo } from 'react';
import { ModalContent, Text, useColorModeValue } from '@chakra-ui/react';
import {
  createDashboardModalDangerButtonProps,
  createDashboardModalFieldProps,
  createDashboardModalLabelProps,
  createDashboardModalOutlineButtonProps,
  createDashboardModalPrimaryButtonProps,
  dashboardDialogFooterLayoutSx,
  dashboardModalDescriptionProps,
  dashboardModalTitleProps,
  dashboardModalTokenModes,
} from '../styles/theme.js';

export { DASHBOARD_MODAL_HEADING_FONT } from '../styles/theme.js';

export function DashboardModalTitle({ children, color, ...props }) {
  const defaultColor = useColorModeValue(
    dashboardModalTokenModes.light.text,
    dashboardModalTokenModes.dark.text
  );

  return (
    <Text
      {...dashboardModalTitleProps}
      color={color ?? defaultColor}
      {...props}
    >
      {children}
    </Text>
  );
}

export function DashboardModalDescription({ children, color, ...props }) {
  const defaultColor = useColorModeValue(
    dashboardModalTokenModes.light.subtleText,
    dashboardModalTokenModes.dark.subtleText
  );

  return (
    <Text
      {...dashboardModalDescriptionProps}
      color={color ?? defaultColor}
      {...props}
    >
      {children}
    </Text>
  );
}

const DASHBOARD_MODAL_MAX_WIDTHS = {
  standard: 'xl',
  workflow: '6xl',
  danger: 'md',
  detail: '800px',
};

/**
 * Semantic modal helpers. Visual shell styling lives in theme.js (Modal / AlertDialog baseStyle).
 */
export function useDashboardModalProps() {
  const tokens = useColorModeValue(
    dashboardModalTokenModes.light,
    dashboardModalTokenModes.dark
  );

  return useMemo(
    () => ({
      overlayProps: {},
      contentProps: {},
      headerProps: {},
      bodyProps: {},
      footerProps: {
        sx: dashboardDialogFooterLayoutSx,
      },
      closeButtonProps: {},
      fieldProps: createDashboardModalFieldProps(tokens),
      labelProps: createDashboardModalLabelProps(tokens),
      outlineButtonProps: createDashboardModalOutlineButtonProps(tokens),
      primaryButtonProps: createDashboardModalPrimaryButtonProps(),
      dangerButtonProps: createDashboardModalDangerButtonProps(),
      tokens,
    }),
    [tokens]
  );
}

export function DashboardModalFrame({
  type = 'standard',
  children,
  containerProps,
  ...rest
}) {
  const maxW =
    DASHBOARD_MODAL_MAX_WIDTHS[type] ?? DASHBOARD_MODAL_MAX_WIDTHS.standard;

  return (
    <ModalContent maxW={maxW} containerProps={containerProps} {...rest}>
      {children}
    </ModalContent>
  );
}
