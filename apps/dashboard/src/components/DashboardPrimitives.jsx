import { forwardRef } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  Box,
  Button,
  Heading,
  HStack,
  Spinner,
  Text,
  VStack,
} from '@chakra-ui/react';
import { useDashboardTheme } from '../hooks/useDashboardTheme';
import { SETTINGS_PANEL_PADDING } from '../styles/dashboardLayout';

export function DashboardPanel({
  children,
  p = SETTINGS_PANEL_PADDING,
  borderRadius = 'md',
  ...props
}) {
  const { surface, border } = useDashboardTheme();

  return (
    <Box
      bg={surface}
      border='1px solid'
      borderColor={border}
      borderRadius={borderRadius}
      p={p}
      overflow='hidden'
      w='full'
      maxW='100%'
      {...props}
    >
      {children}
    </Box>
  );
}

export function DashboardPanelHeader({
  title,
  description,
  action,
  children,
  mb = 4,
}) {
  const { muted } = useDashboardTheme();

  return (
    <HStack
      align={{ base: 'stretch', sm: 'start' }}
      justify='space-between'
      spacing={4}
      mb={mb}
      flexWrap='wrap'
    >
      <Box minW={0}>
        <Heading
          as='h2'
          size='sm'
          color='inherit'
          fontFamily='Archivo, system-ui, sans-serif'
          fontWeight='bold'
          lineHeight='short'
        >
          {title}
        </Heading>
        {description ? (
          <Text mt={1} color={muted} fontSize='sm'>
            {description}
          </Text>
        ) : null}
        {children}
      </Box>
      {action ? <Box flexShrink={0}>{action}</Box> : null}
    </HStack>
  );
}

export const DashboardActionButton = forwardRef(function DashboardActionButton(
  { children, ...props },
  ref
) {
  return (
    <Button
      ref={ref}
      size='sm'
      h='36px'
      px={4}
      borderRadius='md'
      fontSize='sm'
      fontWeight='semibold'
      {...props}
    >
      {children}
    </Button>
  );
});

export function DashboardState({
  type = 'empty',
  title,
  description,
  action,
  py = 10,
}) {
  const { muted } = useDashboardTheme();
  const isLoading = type === 'loading';

  return (
    <VStack spacing={3} py={py} px={4} textAlign='center'>
      {isLoading ? <Spinner size='md' color='blue.400' /> : null}
      {title ? (
        <Text color='inherit' fontSize='sm' fontWeight='semibold'>
          {title}
        </Text>
      ) : null}
      {description ? (
        <Text color={muted} fontSize='sm' maxW='520px'>
          {description}
        </Text>
      ) : null}
      {action ? <Box pt={1}>{action}</Box> : null}
    </VStack>
  );
}

export function DashboardErrorAlert({ children }) {
  return (
    <Alert status='error' borderRadius='md' variant='left-accent'>
      <AlertIcon />
      <AlertDescription>{children}</AlertDescription>
    </Alert>
  );
}
