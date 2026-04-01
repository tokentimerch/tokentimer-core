import { useEffect, useRef } from 'react';
import { Box, VisuallyHidden } from '@chakra-ui/react';

/**
 * Focus trap for modals and dialogs
 * Ensures keyboard navigation stays within the modal
 */
export const FocusTrap = ({ children, isActive = true }) => {
  const containerRef = useRef();
  const firstFocusableRef = useRef();
  const lastFocusableRef = useRef();

  useEffect(() => {
    if (!isActive) return;

    const container = containerRef.current;
    if (!container) return;

    // Find all focusable elements
    const focusableElements = container.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );

    if (focusableElements.length === 0) return;

    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];

    firstFocusableRef.current = firstElement;
    lastFocusableRef.current = lastElement;

    // Focus the first element
    firstElement.focus();

    const handleKeyDown = event => {
      if (event.key === 'Tab') {
        if (event.shiftKey) {
          // Shift + Tab
          if (document.activeElement === firstElement) {
            event.preventDefault();
            lastElement.focus();
          }
        } else {
          // Tab
          if (document.activeElement === lastElement) {
            event.preventDefault();
            firstElement.focus();
          }
        }
      }
    };

    container.addEventListener('keydown', handleKeyDown);
    return () => container.removeEventListener('keydown', handleKeyDown);
  }, [isActive]);

  return (
    <Box ref={containerRef} tabIndex='-1'>
      {children}
    </Box>
  );
};

/**
 * ARIA Live Region for dynamic content updates
 * Announces changes to screen readers
 */
export const LiveRegion = ({
  children,
  role = 'status',
  'aria-live': ariaLive = 'polite',
  'aria-atomic': ariaAtomic = 'true',
}) => {
  return (
    <Box
      role={role}
      aria-live={ariaLive}
      aria-atomic={ariaAtomic}
      position='absolute'
      left='-10000px'
      width='1px'
      height='1px'
      overflow='hidden'
    >
      {children}
    </Box>
  );
};

/**
 * Visually hidden but accessible to screen readers
 */
export const ScreenReaderOnly = ({ children }) => {
  return <VisuallyHidden>{children}</VisuallyHidden>;
};

/**
 * Enhanced button with proper ARIA attributes
 */
export const AccessibleButton = ({
  children,
  onClick,
  disabled = false,
  'aria-label': ariaLabel,
  'aria-describedby': ariaDescribedby,
  leftIcon,
  ...props
}) => {
  return (
    <Box
      as='button'
      onClick={onClick}
      disabled={disabled}
      aria-label={ariaLabel}
      aria-describedby={ariaDescribedby}
      role='button'
      tabIndex={disabled ? -1 : 0}
      display='inline-flex'
      alignItems='center'
      justifyContent='center'
      _focus={{
        outline: '2px solid',
        outlineColor: 'primary.300',
        outlineOffset: '2px',
      }}
      _disabled={{
        opacity: 0.6,
        cursor: 'not-allowed',
      }}
      {...props}
    >
      {leftIcon && (
        <Box
          as='span'
          mr={children ? 2 : 0}
          display='inline-flex'
          alignItems='center'
        >
          {leftIcon}
        </Box>
      )}
      {children}
    </Box>
  );
};

/**
 * Enhanced form field with proper labeling
 */
export const AccessibleFormField = ({
  label,
  id,
  error,
  required = false,
  children,
  ...props
}) => {
  const fieldId = id || `field-${Math.random().toString(36).substr(2, 9)}`;
  const errorId = `${fieldId}-error`;
  return (
    <Box {...props}>
      <Box
        as='label'
        htmlFor={fieldId}
        display='block'
        fontWeight='medium'
        mb='2'
        color='text.primary'
      >
        {label}
        {required && (
          <Box as='span' color='error.500' ml='1'>
            *
          </Box>
        )}
      </Box>

      <Box position='relative'>
        {React.cloneElement(children, {
          id: fieldId,
          'aria-invalid': error ? 'true' : 'false',
          'aria-describedby': error ? errorId : undefined,
          'aria-required': required,
        })}
      </Box>

      {error && (
        <Box
          id={errorId}
          role='alert'
          color='error.500'
          fontSize='sm'
          mt='1'
          aria-live='polite'
        >
          {error}
        </Box>
      )}
    </Box>
  );
};

/**
 * Loading spinner with proper ARIA attributes
 */
export const AccessibleSpinner = ({
  size = 'md',
  'aria-label': ariaLabel = 'Loading...',
  ...props
}) => {
  return (
    <Box
      role='status'
      aria-label={ariaLabel}
      aria-live='polite'
      display='inline-flex'
      alignItems='center'
      justifyContent='center'
      {...props}
    >
      <Box
        as='div'
        width={size === 'sm' ? '16px' : size === 'lg' ? '32px' : '24px'}
        height={size === 'sm' ? '16px' : size === 'lg' ? '32px' : '24px'}
        border='2px solid'
        borderColor='border.primary'
        borderTopColor='primary.500'
        borderRadius='full'
        animation='spin 1s linear infinite'
        sx={{
          '@keyframes spin': {
            '0%': { transform: 'rotate(0deg)' },
            '100%': { transform: 'rotate(360deg)' },
          },
        }}
      />
      <ScreenReaderOnly>{ariaLabel}</ScreenReaderOnly>
    </Box>
  );
};

/**
 * Progress indicator with ARIA attributes
 */
export const AccessibleProgress = ({
  value,
  max = 100,
  'aria-label': ariaLabel = 'Progress',
  ...props
}) => {
  const percentage = Math.round((value / max) * 100);

  return (
    <Box
      role='progressbar'
      aria-valuenow={value}
      aria-valuemin='0'
      aria-valuemax={max}
      aria-label={ariaLabel}
      {...props}
    >
      <Box
        bg='background.secondary'
        borderRadius='full'
        height='8px'
        overflow='hidden'
      >
        <Box
          bg='primary.500'
          height='100%'
          width={`${percentage}%`}
          transition='width 0.3s ease'
          borderRadius='full'
        />
      </Box>
      <ScreenReaderOnly>{percentage}% complete</ScreenReaderOnly>
    </Box>
  );
};

/**
 * Utility to check if element is focusable
 */
export const isFocusable = element => {
  if (!element) return false;

  const tagName = element.tagName.toLowerCase();
  const tabIndex = element.getAttribute('tabindex');
  const disabled = element.hasAttribute('disabled');
  const hidden = element.hasAttribute('hidden');

  // Elements that are naturally focusable
  const naturallyFocusable = [
    'button',
    'input',
    'select',
    'textarea',
    'a',
    'area',
    'object',
    'embed',
  ];

  if (naturallyFocusable.includes(tagName) && !disabled && !hidden) {
    return true;
  }

  // Elements with tabindex >= 0
  if (tabIndex !== null && parseInt(tabIndex) >= 0) {
    return true;
  }

  return false;
};

/**
 * Utility to get all focusable elements within a container
 */
export const getFocusableElements = container => {
  if (!container) return [];

  const focusableSelectors = [
    'button:not([disabled])',
    'input:not([disabled])',
    'select:not([disabled])',
    'textarea:not([disabled])',
    'a[href]',
    'area[href]',
    'object',
    'embed',
    '[tabindex]:not([tabindex="-1"])',
  ];

  return Array.from(container.querySelectorAll(focusableSelectors.join(', ')));
};

export default {
  FocusTrap,
  LiveRegion,
  ScreenReaderOnly,
  AccessibleButton,
  AccessibleFormField,
  AccessibleSpinner,
  AccessibleProgress,
  isFocusable,
  getFocusableElements,
};
