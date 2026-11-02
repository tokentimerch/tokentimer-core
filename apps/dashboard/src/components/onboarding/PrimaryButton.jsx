import { forwardRef } from 'react';
import { DashboardActionButton } from '../DashboardPrimitives';

/**
 * The wizard's call-to-action button. The theme's solid blue (blue.500) gives
 * white text a contrast of 3.7:1, below the 4.5:1 that WCAG AA asks for at this
 * size. blue.600 is already part of the product palette and gives 5.2:1, so the
 * wizard uses it locally and the shared theme stays untouched.
 */
const PrimaryButton = forwardRef(function PrimaryButton(
  { colorScheme: _ignored, children, ...props },
  ref
) {
  return (
    <DashboardActionButton
      ref={ref}
      colorScheme='blue'
      bg='blue.600'
      _hover={{ bg: 'blue.700', _disabled: { bg: 'blue.600' } }}
      _active={{ bg: 'blue.800' }}
      {...props}
    >
      {children}
    </DashboardActionButton>
  );
});

export default PrimaryButton;
