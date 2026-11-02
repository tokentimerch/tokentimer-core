import { Alert, AlertDescription, AlertIcon } from '@chakra-ui/react';

/** Warning for a CertOps worker signal. A note, not an alert, so it does not interrupt. */
export default function WorkerWarning({ children, testId }) {
  return (
    <Alert
      status='warning'
      role='note'
      borderRadius='md'
      variant='left-accent'
      data-testid={testId}
    >
      <AlertIcon />
      <AlertDescription fontSize='sm'>{children}</AlertDescription>
    </Alert>
  );
}
