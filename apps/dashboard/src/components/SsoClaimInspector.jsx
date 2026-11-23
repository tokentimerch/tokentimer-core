import { useMemo, useState } from 'react';
import {
  Box,
  Button,
  FormControl,
  FormLabel,
  Textarea,
  VStack,
  Text,
  Code,
  Alert,
  AlertIcon,
  AlertDescription,
} from '@chakra-ui/react';
import { inspectClaims } from '../lib/sso-claim-inspector.js';

/**
 * Local-only claim inspector. Parsed JSON never leaves the browser.
 */
export default function SsoClaimInspector({ provider }) {
  const [raw, setRaw] = useState('');
  const [parseError, setParseError] = useState('');

  const inspection = useMemo(() => {
    if (!raw.trim()) return null;
    try {
      const payload = JSON.parse(raw);
      setParseError('');
      return inspectClaims(
        provider?.type || 'oidc',
        provider?.claim_mapping || {},
        payload
      );
    } catch (e) {
      setParseError(e.message || 'Invalid JSON');
      return null;
    }
  }, [raw, provider]);

  return (
    <Box borderWidth='1px' borderRadius='md' p={4}>
      <Text fontWeight='semibold' mb={2}>
        Claim inspector
      </Text>
      <Text fontSize='sm' color='gray.500' mb={3}>
        Paste sanitised OIDC ID token / UserInfo JSON or a normalised SAML
        profile. Processed locally only.
      </Text>
      <VStack align='stretch' spacing={3}>
        <FormControl>
          <FormLabel fontSize='sm'>Sample claims JSON</FormLabel>
          <Textarea
            size='sm'
            fontFamily='mono'
            rows={8}
            value={raw}
            onChange={e => setRaw(e.target.value)}
            placeholder='{"sub":"abc","email":"user@example.com","groups":["devops"]}'
          />
        </FormControl>
        {parseError && (
          <Alert status='error' fontSize='sm'>
            <AlertIcon />
            <AlertDescription>{parseError}</AlertDescription>
          </Alert>
        )}
        {inspection && (
          <Box fontSize='sm'>
            <Text>
              <strong>Subject:</strong>{' '}
              <Code>{inspection.subject || '(empty)'}</Code>
            </Text>
            <Text mt={1}>
              <strong>Email:</strong>{' '}
              <Code>{inspection.email || '(empty)'}</Code>
            </Text>
            <Text mt={1}>
              <strong>Display name:</strong>{' '}
              <Code>{inspection.displayName || '(empty)'}</Code>
            </Text>
            {inspection.givenName != null || inspection.surname != null ? (
              <Text mt={1}>
                <strong>Given / surname (SAML):</strong>{' '}
                <Code>
                  {[inspection.givenName, inspection.surname]
                    .filter(Boolean)
                    .join(' ') || '(empty)'}
                </Code>
              </Text>
            ) : null}
            <Text mt={1}>
              <strong>Groups:</strong>{' '}
              <Code>
                {inspection.groups?.length
                  ? inspection.groups.join(', ')
                  : '(none)'}
              </Code>
            </Text>
          </Box>
        )}
        <Button
          size='xs'
          variant='ghost'
          onClick={() => {
            setRaw('');
            setParseError('');
          }}
        >
          Clear
        </Button>
      </VStack>
    </Box>
  );
}
