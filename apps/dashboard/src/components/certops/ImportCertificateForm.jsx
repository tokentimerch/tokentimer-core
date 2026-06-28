import { forwardRef, useImperativeHandle, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  FormControl,
  FormHelperText,
  FormLabel,
  Input,
  Select,
  Textarea,
  VStack,
} from '@chakra-ui/react';
import { importCertificateMaterial } from './certopsApi';
import {
  KEY_MODE_CUSTOM,
  KEY_MODE_SELECT_OPTIONS,
} from './certopsFormat';
import {
  containsPrivateKeyMaterial,
  PRIVATE_KEY_REFUSAL_MESSAGE,
} from './privateKeyScan';

const ImportCertificateForm = forwardRef(function ImportCertificateForm(
  { workspaceId, onImported },
  ref
) {
  const [pem, setPem] = useState('');
  const [keyModeSelection, setKeyModeSelection] = useState('');
  const [customKeyLocation, setCustomKeyLocation] = useState('');
  const [keyReference, setKeyReference] = useState('');
  const [scanError, setScanError] = useState('');
  const [serverError, setServerError] = useState('');

  const handlePemChange = event => {
    setPem(event.target.value);
    if (scanError) setScanError('');
    if (serverError) setServerError('');
  };

  const submit = async () => {
    setServerError('');

    const trimmed = pem.trim();
    if (!trimmed) {
      setScanError('Paste the public certificate (PEM) to import.');
      return false;
    }

    if (
      containsPrivateKeyMaterial(trimmed) ||
      containsPrivateKeyMaterial(keyReference) ||
      containsPrivateKeyMaterial(customKeyLocation)
    ) {
      setScanError(PRIVATE_KEY_REFUSAL_MESSAGE);
      return false;
    }
    setScanError('');

    const customLocation = customKeyLocation.trim();
    const technicalReference = keyReference.trim();
    let resolvedKeyMode = null;
    let resolvedKeyReference = null;

    if (keyModeSelection === KEY_MODE_CUSTOM) {
      if (!customLocation) {
        setScanError(
          'Describe where the private key lives, or choose another option.'
        );
        return false;
      }
      resolvedKeyMode = 'external-unknown';
      resolvedKeyReference = technicalReference
        ? `${customLocation} — ${technicalReference}`
        : customLocation;
    } else if (keyModeSelection) {
      resolvedKeyMode = keyModeSelection;
      resolvedKeyReference = technicalReference || null;
    } else if (technicalReference) {
      resolvedKeyReference = technicalReference;
    }

    try {
      const payload = { certificatePem: trimmed };
      if (resolvedKeyMode) payload.keyMode = resolvedKeyMode;
      if (resolvedKeyReference) payload.keyReference = resolvedKeyReference;

      const { result, existingCount, newCount } = await importCertificateMaterial(
        workspaceId,
        payload
      );
      onImported?.(result, { existingCount, newCount });
      return true;
    } catch (err) {
      const code = err?.response?.data?.code;
      if (code === 'PRIVATE_KEY_MATERIAL_REJECTED') {
        setScanError(PRIVATE_KEY_REFUSAL_MESSAGE);
      } else {
        setServerError(
          err?.response?.data?.error ||
            'Import failed. Check the certificate and try again.'
        );
      }
      return false;
    }
  };

  useImperativeHandle(ref, () => ({ submit }), [
    pem,
    keyModeSelection,
    customKeyLocation,
    keyReference,
    workspaceId,
    onImported,
  ]);

  return (
    <VStack align='stretch' spacing={4}>
      {scanError ? (
        <Alert status='warning' borderRadius='md' variant='left-accent'>
          <AlertIcon />
          <AlertDescription>{scanError}</AlertDescription>
        </Alert>
      ) : null}
      {serverError ? (
        <Alert status='error' borderRadius='md' variant='left-accent'>
          <AlertIcon />
          <AlertDescription>{serverError}</AlertDescription>
        </Alert>
      ) : null}

      <FormControl isRequired>
        <FormLabel>Public certificate (PEM)</FormLabel>
        <Textarea
          value={pem}
          onChange={handlePemChange}
          placeholder={
            '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----'
          }
          fontFamily='mono'
          fontSize='sm'
          rows={10}
          spellCheck={false}
        />
        <FormHelperText>
          Paste the certificate and any chain certificates. Public material
          only. Never paste a private key; TokenTimer does not store keys.
        </FormHelperText>
      </FormControl>

      <FormControl>
        <FormLabel>Where does the private key live? (optional)</FormLabel>
        <Select
          value={keyModeSelection}
          onChange={event => {
            setKeyModeSelection(event.target.value);
            if (event.target.value !== KEY_MODE_CUSTOM) {
              setCustomKeyLocation('');
            }
            if (scanError) setScanError('');
          }}
        >
          {KEY_MODE_SELECT_OPTIONS.map(option => (
            <option key={option.value || 'none'} value={option.value}>
              {option.label}
            </option>
          ))}
        </Select>
        {keyModeSelection === KEY_MODE_CUSTOM ? (
          <Input
            mt={3}
            value={customKeyLocation}
            onChange={event => {
              setCustomKeyLocation(event.target.value);
              if (scanError) setScanError('');
            }}
            placeholder='e.g. Manual upload on F5, team password manager entry'
            maxLength={256}
          />
        ) : null}
        <FormHelperText>
          Records where the key is believed to live. Choose Custom to enter your
          own description. TokenTimer never receives or stores the key itself.
        </FormHelperText>
      </FormControl>

      <FormControl>
        <FormLabel>Key reference (optional)</FormLabel>
        <Input
          value={keyReference}
          onChange={event => setKeyReference(event.target.value)}
          placeholder='e.g. agent-id:/etc/ssl/private/site.key or pkcs11 URI'
        />
        <FormHelperText>
          A non-secret pointer to where the key lives. Do not paste secrets.
        </FormHelperText>
      </FormControl>
    </VStack>
  );
});

export default ImportCertificateForm;
