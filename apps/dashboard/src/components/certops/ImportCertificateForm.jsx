import { forwardRef, useImperativeHandle, useState } from 'react';
import {
  Alert,
  AlertDescription,
  AlertIcon,
  FormControl,
  FormHelperText,
  FormLabel,
  Select,
  Textarea,
  VStack,
} from '@chakra-ui/react';
import { importCertificateMaterial } from './certopsApi';
import {
  buildKeyReferenceFromLocations,
  KEY_MODE_CUSTOM,
  KEY_MODE_SELECT_OPTIONS,
  KEY_REFERENCE_MAX_LENGTH,
  parseKeyLocationInput,
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
  const [keyLocations, setKeyLocations] = useState('');
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
      containsPrivateKeyMaterial(keyLocations)
    ) {
      setScanError(PRIVATE_KEY_REFUSAL_MESSAGE);
      return false;
    }
    setScanError('');

    const locationLabels = parseKeyLocationInput(keyLocations);
    const technicalReference = keyReference.trim();
    let resolvedKeyMode = null;
    let resolvedKeyReference = null;

    if (keyModeSelection === KEY_MODE_CUSTOM) {
      if (locationLabels.length === 0) {
        setScanError(
          'Enter at least one location, or choose another key locality option.'
        );
        return false;
      }
      resolvedKeyMode = 'external-unknown';
      resolvedKeyReference = buildKeyReferenceFromLocations(
        locationLabels,
        technicalReference
      );
    } else if (keyModeSelection) {
      resolvedKeyMode = keyModeSelection;
      if (locationLabels.length > 0) {
        resolvedKeyReference = buildKeyReferenceFromLocations(
          locationLabels,
          technicalReference
        );
      } else {
        resolvedKeyReference = technicalReference || null;
      }
    } else if (locationLabels.length > 0) {
      resolvedKeyMode = 'external-unknown';
      resolvedKeyReference = buildKeyReferenceFromLocations(
        locationLabels,
        technicalReference
      );
    } else if (technicalReference) {
      resolvedKeyReference = technicalReference;
    }

    if (
      resolvedKeyReference &&
      resolvedKeyReference.length > KEY_REFERENCE_MAX_LENGTH
    ) {
      setScanError(
        `Key locality details must be ${KEY_REFERENCE_MAX_LENGTH} characters or less. Shorten the location list or reference.`
      );
      return false;
    }

    try {
      const payload = { certificatePem: trimmed };
      if (resolvedKeyMode) payload.keyMode = resolvedKeyMode;
      if (resolvedKeyReference) payload.keyReference = resolvedKeyReference;

      const { result, existingCount, newCount } =
        await importCertificateMaterial(workspaceId, payload);
      onImported?.(result, { existingCount, newCount });
      return true;
    } catch (err) {
      const code = err?.response?.data?.code;
      if (code === 'PRIVATE_KEY_MATERIAL_REJECTED') {
        setScanError(PRIVATE_KEY_REFUSAL_MESSAGE);
      } else if (code === 'CERTOPS_KEY_REFERENCE_INVALID') {
        setScanError(
          'Key reference or locations were rejected. Use non-secret labels only.'
        );
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
    keyLocations,
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
        <FormLabel>Key locality (optional)</FormLabel>
        <Select
          value={keyModeSelection}
          onChange={event => {
            setKeyModeSelection(event.target.value);
            if (scanError) setScanError('');
          }}
        >
          {KEY_MODE_SELECT_OPTIONS.map(option => (
            <option key={option.value || 'none'} value={option.value}>
              {option.label}
            </option>
          ))}
        </Select>
        <FormHelperText mb={3}>
          How the private key is custodied (same mode for all locations below).
        </FormHelperText>

        <FormLabel fontSize='sm' mt={2}>
          Locations
        </FormLabel>
        <Textarea
          value={keyLocations}
          onChange={event => {
            setKeyLocations(event.target.value);
            if (scanError) setScanError('');
          }}
          placeholder={
            'One location per line (commas also work)\ne.g. Edge LB Frankfurt\nEdge LB Zurich\nCDN PoP Paris'
          }
          rows={4}
          spellCheck={true}
        />
        <FormHelperText>
          For wildcard or shared certificates used in several places. Optional
          unless you chose Custom.
        </FormHelperText>

        <FormLabel fontSize='sm' mt={3}>
          Shared key reference (optional)
        </FormLabel>
        <Textarea
          value={keyReference}
          onChange={event => {
            setKeyReference(event.target.value);
            if (scanError) setScanError('');
          }}
          placeholder='e.g. agent-id:/etc/ssl/private/wildcard.key or pkcs11 URI'
          rows={2}
          fontFamily='mono'
          fontSize='sm'
          spellCheck={false}
        />
        <FormHelperText>
          One non-secret pointer when the same key backs every location above.
          Combined length is limited to {KEY_REFERENCE_MAX_LENGTH} characters.
        </FormHelperText>
      </FormControl>
    </VStack>
  );
});

export default ImportCertificateForm;
