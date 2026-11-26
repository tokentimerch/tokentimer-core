import { Text, Tooltip, Wrap, WrapItem } from '@chakra-ui/react';
import CertOpsBadge from './CertOpsBadge.jsx';
import { keyLocalityPlaces } from './certopsFormat.js';

export const KEY_LOCALITY_HINT =
  'Where the private key is recorded. One certificate can be in several places, such as the local agent, the OS store, and IIS.';

export default function KeyLocalityPlaces({
  keyMode,
  keyReference,
  locations,
  empty = null,
}) {
  const places = keyLocalityPlaces({ keyMode, keyReference, locations });
  if (places.length === 0) {
    return empty ? (
      <Text fontSize='sm' color='dashboard.modal.muted'>
        {empty}
      </Text>
    ) : null;
  }

  return (
    <Tooltip
      label={KEY_LOCALITY_HINT}
      hasArrow
      placement='top'
      openDelay={250}
      shouldWrapChildren
    >
      <Wrap spacing={1}>
        {places.map(place => (
          <WrapItem key={place}>
            <CertOpsBadge colorScheme='gray'>{place}</CertOpsBadge>
          </WrapItem>
        ))}
      </Wrap>
    </Tooltip>
  );
}
