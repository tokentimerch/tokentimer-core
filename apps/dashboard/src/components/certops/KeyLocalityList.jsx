import { HStack, Text, VStack, Wrap, WrapItem } from '@chakra-ui/react';
import { useDashboardTheme } from '../../hooks/useDashboardTheme';
import KeyLocalityBadge from './KeyLocalityBadge.jsx';
import { parseStoredKeyReference } from './certopsFormat';

/**
 * Renders one or more key-locality badges from the stored keyMode/keyReference
 * pair. Multiple locations are encoded as newline-separated labels in
 * keyReference (optional shared technical ref after " — ").
 */
export default function KeyLocalityList({ keyMode, keyReference }) {
  const { muted } = useDashboardTheme();
  const { locations, technicalReference } =
    parseStoredKeyReference(keyReference);

  if (locations.length === 0) {
    return <KeyLocalityBadge keyMode={keyMode} keyReference={keyReference} />;
  }

  return (
    <VStack align='stretch' spacing={2}>
      <Wrap spacing={2}>
        {locations.map(label => (
          <WrapItem key={label}>
            <KeyLocalityBadge
              keyMode={keyMode || 'external-unknown'}
              keyReference={label}
            />
          </WrapItem>
        ))}
      </Wrap>
      {technicalReference ? (
        <HStack spacing={2} align='start' fontSize='xs' color={muted}>
          <Text fontWeight='semibold' flexShrink={0}>
            Shared reference
          </Text>
          <Text wordBreak='break-word'>{technicalReference}</Text>
        </HStack>
      ) : null}
    </VStack>
  );
}
