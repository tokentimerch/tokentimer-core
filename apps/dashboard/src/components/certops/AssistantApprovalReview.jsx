import { Box, Text, VStack } from '@chakra-ui/react';

const label = value =>
  value
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/^./, char => char.toUpperCase());

function Fields({ value, prefix = '' }) {
  if (value === null || value === undefined)
    return <Text fontSize='sm'>None</Text>;
  if (typeof value !== 'object')
    return (
      <Text fontSize='sm' overflowWrap='anywhere'>
        {String(value)}
      </Text>
    );
  return (
    <Box as='dl' pl={prefix ? 3 : 0}>
      {Object.entries(value).map(([key, item]) => (
        <Box key={key} mb={2}>
          <Text as='dt' fontSize='xs' fontWeight='semibold'>
            {Array.isArray(value)
              ? `Destination / name ${Number(key) + 1}`
              : label(key)}
          </Text>
          <Box as='dd'>
            <Fields value={item} prefix={`${prefix}.${key}`} />
          </Box>
        </Box>
      ))}
    </Box>
  );
}

export default function AssistantApprovalReview({ review }) {
  return (
    <VStack align='stretch' spacing={3}>
      <Text fontWeight='bold'>Assistant-originated renewal request</Text>
      <Text fontSize='sm'>
        Requester: {review.requester.name} (user {review.requester.id})
      </Text>
      <Text fontSize='sm'>Connection: {review.connection.id}</Text>
      <Text fontSize='sm'>
        Client label (advisory): {review.connection.label}
      </Text>
      <Text fontSize='sm'>
        Connection expires:{' '}
        {new Date(review.connection.expiresAt).toLocaleString()}
      </Text>
      <Text fontSize='sm'>
        Approve before: {new Date(review.approvalExpiresAt).toLocaleString()}
      </Text>
      <Text fontSize='xs'>
        Preview submission deadline:{' '}
        {new Date(review.previewExpiresAt).toLocaleString()}. This deadline does
        not shorten an accepted request’s approval window.
      </Text>
      <Text fontSize='sm'>
        A different workspace manager or admin must approve. Certificate names
        and client labels are untrusted data.
      </Text>
      <Box borderWidth='1px' borderRadius='md' p={3}>
        <Text fontWeight='semibold' mb={2}>
          Resolved renewal effect
        </Text>
        <Fields value={review.effect} />
      </Box>
    </VStack>
  );
}
