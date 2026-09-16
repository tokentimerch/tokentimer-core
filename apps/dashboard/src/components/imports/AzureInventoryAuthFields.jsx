import {
  Box,
  Button,
  Code,
  HStack,
  Input,
  InputGroup,
  InputRightElement,
  IconButton,
  Radio,
  RadioGroup,
  Stack,
  Text,
  VStack,
} from '@chakra-ui/react';
import { FiEye, FiEyeOff } from 'react-icons/fi';

export default function AzureInventoryAuthFields({
  audienceHint,
  tokenPlaceholder,
  helpTextColor,
  authMethod,
  onAuthMethodChange,
  token,
  onTokenChange,
  tenantId,
  onTenantIdChange,
  clientId,
  onClientIdChange,
  clientSecret,
  onClientSecretChange,
  showSecret,
  onToggleSecret,
  autoSyncManageMode = false,
  replacingCredentials = false,
  onStartReplace,
  onCancelReplace,
}) {
  const showStoredNotice = autoSyncManageMode && !replacingCredentials;
  const showFields = !autoSyncManageMode || replacingCredentials;

  return (
    <VStack align='stretch' spacing={3}>
      {showStoredNotice ? (
        <Box>
          <Text fontSize='sm' color={helpTextColor}>
            Stored credentials are not shown. Replace them to rotate a secret or
            switch between a pasted token and an Entra app.
          </Text>
          <Button mt={2} size='sm' variant='outline' onClick={onStartReplace}>
            Replace credentials
          </Button>
        </Box>
      ) : null}
      {showFields ? (
        <>
          {autoSyncManageMode ? (
            <HStack>
              <Button size='sm' variant='ghost' onClick={onCancelReplace}>
                Cancel replace
              </Button>
            </HStack>
          ) : null}
          <Box>
            <Text fontSize='sm' mb={1}>
              Authentication
            </Text>
            <RadioGroup value={authMethod} onChange={onAuthMethodChange}>
              <Stack direction={{ base: 'column', md: 'row' }} spacing={4}>
                <Radio value='token'>Pasted access token</Radio>
                <Radio value='client_credentials'>
                  Entra app (client credentials)
                </Radio>
              </Stack>
            </RadioGroup>
          </Box>
          {authMethod === 'token' ? (
            <Box minW='320px'>
              <Text fontSize='sm' mb={1}>
                Access token
              </Text>
              <InputGroup>
                <Input
                  type={showSecret ? 'text' : 'password'}
                  placeholder={tokenPlaceholder || 'Paste token'}
                  value={token}
                  onChange={e => onTokenChange(e.target.value)}
                />
                <InputRightElement>
                  <IconButton
                    size='xs'
                    variant='ghost'
                    icon={showSecret ? <FiEyeOff /> : <FiEye />}
                    onClick={onToggleSecret}
                    aria-label={showSecret ? 'Hide' : 'Show'}
                  />
                </InputRightElement>
              </InputGroup>
              {audienceHint ? (
                <Text fontSize='xs' color={helpTextColor} mt={1}>
                  {audienceHint.prefix}{' '}
                  <Code fontSize='xs'>{audienceHint.command}</Code>
                </Text>
              ) : null}
            </Box>
          ) : (
            <HStack spacing={3} align='flex-end' flexWrap='wrap'>
              <Box minW='220px'>
                <Text fontSize='sm' mb={1}>
                  Tenant ID
                </Text>
                <Input
                  placeholder='Tenant ID or domain'
                  value={tenantId}
                  onChange={e => onTenantIdChange(e.target.value)}
                />
              </Box>
              <Box minW='220px'>
                <Text fontSize='sm' mb={1}>
                  Application (client) ID
                </Text>
                <Input
                  placeholder='Client ID'
                  value={clientId}
                  onChange={e => onClientIdChange(e.target.value)}
                />
              </Box>
              <Box minW='220px'>
                <Text fontSize='sm' mb={1}>
                  Client secret
                </Text>
                <InputGroup>
                  <Input
                    type={showSecret ? 'text' : 'password'}
                    placeholder='Client secret'
                    value={clientSecret}
                    onChange={e => onClientSecretChange(e.target.value)}
                  />
                  <InputRightElement>
                    <IconButton
                      size='xs'
                      variant='ghost'
                      icon={showSecret ? <FiEyeOff /> : <FiEye />}
                      onClick={onToggleSecret}
                      aria-label={showSecret ? 'Hide' : 'Show'}
                    />
                  </InputRightElement>
                </InputGroup>
              </Box>
            </HStack>
          )}
        </>
      ) : null}
    </VStack>
  );
}
