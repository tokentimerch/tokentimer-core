import {
  Alert,
  AlertDescription,
  AlertIcon,
  Badge,
  Box,
  Button,
  Divider,
  HStack,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Stack,
  Text,
} from '@chakra-ui/react';
import { useDashboardTheme } from '../../hooks/useDashboardTheme.js';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from '../DashboardModalFrame.jsx';
import { INFO_NOTE_PROPS } from '../LearnMorePanel.jsx';

const dateLabel = value =>
  value ? new Date(value).toLocaleString() : 'Not used yet';

export default function AssistantConnectionsModal({
  isOpen,
  onClose,
  data,
  busy,
  error,
  notice,
  isAdmin,
  onRefresh,
  onRevoke,
}) {
  const modal = useDashboardModalProps();
  const { muted } = useDashboardTheme();
  const pending =
    data?.enrollments.filter(item => item.status === 'pending') || [];
  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      closeOnOverlayClick={false}
      scrollBehavior='inside'
      size='2xl'
    >
      <ModalOverlay />
      <DashboardModalFrame
        maxW='2xl'
        my={0}
        minH={0}
        maxH={{ base: 'calc(100dvh - 32px)', md: 'calc(100dvh - 64px)' }}
      >
        <ModalHeader>
          <DashboardModalTitle>Manage MCP connections</DashboardModalTitle>
          <DashboardModalDescription>
            {data?.frozenWorkspaceName
              ? `Review and revoke access to ${data.frozenWorkspaceName}.`
              : 'Review access in this workspace and revoke connections you no longer use.'}
          </DashboardModalDescription>
        </ModalHeader>
        <ModalCloseButton
          aria-label='Close connection manager'
          isDisabled={busy}
        />
        <ModalBody>
          <Stack spacing={4}>
            {error ? (
              <Alert status='warning' borderRadius='md'>
                <AlertIcon />
                <AlertDescription fontSize='sm'>{error}</AlertDescription>
              </Alert>
            ) : null}
            {notice ? (
              <Alert {...INFO_NOTE_PROPS}>
                <AlertIcon />
                <AlertDescription fontSize='sm'>{notice}</AlertDescription>
              </Alert>
            ) : null}
            {data ? (
              <>
                <Text fontWeight='semibold' fontSize='sm'>
                  {data.frozenWorkspaceName
                    ? 'Connections in this workspace'
                    : isAdmin
                      ? 'Workspace connections'
                      : 'Your connections'}
                </Text>
                <Stack spacing={3} divider={<Divider />}>
                  {!data.connections.length ? (
                    <Text fontSize='sm' color={muted}>
                      {data.frozenWorkspaceName
                        ? 'No connections to manage.'
                        : 'No connections yet. Use Connect an MCP assistant to get started.'}
                    </Text>
                  ) : null}
                  {data.connections.map(item => (
                    <HStack
                      key={item.id}
                      justify='space-between'
                      align='start'
                      flexWrap='wrap'
                      spacing={3}
                    >
                      <Box minW={0} flex='1'>
                        <HStack flexWrap='wrap' spacing={2}>
                          <Text
                            fontSize='sm'
                            fontWeight='semibold'
                            overflowWrap='anywhere'
                          >
                            {item.name}
                          </Text>
                          <Badge
                            colorScheme={
                              item.status === 'active' ? 'green' : 'gray'
                            }
                          >
                            {item.status}
                          </Badge>
                        </HStack>
                        <Text fontSize='xs' color={muted}>
                          {item.scopes.includes('mcp:renew:request') ||
                          item.scopes.includes('mcp:inventory:import') ||
                          item.scopes.includes('mcp:inventory:update') ||
                          item.scopes.includes('mcp:contacts:create') ||
                          item.scopes.includes('mcp:webhooks:create') ||
                          item.scopes.includes('mcp:groups:create') ||
                          item.scopes.includes('mcp:members:invite') ||
                          item.scopes.includes('mcp:issue:request')
                            ? [
                                'Read',
                                item.scopes.includes('mcp:inventory:import') &&
                                  'inventory import',
                                item.scopes.includes('mcp:inventory:update') &&
                                  'inventory updates',
                                item.scopes.includes('mcp:contacts:create') &&
                                  'contact creation',
                                item.scopes.includes('mcp:webhooks:create') &&
                                  'webhook creation',
                                item.scopes.includes('mcp:groups:create') &&
                                  'contact group creation',
                                item.scopes.includes('mcp:members:invite') &&
                                  'viewer invitations',
                                item.scopes.includes('mcp:issue:request') &&
                                  'issuance requests',
                                item.scopes.includes('mcp:renew:request') &&
                                  'renewal requests',
                              ]
                                .filter(Boolean)
                                .join(' + ')
                            : 'Read only'}{' '}
                          ·{' '}
                          {item.expiresAt
                            ? `expires ${dateLabel(item.expiresAt)}`
                            : 'No expiry'}
                        </Text>
                        <Text fontSize='xs' color={muted}>
                          Last used: {dateLabel(item.lastUsedAt)}
                        </Text>
                      </Box>
                      {item.status === 'active' ? (
                        <Button
                          size='sm'
                          variant='outline'
                          colorScheme='red'
                          isDisabled={busy}
                          onClick={() => onRevoke('connections', item.id)}
                        >
                          Revoke connection
                        </Button>
                      ) : null}
                    </HStack>
                  ))}
                </Stack>
                {pending.length ? (
                  <>
                    <Text fontWeight='semibold' fontSize='sm'>
                      Pending local setups
                    </Text>
                    <Stack spacing={3} divider={<Divider />}>
                      {pending.map(item => (
                        <HStack
                          key={item.id}
                          justify='space-between'
                          align='start'
                          flexWrap='wrap'
                          spacing={3}
                        >
                          <Box minW={0} flex='1'>
                            <Text fontSize='sm' overflowWrap='anywhere'>
                              {item.name}
                            </Text>
                            <Text fontSize='xs' color={muted}>
                              Code expires {dateLabel(item.expiresAt)}. Revoke
                              an unused code before starting again.
                            </Text>
                          </Box>
                          <Button
                            size='sm'
                            variant='outline'
                            isDisabled={busy}
                            onClick={() => onRevoke('enrollments', item.id)}
                          >
                            Revoke setup code
                          </Button>
                        </HStack>
                      ))}
                    </Stack>
                  </>
                ) : null}
                <Alert {...INFO_NOTE_PROPS}>
                  <AlertIcon />
                  <AlertDescription fontSize='sm'>
                    Revocation blocks new calls and unclaimed work. Work already
                    held by an agent may continue.
                  </AlertDescription>
                </Alert>
              </>
            ) : null}
          </Stack>
        </ModalBody>
        <ModalFooter {...modal.footerProps}>
          <Button
            {...modal.outlineButtonProps}
            onClick={onRefresh}
            isLoading={busy}
          >
            Refresh connections
          </Button>
          <Button
            {...modal.primaryButtonProps}
            onClick={onClose}
            isDisabled={busy}
          >
            Done
          </Button>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}
