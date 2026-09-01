import {
  Alert,
  AlertDescription,
  AlertIcon,
  Badge,
  Box,
  Button,
  Flex,
  FormControl,
  FormErrorMessage,
  HStack,
  Input,
  Modal,
  ModalBody,
  ModalCloseButton,
  ModalFooter,
  ModalHeader,
  ModalOverlay,
  Text,
  VStack,
} from '@chakra-ui/react';
import { TOKEN_CATEGORIES } from '../constants/tokenCategories.js';
import { formatDate } from '../utils/apiClient';
import { useDashboardTheme } from '../hooks/useDashboardTheme.js';
import {
  DashboardModalDescription,
  DashboardModalFrame,
  DashboardModalTitle,
  useDashboardModalProps,
} from './DashboardModalFrame.jsx';
import {
  DashboardModalDetailRow,
  DashboardModalDetailsGrid,
  DashboardModalSectionHeading,
} from './DashboardModalDetails.jsx';

function getTokenDisplayMeta(token) {
  const category = TOKEN_CATEGORIES.find(cat => cat.value === token?.category);
  const type = category?.types?.find(item => item.value === token?.type);

  return {
    categoryLabel: category?.label || token?.category || 'Asset',
    typeLabel: type?.label || token?.type || 'Unknown type',
    colorScheme: category?.color || 'gray',
  };
}

function ActionModalHeader({ title, description, badge, colorScheme }) {
  return (
    <Flex align='flex-start' justify='space-between' gap={4} pr={8}>
      <Box minW={0}>
        <DashboardModalTitle>{title}</DashboardModalTitle>
        <DashboardModalDescription>{description}</DashboardModalDescription>
      </Box>
      <Badge
        colorScheme={colorScheme}
        variant='subtle'
        fontSize='2xs'
        letterSpacing='0.08em'
        px={2.5}
        py={1.5}
        flexShrink={0}
      >
        {badge}
      </Badge>
    </Flex>
  );
}

export function TokenDeletionModal({
  isOpen,
  onClose,
  tokenToDelete,
  onConfirm,
}) {
  const {
    overlayProps,
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    outlineButtonProps,
    dangerButtonProps,
    tokens,
  } = useDashboardModalProps();
  const { dashboard } = useDashboardTheme();
  const { categoryLabel, typeLabel } = getTokenDisplayMeta(tokenToDelete);

  return (
    <Modal isOpen={isOpen} onClose={onClose} isCentered scrollBehavior='inside'>
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame
        maxW={{ base: 'calc(100vw - 24px)', md: '640px' }}
        maxH={{ base: 'calc(100dvh - 24px)', md: 'calc(100dvh - 64px)' }}
      >
        <ModalHeader {...headerProps} py={{ base: 4, md: 4 }}>
          <ActionModalHeader
            title='Delete Token'
            description={
              tokenToDelete
                ? `${tokenToDelete.name} · ${categoryLabel} · ${typeLabel}`
                : 'Review this asset before permanently deleting it.'
            }
            badge='DELETE'
            colorScheme='red'
          />
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} />
        <ModalBody {...bodyProps} py={{ base: 4, md: 4 }}>
          <VStack spacing={4} align='stretch'>
            <Alert
              status='warning'
              bg={dashboard.callout.warningSurface}
              border='1px solid'
              borderColor={dashboard.callout.warningBorder}
              color={dashboard.callout.warningText}
              borderRadius='8px'
              px={3}
              py={2.5}
              fontSize='sm'
            >
              <AlertIcon boxSize={4} />
              <AlertDescription>
                This action cannot be undone. The token will be permanently
                deleted.
              </AlertDescription>
            </Alert>

            {tokenToDelete?.monitor_url ? (
              <Alert
                status='error'
                bg={dashboard.callout.dangerSurface}
                border='1px solid'
                borderColor={dashboard.callout.dangerBorder}
                color={dashboard.state.danger}
                borderRadius='8px'
                px={3}
                py={2.5}
                fontSize='sm'
              >
                <AlertIcon boxSize={4} />
                <AlertDescription>
                  This token has a linked endpoint monitor (
                  {tokenToDelete.monitor_url}). Deleting this token will also
                  remove the monitor and stop health checks.
                </AlertDescription>
              </Alert>
            ) : null}

            {tokenToDelete ? (
              <DashboardModalDetailsGrid>
                <DashboardModalSectionHeading
                  tokens={tokens}
                  withDivider={false}
                >
                  Asset summary
                </DashboardModalSectionHeading>
                <DashboardModalDetailRow
                  label='Name'
                  value={tokenToDelete.name}
                  tokens={tokens}
                />
                <DashboardModalDetailRow
                  label='Type'
                  value={typeLabel}
                  tokens={tokens}
                />
                <DashboardModalDetailRow
                  label='Category'
                  value={categoryLabel}
                  tokens={tokens}
                />
                <DashboardModalDetailRow
                  label='Expiration date'
                  value={
                    tokenToDelete.expiresAt
                      ? formatDate(tokenToDelete.expiresAt)
                      : '--'
                  }
                  tokens={tokens}
                />
              </DashboardModalDetailsGrid>
            ) : null}
          </VStack>
        </ModalBody>
        <ModalFooter {...footerProps} py={{ base: 2, md: 3 }}>
          <Flex
            w='100%'
            align={{ base: 'stretch', sm: 'center' }}
            justify='space-between'
            gap={3}
            direction={{ base: 'column', sm: 'row' }}
          >
            <Text fontSize='sm' color={tokens.muted}>
              Deletion is permanent.
            </Text>
            <HStack spacing={3} justify='flex-end'>
              <Button onClick={onClose} minW='96px' {...outlineButtonProps}>
                Cancel
              </Button>
              <Button onClick={onConfirm} minW='120px' {...dangerButtonProps}>
                Delete Token
              </Button>
            </HStack>
          </Flex>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}

export function TokenRenewModal({
  isOpen,
  onClose,
  tokenToRenew,
  renewDate,
  renewErrors,
  isRenewSubmitting,
  onRenewDateChange,
  onConfirm,
}) {
  const {
    overlayProps,
    headerProps,
    bodyProps,
    footerProps,
    closeButtonProps,
    outlineButtonProps,
    primaryButtonProps,
    tokens,
  } = useDashboardModalProps();
  const { categoryLabel, typeLabel, colorScheme } =
    getTokenDisplayMeta(tokenToRenew);

  return (
    <Modal isOpen={isOpen} onClose={onClose} isCentered scrollBehavior='inside'>
      <ModalOverlay {...overlayProps} />
      <DashboardModalFrame
        maxW={{ base: 'calc(100vw - 24px)', md: '640px' }}
        maxH={{ base: 'calc(100dvh - 24px)', md: 'calc(100dvh - 64px)' }}
      >
        <ModalHeader {...headerProps} py={{ base: 4, md: 4 }}>
          <ActionModalHeader
            title='Renew Token'
            description={
              tokenToRenew
                ? `${tokenToRenew.name} · ${categoryLabel} · ${typeLabel}`
                : 'Choose the next expiration date for this asset.'
            }
            badge='RENEW'
            colorScheme={colorScheme}
          />
        </ModalHeader>
        <ModalCloseButton {...closeButtonProps} />
        <ModalBody {...bodyProps} py={{ base: 4, md: 4 }}>
          <DashboardModalDetailsGrid>
            {tokenToRenew ? (
              <>
                <DashboardModalSectionHeading
                  tokens={tokens}
                  withDivider={false}
                >
                  Asset summary
                </DashboardModalSectionHeading>
                <DashboardModalDetailRow
                  label='Name'
                  value={tokenToRenew.name}
                  tokens={tokens}
                />
                <DashboardModalDetailRow
                  label='Type'
                  value={typeLabel}
                  tokens={tokens}
                />
                <DashboardModalDetailRow
                  label='Category'
                  value={categoryLabel}
                  tokens={tokens}
                />
                <DashboardModalDetailRow
                  label='Current expiration'
                  value={
                    tokenToRenew.expiresAt
                      ? formatDate(tokenToRenew.expiresAt)
                      : '--'
                  }
                  tokens={tokens}
                />
              </>
            ) : null}

            <DashboardModalSectionHeading tokens={tokens}>
              Renewal
            </DashboardModalSectionHeading>
            <DashboardModalDetailRow
              label='New expiration date'
              tokens={tokens}
              htmlFor='renewDate'
            >
              <FormControl isInvalid={Boolean(renewErrors.renewDate)}>
                <Input
                  id='renewDate'
                  type='date'
                  value={renewDate}
                  onChange={event => onRenewDateChange(event.target.value)}
                  bg={tokens.inputBg}
                  borderColor={
                    renewErrors.renewDate ? tokens.danger : tokens.inputBorder
                  }
                  borderRadius='8px'
                  color={tokens.text}
                  size='sm'
                  _hover={{ borderColor: tokens.focusBorder }}
                  _focusVisible={{
                    borderColor: tokens.focusBorder,
                    boxShadow: `0 0 0 1px ${tokens.focusBorder}`,
                  }}
                />
                {renewErrors.renewDate ? (
                  <FormErrorMessage color={tokens.danger} fontSize='xs'>
                    {renewErrors.renewDate}
                  </FormErrorMessage>
                ) : null}
                <Text
                  fontSize='xs'
                  color={tokens.muted}
                  lineHeight='1.5'
                  mt={2}
                >
                  Defaulted from the token category and type. Choose any future
                  date.
                </Text>
              </FormControl>
            </DashboardModalDetailRow>
          </DashboardModalDetailsGrid>
        </ModalBody>
        <ModalFooter {...footerProps} py={{ base: 2, md: 3 }}>
          <Flex
            w='100%'
            align={{ base: 'stretch', sm: 'center' }}
            justify='space-between'
            gap={3}
            direction={{ base: 'column', sm: 'row' }}
          >
            <Text fontSize='sm' color={tokens.muted}>
              This updates the asset expiration date.
            </Text>
            <HStack spacing={3} justify='flex-end'>
              <Button onClick={onClose} minW='96px' {...outlineButtonProps}>
                Cancel
              </Button>
              <Button
                {...primaryButtonProps}
                colorScheme='green'
                onClick={onConfirm}
                isLoading={isRenewSubmitting}
                minW='120px'
              >
                Confirm
              </Button>
            </HStack>
          </Flex>
        </ModalFooter>
      </DashboardModalFrame>
    </Modal>
  );
}
