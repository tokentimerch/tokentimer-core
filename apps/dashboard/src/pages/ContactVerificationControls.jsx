import { useState } from 'react';
import {
  Badge,
  Box,
  Button,
  Collapse,
  FormControl,
  FormLabel,
  HStack,
  Input,
  Text,
  VStack,
  useClipboard,
} from '@chakra-ui/react';
import {
  channelStatus,
  verificationWaitCopy,
} from './contactVerificationStatus';

const COLORS = {
  pending: 'orange',
  verified: 'green',
  revoked: 'red',
  opted_out: 'red',
};

function ChannelLine({
  label,
  entry,
  actionLabel,
  onAction,
  busy,
  disabled,
  expanded,
}) {
  const expiry = entry.invitation?.expires_at
    ? new Date(entry.invitation.expires_at)
    : null;
  const expiryLabel =
    expiry && !Number.isNaN(expiry.getTime())
      ? `Invitation open until ${expiry.toLocaleString()}`
      : null;
  return (
    <HStack spacing={2} align='center' flexWrap='wrap'>
      <Text fontSize='xs' color='inherit'>
        {label}
      </Text>
      <Badge colorScheme={COLORS[entry.status] || 'orange'} variant='subtle'>
        {entry.label}
      </Badge>
      {expiryLabel ? (
        <Text fontSize='xs' color='inherit'>
          {expiryLabel}
        </Text>
      ) : null}
      {actionLabel ? (
        <Button
          size='xs'
          variant='outline'
          onClick={onAction}
          aria-expanded={expanded}
          isLoading={busy}
          isDisabled={disabled || busy}
        >
          {actionLabel}
        </Button>
      ) : null}
    </HStack>
  );
}

export default function ContactVerificationControls({
  contact,
  sharedInvitation,
  mode,
  isViewer,
  busyKey,
  onInviteEmail,
  onShareWhatsApp,
  onRevoke,
}) {
  const [confirmationOpen, setConfirmationOpen] = useState(false);
  const { hasCopied, onCopy } = useClipboard(sharedInvitation?.url || '');
  const email = channelStatus(contact, 'email');
  const whatsapp = channelStatus(contact, 'whatsapp');
  const sharedExpiry = Date.parse(sharedInvitation?.expiresAt || '');
  const showSharedLink =
    !isViewer &&
    Boolean(sharedInvitation?.url) &&
    whatsapp?.status === 'pending' &&
    sharedExpiry > Date.now() &&
    (!whatsapp.invitation ||
      Date.parse(whatsapp.invitation.expires_at) === sharedExpiry);

  if ((mode !== 'enforce' && mode !== 'shadow') || (!email && !whatsapp))
    return null;
  const actionFor = (channel, entry) => {
    if (isViewer) return null;
    if (entry.status === 'verified') {
      return {
        label: 'Stop notifications',
        onAction: () => onRevoke(contact, channel),
      };
    }
    if (channel === 'email') {
      return {
        label: entry.invitation ? 'Resend invitation' : 'Send invitation',
        onAction: () => onInviteEmail(contact),
      };
    }
    if (entry.status === 'opted_out') return null;
    return {
      label: confirmationOpen
        ? 'Close confirmation'
        : showSharedLink
          ? 'View confirmation link'
          : 'Confirm WhatsApp',
      onAction: () => setConfirmationOpen(open => !open),
    };
  };
  const emailAction = email ? actionFor('email', email) : null;
  const whatsappAction = whatsapp ? actionFor('whatsapp', whatsapp) : null;
  return (
    <VStack align='flex-start' spacing={1} mt={2} w='full' minW={0}>
      {[email, whatsapp].some(
        entry => entry && entry.status !== 'verified'
      ) && <Text fontSize='xs'>{verificationWaitCopy(mode)}</Text>}
      {email ? (
        <ChannelLine
          label='Email'
          entry={email}
          actionLabel={emailAction?.label}
          onAction={emailAction?.onAction}
          busy={busyKey === `${contact.id}:email`}
          disabled={isViewer}
        />
      ) : null}
      {whatsapp ? (
        <ChannelLine
          label='WhatsApp'
          entry={whatsapp}
          actionLabel={whatsappAction?.label}
          onAction={whatsappAction?.onAction}
          busy={busyKey === `${contact.id}:whatsapp`}
          disabled={isViewer}
          expanded={
            whatsappAction && whatsapp.status !== 'verified'
              ? confirmationOpen
              : undefined
          }
        />
      ) : null}
      {whatsapp &&
        whatsapp.status !== 'verified' &&
        !isViewer &&
        whatsapp.status !== 'opted_out' && (
          <Collapse in={confirmationOpen} style={{ width: '100%' }}>
            <Box
              w='full'
              maxW='36rem'
              borderWidth='1px'
              borderRadius='md'
              p={3}
              mt={1}
            >
              <Text fontSize='sm' mb={2}>
                This link is for the saved number {contact.phone_e164}. Share it
                with the contact.{' '}
                {mode === 'enforce'
                  ? 'They must opt in before WhatsApp alerts or tests can be sent.'
                  : 'Confirmation is recorded; it does not block alerts or tests.'}
              </Text>
              {showSharedLink && (
                <FormControl minW={0}>
                  <FormLabel fontSize='sm' mb={1}>
                    WhatsApp confirmation link
                  </FormLabel>
                  <HStack align='stretch' flexWrap='wrap' spacing={2}>
                    <Input
                      flex='1 1 14rem'
                      minW={0}
                      size='sm'
                      fontSize='xs'
                      isReadOnly
                      value={sharedInvitation.url}
                      onFocus={event => event.target.select()}
                    />
                    <Button size='sm' variant='outline' onClick={onCopy}>
                      {hasCopied ? 'Copied' : 'Copy link'}
                    </Button>
                  </HStack>
                  <Text fontSize='xs' mt={2}>
                    Copy and share this link before leaving this page.
                  </Text>
                </FormControl>
              )}
              <Button
                size='xs'
                variant='outline'
                mt={showSharedLink ? 3 : 0}
                onClick={() => onShareWhatsApp(contact)}
                isLoading={busyKey === `${contact.id}:whatsapp`}
              >
                {showSharedLink || whatsapp.invitation
                  ? 'Create new link'
                  : 'Create confirmation link'}
              </Button>
              <Text fontSize='xs' mt={1}>
                Creating a link is subject to limits.
              </Text>
            </Box>
          </Collapse>
        )}
    </VStack>
  );
}
