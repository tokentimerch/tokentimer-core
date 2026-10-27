import { Badge, Button, HStack, Text, VStack } from "@chakra-ui/react";
import { channelStatus, verificationWaitCopy } from "./contactVerificationStatus";

const COLORS = {
  pending: "orange",
  verified: "green",
  revoked: "red",
  opted_out: "red",
};

function ChannelLine({ label, entry, actionLabel, onAction, busy, disabled }) {
  const expiry = entry.invitation?.expires_at
    ? new Date(entry.invitation.expires_at)
    : null;
  const expiryLabel = expiry && !Number.isNaN(expiry.getTime())
    ? `Invitation open until ${expiry.toLocaleString()}`
    : null;
  return (
    <HStack spacing={2} align="center" flexWrap="wrap">
      <Text fontSize="xs" color="inherit">
        {label}
      </Text>
      <Badge colorScheme={COLORS[entry.status] || "orange"} variant="subtle">
        {entry.label}
      </Badge>
      {expiryLabel ? (
        <Text fontSize="xs" color="inherit">
          {expiryLabel}
        </Text>
      ) : null}
      {actionLabel ? (
        <Button
          size="xs"
          variant="outline"
          onClick={onAction}
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
  mode,
  isViewer,
  busyKey,
  onInviteEmail,
  onShareWhatsApp,
  onRevoke,
}) {
  if (mode !== "enforce" && mode !== "shadow") return null;
  const email = channelStatus(contact, "email");
  const whatsapp = channelStatus(contact, "whatsapp");
  if (!email && !whatsapp) return null;
  const waitCopy = verificationWaitCopy(mode);
  const actionFor = (channel, entry) => {
    if (isViewer) return null;
    if (entry.status === "verified") {
      return {
        label: "Stop notifications",
        onAction: () => onRevoke(contact, channel),
      };
    }
    if (channel === "email") {
      return {
        label: entry.invitation ? "Resend invitation" : "Send invitation",
        onAction: () => onInviteEmail(contact),
      };
    }
    return {
      label: entry.invitation ? "Copy a new link" : "Copy confirmation link",
      onAction: () => onShareWhatsApp(contact),
    };
  };
  const emailAction = email ? actionFor("email", email) : null;
  const whatsappAction = whatsapp ? actionFor("whatsapp", whatsapp) : null;
  return (
    <VStack align="flex-start" spacing={1} mt={2}>
      {waitCopy ? (
        <Text fontSize="xs">
          {waitCopy}
        </Text>
      ) : null}
      {email && emailAction ? (
        <ChannelLine
          label="Email"
          entry={email}
          actionLabel={emailAction.label}
          onAction={emailAction.onAction}
          busy={busyKey === `${contact.id}:email`}
          disabled={isViewer}
        />
      ) : null}
      {whatsapp && whatsappAction ? (
        <ChannelLine
          label="WhatsApp"
          entry={whatsapp}
          actionLabel={whatsappAction.label}
          onAction={whatsappAction.onAction}
          busy={busyKey === `${contact.id}:whatsapp`}
          disabled={isViewer}
        />
      ) : null}
    </VStack>
  );
}
