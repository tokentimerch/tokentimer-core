const LABELS = {
  pending: "Pending",
  verified: "Verified",
  revoked: "Revoked",
  opted_out: "Opted out",
};

export function channelStatus(contact, channel) {
  const entry = contact?.verification?.[channel];
  if (!entry || !entry.status) {
    const hasDestination = channel === "email"
      ? Boolean(String(contact?.details?.email || "").trim())
      : Boolean(String(contact?.phone_e164 || "").trim());
    if (!hasDestination) return null;
    return { status: "pending", label: LABELS.pending, invitation: null };
  }
  return {
    status: entry.status,
    label: LABELS[entry.status] || "Pending",
    invitation: entry.invitation || null,
    verified_at: entry.verified_at || null,
    consent_at: entry.consent_at || null,
  };
}

export function canTestSavedWhatsApp(contact, phoneNow) {
  const status = channelStatus(contact, "whatsapp");
  if (!contact?.id || !status || status.status !== "verified") return false;
  return String(contact.phone_e164 || "").trim() === String(phoneNow || "").trim();
}

export function formatRetry(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value <= 0) return "Please wait before trying again.";
  if (value >= 3600) {
    return `Please wait about ${Math.ceil(value / 3600)} hours before trying again.`;
  }
  if (value >= 60) {
    return `Please wait ${Math.ceil(value / 60)} minutes before trying again.`;
  }
  return `Please wait ${Math.ceil(value)} seconds before trying again.`;
}

export function groupEligibilityNote(contacts, emailIds, whatsappIds) {
  const list = Array.isArray(contacts) ? contacts : [];
  const notes = [];
  const selected = (ids, channel) => {
    const chosen = (Array.isArray(ids) ? ids : [])
      .map((id) => list.find((contact) => String(contact.id) === String(id)))
      .filter(Boolean);
    if (!chosen.length) return false;
    return chosen.every((contact) => channelStatus(contact, channel)?.status !== "verified");
  };
  if (selected(emailIds, "email")) {
    notes.push("Nobody selected for email has confirmed it, so this group will not send email alerts.");
  }
  if (selected(whatsappIds, "whatsapp")) {
    notes.push("Nobody selected for WhatsApp has confirmed it, so this group will not send WhatsApp alerts.");
  }
  return notes;
}

export { LABELS };
