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

export function canTestSavedWhatsApp(contact, phoneNow, mode = "enforce") {
  const status = channelStatus(contact, "whatsapp");
  if (!contact?.id || !status) return false;
  if (String(contact.phone_e164 || "").trim() !== String(phoneNow || "").trim()) return false;
  if (mode === "enforce") return status.status === "verified";
  return true;
}

export function verificationControlsVisible(mode) {
  return mode === "enforce" || mode === "shadow";
}

export function verificationIntro(mode) {
  if (mode === "enforce") {
    return "A contact can be saved before they confirm. Email and WhatsApp alerts wait until that person confirms the exact address or number.";
  }
  if (mode === "shadow") {
    return "Recipient verification is recording confirmation status. Notifications are still sent.";
  }
  if (mode === "off") {
    return "Contacts receive workspace alerts at the address or number you save. Recipient confirmation is off for this deployment.";
  }
  return "Manage people who can receive workspace alerts.";
}

export function verificationWaitCopy(mode) {
  if (mode === "enforce") return "Alerts wait until this person confirms the address or number.";
  if (mode === "shadow") return "Confirmation is recorded. Notifications are still sent.";
  return null;
}

export function groupChannelHint(mode) {
  if (mode === "enforce") {
    return "Unverified people stay in the group and do not receive email or WhatsApp until they confirm.";
  }
  if (mode === "shadow") {
    return "Unverified people stay in the group. Notifications are still sent while verification is recording status.";
  }
  return "Each selected person receives alerts at the saved address or number.";
}

export function testNumberHint(mode) {
  if (mode === "enforce") {
    return "Provide a valid email or phone number. A test is available only while this saved number stays confirmed.";
  }
  if (mode === "shadow") {
    return "Provide a valid email or phone number. Confirmation is recorded and does not block a test to this saved number.";
  }
  if (mode === "off") {
    return "Provide a valid email or phone number. A test uses this saved number and does not require confirmation.";
  }
  return "Provide a valid email or phone number.";
}

export function addContactTestHint(mode) {
  if (mode === "enforce") {
    return "Save the contact first. A WhatsApp test is available only after this number is confirmed.";
  }
  if (mode === "shadow") {
    return "Save the contact first. Confirmation is recorded and does not block the test.";
  }
  if (mode === "off") {
    return "Save the contact first. A WhatsApp test uses the saved number and does not require confirmation.";
  }
  return "Save the contact first.";
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

export function groupEligibilityNote(contacts, emailIds, whatsappIds, mode = "enforce") {
  if (mode !== "enforce") return [];
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
