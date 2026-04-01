/**
 * Contact Group Resolution Utilities
 *
 * Shared functions for resolving contact groups from workspace settings,
 * handling fallbacks between token-level and workspace default groups.
 */

/**
 * Resolves a contact group from an array of contact groups based on token-level
 * or workspace default contact group ID.
 *
 * @param {Object} options - Resolution options
 * @param {Array<Object>} options.contactGroups - Array of contact group objects from workspace settings
 * @param {string|null} options.contactGroupId - Token-level contact group ID (optional)
 * @param {string|null} options.defaultContactGroupId - Workspace default contact group ID (optional)
 * @returns {Object|null} The resolved contact group object, or null if not found
 *
 * @example
 * const group = resolveContactGroup({
 *   contactGroups: workspaceSettings.contact_groups,
 *   contactGroupId: token.contact_group_id,
 *   defaultContactGroupId: workspaceSettings.default_contact_group_id
 * });
 */
function resolveContactGroup({
  contactGroups,
  contactGroupId,
  defaultContactGroupId,
}) {
  try {
    const groups = Array.isArray(contactGroups) ? contactGroups : [];

    // Determine which group ID to use: token-level takes precedence, fallback to workspace default
    const pickId =
      contactGroupId && String(contactGroupId).trim().length > 0
        ? String(contactGroupId)
        : defaultContactGroupId
          ? String(defaultContactGroupId)
          : null;

    if (!pickId) {
      return null;
    }

    // Find the group by ID
    let resolvedGroup = groups.find((g) => String(g.id) === pickId) || null;

    // Fallback: if token-level group was deleted, try workspace default
    if (!resolvedGroup && contactGroupId && defaultContactGroupId) {
      resolvedGroup =
        groups.find((g) => String(g.id) === String(defaultContactGroupId)) ||
        null;
    }

    return resolvedGroup;
  } catch (_err) {
    // Return null on any error to allow graceful degradation
    return null;
  }
}

/**
 * Checks if a contact group has email contacts configured.
 *
 * @param {Object|null} contactGroup - The contact group object
 * @returns {boolean} True if the group has email contact IDs
 */
function hasEmailContacts(contactGroup) {
  if (!contactGroup) return false;
  return (
    Array.isArray(contactGroup.email_contact_ids) &&
    contactGroup.email_contact_ids.length > 0
  );
}

/**
 * Checks if a contact group has WhatsApp contacts configured.
 *
 * @param {Object|null} contactGroup - The contact group object
 * @returns {boolean} True if the group has WhatsApp contact IDs
 */
function hasWhatsAppContacts(contactGroup) {
  if (!contactGroup) return false;
  return (
    Array.isArray(contactGroup.whatsapp_contact_ids) &&
    contactGroup.whatsapp_contact_ids.length > 0
  );
}

/**
 * Checks if a contact group has webhook names configured.
 *
 * @param {Object|null} contactGroup - The contact group object
 * @returns {boolean} True if the group has webhook names configured
 */
function hasWebhookNames(contactGroup) {
  if (!contactGroup) return false;
  return (
    contactGroup.webhook_name ||
    (Array.isArray(contactGroup.webhook_names) &&
      contactGroup.webhook_names.length > 0)
  );
}

/**
 * Gets webhook names from a contact group.
 *
 * @param {Object|null} contactGroup - The contact group object
 * @returns {Array<string>} Array of webhook names (trimmed)
 */
function getWebhookNames(contactGroup) {
  if (!contactGroup) return [];

  if (Array.isArray(contactGroup.webhook_names)) {
    return contactGroup.webhook_names
      .filter(Boolean)
      .map((n) => String(n).trim());
  }

  if (contactGroup.webhook_name) {
    return [String(contactGroup.webhook_name).trim()];
  }

  return [];
}

export {
  resolveContactGroup,
  hasEmailContacts,
  hasWhatsAppContacts,
  hasWebhookNames,
  getWebhookNames,
};
