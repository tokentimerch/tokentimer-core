"use strict";

const crypto = require("crypto");

/**
 * Generate a short, unique error reference code for support tracking
 * Format: ERR-YYYYMMDD-XXXX (e.g., ERR-20251108-A3F9)
 */
function generateErrorReference() {
  const now = new Date();
  const dateStr = now.toISOString().slice(0, 10).replace(/-/g, ""); // YYYYMMDD
  const randomHex = crypto.randomBytes(2).toString("hex").toUpperCase(); // 4 chars
  return `ERR-${dateStr}-${randomHex}`;
}

/**
 * Create a user-friendly error message with support reference
 * @param {string} context - Integration name (e.g., "AWS", "Vault", "Azure AD")
 * @param {Error} error - The error object
 * @param {string} referenceCode - The error reference code
 * @returns {string} User-friendly error message
 */
function formatIntegrationError(context, error, referenceCode) {
  const baseMessage = error?.message || "An unexpected error occurred";
  return `${context} integration failed: ${baseMessage}. If this persists, please contact support via the Help page with reference code: ${referenceCode}`;
}

module.exports = {
  generateErrorReference,
  formatIntegrationError,
};
