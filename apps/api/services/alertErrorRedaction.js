"use strict";

const { redactGenericSecrets } = require("../utils/secretMaterial");

function safeAlertErrorMessage(value) {
  if (value === null || value === undefined || value === "") return null;
  let text = String(value).slice(0, 2000);
  try {
    text = String(redactGenericSecrets(text));
  } catch (_) {
    return "[REDACTED]";
  }
  return text
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[EMAIL_REDACTED]")
    .replace(/https?:\/\/[^\s,;]+/gi, "[URL_REDACTED]")
    .replace(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:\/[^\s,;]*)?/gi, "[URL_REDACTED]")
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/[^\s,;]*)?/g, "[URL_REDACTED]")
    .replace(/\blocalhost(?::\d+)?(?:\/[^\s,;]*)?/gi, "[URL_REDACTED]")
    .replace(/\+\d[\d(). -]{7,}\d\b/g, "[PHONE_REDACTED]")
    .replace(/\b(?:\(?\d{3}\)?[ .-]*)\d{3}[ .-]*\d{4}\b/g, "[PHONE_REDACTED]")
    .replace(/\b\d{11,15}\b/g, "[PHONE_REDACTED]");
}

module.exports = { safeAlertErrorMessage };
