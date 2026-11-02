"use strict";

// Stored JSON, delivery logs, and library arguments must not resolve inherited
// objects or invoke the __proto__ setter when copied into delivery dictionaries.
function safeDeliveryKey(key) {
  return key !== "__proto__" && key !== "constructor" && key !== "prototype";
}

function deliveryData(value) {
  if (Array.isArray(value)) return value.map(deliveryData);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value)
    .filter(([key]) => safeDeliveryKey(key))
    .map(([key, entry]) => [key, deliveryData(entry)]));
}

function deliveryChannelNames(value) {
  return Array.isArray(value) ? value.map(String).filter((key) => key && safeDeliveryKey(key)) : [];
}

module.exports = { safeDeliveryKey, deliveryData, deliveryChannelNames };
