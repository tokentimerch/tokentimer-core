"use strict";

// These bounds are part of the published M3-A6 controller-observation
// contract. The controller imports this module so it cannot construct a
// public-certificate payload that the API boundary rejects for size alone.
const MAX_PUBLIC_TEXT_LENGTH = 1_024;
const MAX_PUBLIC_SAN_ENTRIES = 64;
const MAX_PUBLIC_SAN_LENGTH = 253;
const MAX_PUBLIC_PEM_BYTES = 64 * 1024;

module.exports = {
  MAX_PUBLIC_PEM_BYTES,
  MAX_PUBLIC_SAN_ENTRIES,
  MAX_PUBLIC_SAN_LENGTH,
  MAX_PUBLIC_TEXT_LENGTH,
};
