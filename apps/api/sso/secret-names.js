"use strict";

/** Known encrypted secret field names per provider type. Not all are required. */
const SECRET_NAMES = {
  oidc: ["client_secret"],
  saml: [],
};

module.exports = { SECRET_NAMES };
