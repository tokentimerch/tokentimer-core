"use strict";

const {
  containsPrivateKeyMaterial,
} = require("../utils/secretMaterial");

const PRIVATE_KEY_MATERIAL_REJECTED = "PRIVATE_KEY_MATERIAL_REJECTED";

const REJECTION_RESPONSE = Object.freeze({
  error: "Private key material is not accepted in CertOps requests",
  code: PRIVATE_KEY_MATERIAL_REJECTED,
});

function rejectKeyMaterial(req, res, next) {
  if (!containsPrivateKeyMaterial(req.body)) {
    return next();
  }

  return res.status(422).json(REJECTION_RESPONSE);
}

module.exports = {
  PRIVATE_KEY_MATERIAL_REJECTED,
  rejectKeyMaterial,
};
