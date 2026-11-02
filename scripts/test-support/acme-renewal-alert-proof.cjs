"use strict";
// Synthetic verifier fixture only. Never exported as execution evidence.
const crypto=require("node:crypto");
const h=require("../../tests/e2e/helpers/certops-acme-renewal-alert");
function proof(previous){
  const value={scope:h.SCOPE,jobId:crypto.randomUUID(),claimId:crypto.randomUUID(),certificateId:previous.certificateId,alertId:"17",faultRequestCount:2,servingFingerprint:previous.fingerprints[1].toUpperCase().match(/../g).join(":"),...Object.fromEntries(h.FLAGS.map(flag=>[flag,true]))};
  h.verifyAgainstOutbox(value,previous);return value;
}
module.exports={proof};
