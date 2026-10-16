"use strict";
/** Compare only public CSR/leaf SPKI before Windows ACME certificate acceptance.
 * A tool may return a valid certificate belonging to a different pending key;
 * certreq acceptance alone cannot establish this job's key custody. */
const { X509Certificate, createPublicKey } = require("node:crypto");
const { extractSpkiFromCsr } = require("./der-extensions");
function certificateMatchesCsr(csrPem, certificatePem) {
  try {
    const leaf = new X509Certificate(certificatePem);
    const requested = createPublicKey({
      key: extractSpkiFromCsr(csrPem),
      type: "spki",
      format: "der",
    });
    return requested
      .export({ type: "spki", format: "der" })
      .equals(leaf.publicKey.export({ type: "spki", format: "der" }));
  } catch {
    return false;
  }
}
module.exports = { certificateMatchesCsr };
