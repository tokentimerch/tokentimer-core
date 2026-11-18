"use strict";
const {
  X509Certificate, constants, createHash, createPrivateKey, randomUUID, sign,
} = require("node:crypto");

const SHA256 = /^[a-f0-9]{64}$/;
const ASSERTION_LIFETIME_SECONDS = 300;
const CERTIFICATE_LIFETIME_MS = 24 * 60 * 60 * 1000;
const hash = value => createHash("sha256").update(value).digest();
const encode = value => Buffer.from(JSON.stringify(value)).toString("base64url");

function loadCredential({ identity, certificatePem, privateKeyPem, now, deadlineMs }) {
  try {
    if (!SHA256.test(identity.certificateSha256) ||
      !/^-----BEGIN CERTIFICATE-----[\w+/=\r\n]+-----END CERTIFICATE-----$/.test(certificatePem)) {
      throw new Error();
    }
    const certificate = new X509Certificate(certificatePem);
    const privateKey = createPrivateKey(privateKeyPem);
    const thumbprint = hash(certificate.raw);
    const validFrom = Date.parse(certificate.validFrom);
    const validTo = Date.parse(certificate.validTo);
    if (!(validFrom <= now && deadlineMs < validTo && validTo - validFrom <= CERTIFICATE_LIFETIME_MS) ||
      thumbprint.toString("hex") !== identity.certificateSha256 ||
      privateKey.asymmetricKeyType !== "rsa" || privateKey.asymmetricKeyDetails.modulusLength < 2048 ||
      !certificate.checkPrivateKey(privateKey)) {
      throw new Error();
    }
    const keyFingerprint = hash(certificate.publicKey.export({ format: "der", type: "spki" })).toString("hex");
    return {
      keyFingerprint,
      subjectSha256: hash(JSON.stringify([identity.tenantId, identity.clientId, keyFingerprint])).toString("hex"),
      assertion(target, timeMs) {
        const iat = Math.floor(timeMs / 1000);
        const jti = randomUUID();
        const header = encode({ alg: "PS256", typ: "JWT", "x5t#S256": thumbprint.toString("base64url") });
        const payload = encode({
          aud: "https://login.microsoftonline.com/" + target.tenantId + "/oauth2/v2.0/token",
          iss: target.clientId, sub: target.clientId, jti, iat, nbf: iat,
          exp: iat + ASSERTION_LIFETIME_SECONDS,
        });
        const input = header + "." + payload;
        const signature = sign("sha256", Buffer.from(input), {
          key: privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
        });
        return { assertion: input + "." + signature.toString("base64url"), jti };
      },
    };
  } catch {
    throw new Error("AZURE_BROKER_CERTIFICATE_CREDENTIAL_REFUSED");
  }
}

module.exports = { loadCredential };
