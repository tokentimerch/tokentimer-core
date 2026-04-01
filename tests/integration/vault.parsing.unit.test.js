const { expect } = require("chai");

describe("Vault parsing helpers", () => {
  it("detects base64-like strings", () => {
    const mod = require("../../apps/api/services/vaultIntegration.js");
    const f = mod._test.isBase64Like;
    // Use a base64 string that's long enough (>= 40 chars) like a certificate would be
    const longBase64 =
      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc";
    expect(f(longBase64)).to.equal(true);
    expect(f("not base64!")).to.equal(false);
    // Short base64 strings should return false (too short to be a cert)
    expect(f("YWJjZA==")).to.equal(false);
  });

  it("infers kind from path and keys", () => {
    const mod = require("../../apps/api/services/vaultIntegration.js");
    const f = mod._test.inferKindFromData;

    // Content-based detection (more reliable than path)
    const certPem =
      "-----BEGIN CERTIFICATE-----\nMIIDXTCC...\n-----END CERTIFICATE-----";
    expect(f("secret/certs/www", { certificate: certPem })).to.deep.equal({
      category: "cert",
      type: "ssl_cert",
    });

    // Path-based detection with supporting keys
    expect(f("secret/ssh/key", { ssh_private_key: "xxx" })).to.deep.equal({
      category: "key_secret",
      type: "ssh_key",
    });

    // Key-based detection
    expect(f("secret/api", { api_key: "x" })).to.deep.equal({
      category: "key_secret",
      type: "api_key",
    });

    // Path-only detection (now more conservative - defaults to secret)
    expect(f("secret/random/path", {})).to.deep.equal({
      category: "key_secret",
      type: "secret",
    });
  });

  it("parses PEM certificate dates", () => {
    // Use a real valid self-signed test certificate
    const pem = `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiIMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTYxMjI4MTI0NjEyWhcNMjYxMjI2MTI0NjEyWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onL
Rnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFc
zGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQz
uVaE8AkAFmxZzow3x+VJYKdjykkJ0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgw
lL9xNAwxXFg0x/XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf
4rEjGoXbAAEgAqeGUxrcIlbjXfbcMwIDAQABo1AwTjAdBgNVHQ4EFgQUU3m/Wqor
Ss9UgOHYm8Cd8rIDZsswHwYDVR0jBBgwFoAUU3m/WqorSs9UgOHYm8Cd8rIDZssw
DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAmuDQrOPJlxwQzK9SXFVR
vSL1BqJ7yBbKLgKu6KD8P9xh8Wp6jShZXQPaBKnfP+7bGmFMpKRzYQ3Ly7dmRGdX
r8lHdmtPuJfC7MqThJa1cI8DZ9lZ1G6xQzMW1L1F9oH1qh0aUJGqQ3BNQJhj1Y3g
F3gHCJGpMYJ9J/PqMjXgHVk5FMHT1PlGRMPKEJRNz2pYLX3fGqLH2NHNPUxqYLYe
3/tQQTdRvQJbOdtWB0FbKjZxNNrYhX3qLZPa7f0SJ6qGJP0VYJ0M7E4Ge9fhx5wS
D8JXW0KGW1vKQRz3SqPpPxPQdEuEJHWNfHXGfqRLWLw1LzW5WPUZWTVBbqLaAhIZ
gw==
-----END CERTIFICATE-----`;
    const mod = require("../../apps/api/services/vaultIntegration.js");
    const parsed = mod._test.parseCertificatePemForDatesAndNames(pem);
    expect(parsed).to.be.an("object");
    expect(parsed).to.have.property("notAfter");
  });
});
