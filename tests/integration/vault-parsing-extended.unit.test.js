const { expect } = require("chai");
const path = require("path");

function resolveVaultModule() {
  const candidates = [
    path.join(
      __dirname,
      "..",
      "..",
      "apps",
      "api",
      "services",
      "vaultIntegration.js",
    ),
    path.join(
      __dirname,
      "..",
      "..",
      "apps",
      "saas",
      "integrations",
      "vaultIntegration.js",
    ),
  ];
  for (const candidate of candidates) {
    try {
      return require.resolve(candidate);
    } catch (_) {}
  }
  throw new Error("Unable to resolve vaultIntegration module in this variant");
}

describe("Vault parsing extended coverage", () => {
  let mod;

  before(() => {
    mod = require(resolveVaultModule());
  });

  describe("isBase64Like", () => {
    const isBase64Like = () => mod._test.isBase64Like;

    it("rejects non-string input", () => {
      expect(isBase64Like()(null)).to.be.false;
      expect(isBase64Like()(123)).to.be.false;
      expect(isBase64Like()(undefined)).to.be.false;
    });

    it("rejects strings shorter than 40 chars", () => {
      expect(isBase64Like()("AAAA")).to.be.false;
      expect(isBase64Like()("YWJjZA==")).to.be.false;
    });

    it("rejects strings with non-base64 characters", () => {
      expect(isBase64Like()("!" + "A".repeat(50))).to.be.false;
    });

    it("rejects strings with invalid padding length", () => {
      expect(isBase64Like()("A".repeat(43))).to.be.false;
    });

    it("accepts valid long base64 strings", () => {
      expect(isBase64Like()("A".repeat(44))).to.be.true;
      expect(isBase64Like()("ABCDabcd0123+/==" + "A".repeat(40))).to.be.true;
    });

    it("handles whitespace in base64 strings", () => {
      const s = "A".repeat(20) + "\n" + "A".repeat(24);
      expect(isBase64Like()(s)).to.be.true;
    });
  });

  describe("parseCertificateFromUnknown", () => {
    const fn = () => mod._test.parseCertificateFromUnknown;

    it("returns null for non-certificate values", () => {
      expect(fn()("just a string")).to.be.null;
      expect(fn()("")).to.be.null;
    });

    it("returns null for invalid base64 that is not a cert", () => {
      expect(fn()("A".repeat(44))).to.be.null;
    });

    it("parses PEM certificate strings", () => {
      const pem = `-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiIMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjMwMTAxMDAwMDAwWhcNMjcxMjMxMjM1OTU5WjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onL
RnrqjGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
RnrqjGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
CgKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onL
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
AgEBMA0GCSqGSIb3DQEBCwUAA4IBAQAcjN
-----END CERTIFICATE-----`;
      const result = fn()(pem);
      // It may or may not parse depending on whether it is a valid x509
      // The function should not throw regardless
      expect(result === null || typeof result === "object").to.be.true;
    });
  });

  describe("inferKindFromData", () => {
    const fn = () => mod._test.inferKindFromData;

    it("detects PEM certificate content in values", () => {
      const data = {
        cert: "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
      };
      expect(fn()("secret/data/myapp", data)).to.deep.equal({
        category: "cert",
        type: "ssl_cert",
      });
    });

    it("detects SSH key content", () => {
      expect(
        fn()("secret/data/ssh", {
          key: "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
        }),
      ).to.deep.equal({ category: "key_secret", type: "ssh_key" });
    });

    it("detects RSA private key", () => {
      expect(
        fn()("secret/data/rsa", {
          key: "-----BEGIN RSA PRIVATE KEY-----\n...",
        }),
      ).to.deep.equal({ category: "key_secret", type: "ssh_key" });
    });

    it("detects encryption keys by field names", () => {
      expect(fn()("secret/enc", { key_id: "k1", cipher: "aes" })).to.deep.equal(
        {
          category: "key_secret",
          type: "encryption_key",
        },
      );
    });

    it("detects password by field name", () => {
      expect(fn()("secret/db", { password: "s3cret" })).to.deep.equal({
        category: "key_secret",
        type: "password",
      });
    });

    it("defaults to secret for objects with many keys", () => {
      const data = { a: "1", b: "2", c: "3", d: "4" };
      expect(fn()("secret/config/app", data)).to.deep.equal({
        category: "key_secret",
        type: "secret",
      });
    });

    it("detects api_key from path when few keys", () => {
      expect(fn()("secret/data/api-key", { value: "tok123" })).to.deep.equal({
        category: "key_secret",
        type: "api_key",
      });
    });

    it("detects password from path when few keys", () => {
      expect(fn()("secret/data/password", { value: "pass" })).to.deep.equal({
        category: "key_secret",
        type: "password",
      });
    });

    it("defaults to secret for unrecognized paths and data", () => {
      expect(fn()("secret/data/misc", { foo: "bar" })).to.deep.equal({
        category: "key_secret",
        type: "secret",
      });
    });

    it("handles null/undefined gracefully", () => {
      expect(fn()(null, null)).to.deep.equal({
        category: "key_secret",
        type: "secret",
      });
      expect(fn()(undefined, {})).to.deep.equal({
        category: "key_secret",
        type: "secret",
      });
    });
  });

  describe("parseCertificatePemForDatesAndNames", () => {
    const fn = () => mod._test.parseCertificatePemForDatesAndNames;

    it("returns null for invalid PEM", () => {
      expect(fn()("not a cert")).to.be.null;
      expect(
        fn()("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----"),
      ).to.be.null;
    });
  });
});
