"use strict";
// Offline report fixture only; no native observations are created here.
exports.proof = () => {
  const {
    SCOPE,
    FLAGS,
  } = require("../../tests/e2e/helpers/certops-adcs-http-leaf-crl");
  return {
    scope: SCOPE,
    enrollmentId: "10000000-0000-4000-8000-000000000001",
    jobId: "10000000-0000-4000-8000-000000000002",
    requestId: 42,
    restoredEnrollmentId: "10000000-0000-4000-8000-000000000003",
    restoredJobId: "10000000-0000-4000-8000-000000000004",
    restoredRequestId: 43,
    leafFingerprint: "1".repeat(64),
    restoredLeafFingerprint: "6".repeat(64),
    publicCrlSha256: "2".repeat(64),
    nativeHelperSha256: "3".repeat(64),
    originalPublicationSha256: "4".repeat(64),
    appliedPublicationSha256: "5".repeat(64),
    caRequestCounts: [10, 11, 12],
    nativeVerdicts: ["valid", "revocation_unknown", "valid"],
    endpointStatusCodes: [200, 503, 200],
    ocspQualified: false,
    caOutageQualified: false,
    signedCmcRenewalQualified: false,
    deferredRecovery: {
      originalJobId: "10000000-0000-4000-8000-000000000005",
      originalClaimId: "10000000-0000-4000-8000-000000000006",
      continuationJobId: "10000000-0000-4000-8000-000000000002",
      continuationClaimId: "10000000-0000-4000-8000-000000000007",
      requestId: 42,
    },
    ...Object.fromEntries(FLAGS.map((flag) => [flag, true])),
  };
};
