"use strict";

/**
 * Agent-local policy engine.
 *
 * ADR-0002: "agent-local policy always wins over
 * control-plane intent." Jobs dispatched by the control plane reference
 * command profiles, paths, CA endpoints, and DNS zones/providers by name or
 * value only; this module is the sole authority that decides whether those
 * references are allowed to run on this host. It never trusts anything the
 * control plane sends beyond an opaque reference/value to look up against
 * agent-local configuration ("the agent distrusts the server").
 *
 * This module is intentionally self-contained: it accepts plain data
 * (a parsed policy config object, and per-call job/target descriptors) as
 * function parameters and does not import sibling modules (config,
 * protocol, etc.). Wiring those together is left to src/index.js.
 *
 * Scope note: this module owns only the *policy* rejection reasons from the
 * agent-protocol schema (resultBody.rejectionReason): target_out_of_scope,
 * command_not_allowlisted, path_not_allowlisted, ca_endpoint_not_allowlisted,
 * dns_zone_not_allowlisted, dns_provider_not_allowlisted,
 * key_export_requested. job_integrity_failed,
 * job_replay_rejected, and clock_drift_suspected belong to the signed-dispatch
 * signature/replay runtime and are NOT implemented here; this module's
 * rejection result shape ({ allowed, rejectionReason, detail }) is designed
 * to be identical to whatever shape the signed-dispatch runtime will produce for those
 * other reasons, so downstream consumers (evidence builder, result
 * reporting) can handle both uniformly.
 *
 * Known follow-up (not this module's job): path containment here is a
 * pure string/segment normalization check (allowlist-prefix match after
 * path.resolve/normalize). It does not resolve symlinks, so a path that is
 * lexically inside an allowed root but is actually a symlink escaping it
 * would still pass this check. Symlink resolution (fs.realpath-based
 * containment) belongs to the discovery/deploy modules that actually touch
 * the filesystem, immediately before any read/write, not to this
 * config-time/reference-time policy check.
 */

const path = require("node:path");
const net = require("node:net");

/**
 * Shell metacharacters disallowed in any argv element of an allowlisted
 * command profile. Command profiles are exec'd without a shell, so
 * this is defense in depth against a misconfigured profile rather than a
 * shell-injection vector by itself -- but a profile that *looks* like it
 * contains shell syntax is almost certainly a config mistake and must fail
 * loudly at load time (see loadPolicyConfig) rather than silently at run
 * time.
 *
 * Matches: ; | & $ ` > < and newlines (CR or LF).
 */
const SHELL_METACHARACTER_PATTERN = /[;|&$`><\r\n]/;

/**
 * Rejection reasons this module can produce, mirroring the subset of
 * packages/contracts/certops/agent-protocol.schema.json's
 * resultBody.rejectionReason enum owned by agent-local policy.
 * Downstream code (e.g. the evidence builder) should reference these
 * constants instead of re-typing the strings.
 */
const REJECTION_REASONS = Object.freeze({
  TARGET_OUT_OF_SCOPE: "target_out_of_scope",
  COMMAND_NOT_ALLOWLISTED: "command_not_allowlisted",
  PATH_NOT_ALLOWLISTED: "path_not_allowlisted",
  CA_ENDPOINT_NOT_ALLOWLISTED: "ca_endpoint_not_allowlisted",
  DNS_ZONE_NOT_ALLOWLISTED: "dns_zone_not_allowlisted",
  DNS_PROVIDER_NOT_ALLOWLISTED: "dns_provider_not_allowlisted",
  KEY_EXPORT_REQUESTED: "key_export_requested",
});

function isNonEmptyString(value) {
  return typeof value === "string" && value.length > 0;
}

/**
 * Validates and normalizes one `allowedCommands` profile entry.
 * Throws descriptively on any malformed shape; a misconfigured allowlist
 * must fail loudly at load time, not permit an unsafe command silently at
 * run time.
 *
 * @param {string} name
 * @param {unknown} rawProfile
 * @returns {{ argv: string[] }}
 */
function validateCommandProfile(name, rawProfile) {
  if (rawProfile === null || typeof rawProfile !== "object" || Array.isArray(rawProfile)) {
    throw new Error(
      `policy: allowedCommands.${name} must be an object with an "argv" array`,
    );
  }

  const { argv } = rawProfile;

  if (!Array.isArray(argv)) {
    throw new Error(
      `policy: allowedCommands.${name}.argv must be an array (got ${typeof argv})`,
    );
  }

  if (argv.length === 0) {
    throw new Error(`policy: allowedCommands.${name}.argv must not be empty`);
  }

  argv.forEach((element, index) => {
    if (!isNonEmptyString(element)) {
      throw new Error(
        `policy: allowedCommands.${name}.argv[${index}] must be a non-empty string`,
      );
    }
    if (SHELL_METACHARACTER_PATTERN.test(element)) {
      throw new Error(
        `policy: allowedCommands.${name}.argv[${index}] contains a disallowed shell metacharacter: ${JSON.stringify(element)}`,
      );
    }
  });

  return { argv: [...argv] };
}

/**
 * Validates a `rawConfigObject.<listName>` value is an array of non-empty
 * strings, returning a shallow copy.
 *
 * @param {string} listName
 * @param {unknown} rawList
 * @returns {string[]}
 */
function validateStringList(listName, rawList) {
  if (rawList === undefined) {
    return [];
  }

  if (!Array.isArray(rawList)) {
    throw new Error(`policy: ${listName} must be an array (got ${typeof rawList})`);
  }

  rawList.forEach((element, index) => {
    if (!isNonEmptyString(element)) {
      throw new Error(`policy: ${listName}[${index}] must be a non-empty string`);
    }
  });

  return [...rawList];
}

/**
 * Normalizes an allowlisted path entry to an absolute, normalized form so
 * later containment checks operate on a canonical representation.
 *
 * @param {string} rawPath
 * @returns {string}
 */
function normalizeAllowedPath(rawPath) {
  return path.normalize(path.resolve(rawPath));
}

/**
 * Validates and normalizes a raw policy config object (already parsed from
 * YAML/JSON by the caller) into the canonical in-memory structure consumed
 * by createPolicyEngine.
 *
 * @param {object} rawConfigObject
 * @returns {{
 *   allowedCommands: Map<string, { argv: string[] }>,
 *   allowedPaths: string[],
 *   allowedCaEndpoints: string[],
 *   allowedDnsZones: string[],
 *   allowedDnsProviders: string[],
 * }}
 */
function loadPolicyConfig(rawConfigObject) {
  if (
    rawConfigObject === null ||
    typeof rawConfigObject !== "object" ||
    Array.isArray(rawConfigObject)
  ) {
    throw new Error("policy: policy config must be an object");
  }

  const rawCommands = rawConfigObject.allowedCommands;
  const allowedCommands = new Map();

  if (rawCommands !== undefined) {
    if (
      rawCommands === null ||
      typeof rawCommands !== "object" ||
      Array.isArray(rawCommands)
    ) {
      throw new Error(
        "policy: allowedCommands must be an object mapping profile name -> { argv }",
      );
    }

    for (const [name, rawProfile] of Object.entries(rawCommands)) {
      allowedCommands.set(name, validateCommandProfile(name, rawProfile));
    }
  }

  const allowedPaths = validateStringList(
    "allowedPaths",
    rawConfigObject.allowedPaths,
  ).map(normalizeAllowedPath);

  const allowedCaEndpoints = validateStringList(
    "allowedCaEndpoints",
    rawConfigObject.allowedCaEndpoints,
  );

  const allowedDnsZones = validateStringList(
    "allowedDnsZones",
    rawConfigObject.allowedDnsZones,
  );

  const allowedDnsProviders = validateStringList(
    "allowedDnsProviders",
    rawConfigObject.allowedDnsProviders,
  );

  const allowedVerifyHosts = validateStringList(
    "allowedVerifyHosts",
    rawConfigObject.allowedVerifyHosts,
  );

  return {
    allowedCommands,
    allowedPaths,
    allowedCaEndpoints,
    allowedDnsZones,
    allowedDnsProviders,
    allowedVerifyHosts,
  };
}

/**
 * @param {string} detail
 * @param {string} rejectionReason
 * @returns {{ allowed: false, rejectionReason: string, detail: string }}
 */
function reject(rejectionReason, detail) {
  return { allowed: false, rejectionReason, detail };
}

/**
 * Removes a trailing slash from a URL string for comparison purposes only
 * (does not otherwise touch the URL).
 *
 * @param {string} value
 * @returns {string}
 */
function stripTrailingSlash(value) {
  return value.endsWith("/") ? value.slice(0, -1) : value;
}

/**
 * Segment-aware containment check: is `candidate` equal to, or nested
 * inside, `allowedRoot`? Rejects lexical sibling-prefix collisions such as
 * `/etc/nginx/tls-evil` against an allowlist entry of `/etc/nginx/tls`
 * (a naive startsWith check would incorrectly allow that).
 *
 * @param {string} candidate normalized absolute path
 * @param {string} allowedRoot normalized absolute path
 * @returns {boolean}
 */
function isPathContainedIn(candidate, allowedRoot) {
  if (candidate === allowedRoot) {
    return true;
  }

  const relative = path.relative(allowedRoot, candidate);

  // path.relative returns a string starting with ".." (e.g. "..", "../x")
  // when candidate is not inside allowedRoot, and an absolute path when the
  // two are on different drives/roots (Windows). Neither case is
  // containment.
  return (
    relative !== "" &&
    relative !== ".." &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
}

/**
 * Suffix-with-dot-boundary DNS zone match: `zone` is covered by
 * `allowedZone` if they are equal, or if `zone` ends with `.${allowedZone}`
 * (so `sub.example.com` is covered by `example.com`, but `evilexample.com`
 * is not -- a naive substring/endsWith("example.com") check would wrongly
 * allow that).
 *
 * @param {string} zone
 * @param {string} allowedZone
 * @returns {boolean}
 */
function isZoneCoveredBy(zone, allowedZone) {
  const normalizedZone = zone.toLowerCase();
  const normalizedAllowed = allowedZone.toLowerCase();
  return (
    normalizedZone === normalizedAllowed ||
    normalizedZone.endsWith(`.${normalizedAllowed}`)
  );
}

/**
 * Classifies a verify destination host for the checkVerifyHost dimension.
 *
 * Returns one of:
 *   "denied"    -- never probeable, regardless of any allowlist: the
 *                  unspecified addresses, IPv4/IPv6 link-local (which
 *                  includes every cloud metadata endpoint such as
 *                  169.254.169.254), multicast, and broadcast. There is no
 *                  legitimate TLS certificate deployment on these.
 *   "loopback"  -- 127.0.0.0/8, ::1, and localhost names. Probing the
 *                  agent's own host CAN be legitimate (a local nginx), but
 *                  only when the operator explicitly allowlists it.
 *   "ordinary"  -- everything else (public/private IPs and hostnames).
 *
 * IPv4-mapped IPv6 (::ffff:a.b.c.d) is unwrapped and classified as its
 * embedded IPv4 address so the mapping cannot bypass the deny list.
 *
 * @param {string} host
 * @returns {"denied"|"loopback"|"ordinary"}
 */
function classifyVerifyHost(host) {
  // Bare IPv6 in URL-style brackets: strip for classification.
  const bare = host.startsWith("[") && host.endsWith("]")
    ? host.slice(1, -1)
    : host;
  const lowered = bare.toLowerCase();

  const ipVersion = net.isIP(lowered);
  if (ipVersion === 4) {
    const octets = lowered.split(".").map(Number);
    if (octets[0] === 127) return "loopback";
    if (octets[0] === 0) return "denied"; // 0.0.0.0/8 unspecified
    if (octets[0] === 169 && octets[1] === 254) return "denied"; // link-local / metadata
    if (octets[0] >= 224) return "denied"; // multicast + reserved + broadcast
    return "ordinary";
  }
  if (ipVersion === 6) {
    // IPv4-mapped: classify the embedded IPv4 address.
    const mappedMatch = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lowered);
    if (mappedMatch) return classifyVerifyHost(mappedMatch[1]);
    if (lowered === "::" || lowered === "0:0:0:0:0:0:0:0") return "denied";
    if (lowered === "::1" || lowered === "0:0:0:0:0:0:0:1") return "loopback";
    if (/^fe[89ab]/.test(lowered)) return "denied"; // fe80::/10 link-local
    if (lowered.startsWith("ff")) return "denied"; // ff00::/8 multicast
    return "ordinary";
  }

  if (lowered === "localhost" || lowered.endsWith(".localhost")) {
    return "loopback";
  }
  return "ordinary";
}

/**
 * Creates a policy engine bound to a canonical policy config (as produced
 * by loadPolicyConfig) and an optional declared target scope.
 *
 * @param {ReturnType<typeof loadPolicyConfig>} policyConfig
 * @param {{ declaredTargetSelectors?: string[] }} [options]
 */
function createPolicyEngine(policyConfig, { declaredTargetSelectors = [] } = {}) {
  const declaredTargetSelectorSet = new Set(declaredTargetSelectors);

  /**
   * @param {string} commandRef
   * @returns {{ allowed: true, argv: string[] } | ReturnType<typeof reject>}
   */
  function checkCommandRef(commandRef) {
    const profile = policyConfig.allowedCommands.get(commandRef);

    if (!profile) {
      return reject(
        REJECTION_REASONS.COMMAND_NOT_ALLOWLISTED,
        `Command reference "${commandRef}" is not present in the agent-local command allowlist.`,
      );
    }

    return { allowed: true, argv: [...profile.argv] };
  }

  /**
   * @param {string} candidatePath
   * @returns {{ allowed: true } | ReturnType<typeof reject>}
   */
  function checkPath(candidatePath) {
    const normalizedCandidate = path.normalize(path.resolve(candidatePath));

    const isAllowed = policyConfig.allowedPaths.some((allowedRoot) =>
      isPathContainedIn(normalizedCandidate, allowedRoot),
    );

    if (!isAllowed) {
      return reject(
        REJECTION_REASONS.PATH_NOT_ALLOWLISTED,
        `Path "${candidatePath}" is not contained within any allowlisted path.`,
      );
    }

    return { allowed: true };
  }

  /**
   * Exact-match check against allowedCaEndpoints, after normalizing
   * trailing slashes on both sides.
   *
   * ACME directory URLs are meaningfully identified by their full path
   * (e.g. "/directory" is part of the CA's identity, not incidental), so
   * an origin-only comparison would be too permissive: it would let a
   * job/CA endpoint reuse the same host but a different, unreviewed path.
   * Exact full-URL match (mod trailing slash) is the simplest rule that is
   * still defensible for the CertOps agent's small, curated CA allowlist,
   * so that is what this check implements.
   *
   * @param {string} url
   * @returns {{ allowed: true } | ReturnType<typeof reject>}
   */
  function checkCaEndpoint(url) {
    let normalizedCandidate;
    try {
      normalizedCandidate = stripTrailingSlash(new URL(url).toString());
    } catch {
      return reject(
        REJECTION_REASONS.CA_ENDPOINT_NOT_ALLOWLISTED,
        `CA endpoint "${url}" is not a valid URL.`,
      );
    }

    const isAllowed = policyConfig.allowedCaEndpoints.some((allowedEndpoint) => {
      let normalizedAllowed;
      try {
        normalizedAllowed = stripTrailingSlash(new URL(allowedEndpoint).toString());
      } catch {
        return false;
      }
      return normalizedAllowed === normalizedCandidate;
    });

    if (!isAllowed) {
      return reject(
        REJECTION_REASONS.CA_ENDPOINT_NOT_ALLOWLISTED,
        `CA endpoint "${url}" is not present in the agent-local CA endpoint allowlist.`,
      );
    }

    return { allowed: true };
  }

  /**
   * @param {string} zone
   * @returns {{ allowed: true } | ReturnType<typeof reject>}
   */
  function checkDnsZone(zone) {
    const isAllowed = policyConfig.allowedDnsZones.some((allowedZone) =>
      isZoneCoveredBy(zone, allowedZone),
    );

    if (!isAllowed) {
      return reject(
        REJECTION_REASONS.DNS_ZONE_NOT_ALLOWLISTED,
        `DNS zone "${zone}" is not covered by any allowlisted DNS zone.`,
      );
    }

    return { allowed: true };
  }

  /**
   * Exact match against allowedDnsProviders.
   *
   * @param {string} providerName
   * @returns {{ allowed: true } | ReturnType<typeof reject>}
   */
  function checkDnsProvider(providerName) {
    const isAllowed = policyConfig.allowedDnsProviders.includes(providerName);

    if (!isAllowed) {
      return reject(
        REJECTION_REASONS.DNS_PROVIDER_NOT_ALLOWLISTED,
        `DNS provider "${providerName}" is not present in the agent-local DNS provider allowlist.`,
      );
    }

    return { allowed: true };
  }

  /**
   * Verify-destination authorization for the post-deploy live probe.
   *
   * A signed job's verifyHost/verifyPort direct the agent to open a TLS
   * connection, so the destination must be authorized agent-locally like
   * every other job-controlled reference (ADR-0002: agent-local policy
   * always wins over control-plane intent). Decision order:
   *
   *   1. hard deny (never probeable, regardless of allowlists): the
   *      unspecified addresses, IPv4/IPv6 link-local (including cloud
   *      metadata endpoints such as 169.254.169.254), multicast/broadcast;
   *   2. loopback (127/8, ::1, localhost): allowed only when explicitly
   *      present in allowedVerifyHosts;
   *   3. otherwise allowed when the host equals the job's own
   *      target.reference (case-insensitive; verifying the domain being
   *      renewed is the normal case and needs no extra config), or when it
   *      is covered by allowedVerifyHosts (exact match for IPs,
   *      dot-boundary suffix match for hostnames, same semantics as DNS
   *      zone coverage).
   *
   * Uses the target_out_of_scope rejection reason: the destination is
   * outside this agent's authorized verification scope.
   *
   * @param {string} host verify destination from the job
   * @param {{ targetReference?: string }} [context]
   * @returns {{ allowed: true } | ReturnType<typeof reject>}
   */
  function checkVerifyHost(host, { targetReference } = {}) {
    if (!isNonEmptyString(host) || host.length > 255) {
      return reject(
        REJECTION_REASONS.TARGET_OUT_OF_SCOPE,
        "Verify destination host must be a non-empty string of at most 255 characters.",
      );
    }

    const classification = classifyVerifyHost(host);
    if (classification === "denied") {
      return reject(
        REJECTION_REASONS.TARGET_OUT_OF_SCOPE,
        `Verify destination "${host}" is a link-local, unspecified, or ` +
          "multicast address and can never be probed (metadata-endpoint " +
          "class destinations are always denied).",
      );
    }

    const loweredHost = host.toLowerCase();
    const allowlisted = policyConfig.allowedVerifyHosts.some((allowedHost) => {
      const loweredAllowed = allowedHost.toLowerCase();
      if (loweredAllowed === loweredHost) return true;
      // Hostname entries also cover subdomains at a dot boundary; IP
      // entries only ever match exactly (net.isIP guards the suffix rule).
      return (
        net.isIP(loweredAllowed) === 0 &&
        net.isIP(loweredHost) === 0 &&
        isZoneCoveredBy(loweredHost, loweredAllowed)
      );
    });

    if (classification === "loopback") {
      if (allowlisted) return { allowed: true };
      return reject(
        REJECTION_REASONS.TARGET_OUT_OF_SCOPE,
        `Verify destination "${host}" is a loopback address, which is only ` +
          "probeable when explicitly present in allowedVerifyHosts.",
      );
    }

    if (
      isNonEmptyString(targetReference) &&
      targetReference.toLowerCase() === loweredHost
    ) {
      return { allowed: true };
    }
    if (allowlisted) return { allowed: true };

    return reject(
      REJECTION_REASONS.TARGET_OUT_OF_SCOPE,
      `Verify destination "${host}" neither matches the job's target ` +
        "reference nor any allowedVerifyHosts entry.",
    );
  }

  /**
   * Exact-match check against the declared target selectors. Selector
   * *pattern* matching (globs, wildcards, etc.), if ever needed, is out of
   * scope for the agent bootstrap and is left as a future extension.
   *
   * @param {string} targetSelector
   * @returns {{ allowed: true } | ReturnType<typeof reject>}
   */
  function checkTargetScope(targetSelector) {
    if (!declaredTargetSelectorSet.has(targetSelector)) {
      return reject(
        REJECTION_REASONS.TARGET_OUT_OF_SCOPE,
        `Target selector "${targetSelector}" is not in this agent's declared target scope.`,
      );
    }

    return { allowed: true };
  }

  /**
   * Rejects unconditionally whenever `jobIntent.requestsKeyExport` is true,
   * regardless of any other flags on `jobIntent` or any policy config. This
   * check can never be overridden or bypassed by allowlist configuration:
   * there is no config knob anywhere in this module that permits key
   * export. Matches the rejection table entry "key export
   * requested (always)".
   *
   * @param {{ requestsKeyExport?: boolean }} jobIntent
   * @returns {{ allowed: true } | ReturnType<typeof reject>}
   */
  function checkNoKeyExport(jobIntent) {
    if (jobIntent && jobIntent.requestsKeyExport === true) {
      return reject(
        REJECTION_REASONS.KEY_EXPORT_REQUESTED,
        "Job intent requests private key export/material extraction, which is never permitted.",
      );
    }

    return { allowed: true };
  }

  /**
   * Runs the applicable subset of checks against a job descriptor and
   * returns the first rejection encountered, or { allowed: true } if every
   * applicable check passes.
   *
   * Check order (fixed, documented here rather than left to call-site
   * ordering):
   *   1. checkNoKeyExport -- always run first: it can never be overridden
   *      by any other config, so it must never be shadowed by an earlier
   *      "allowed" result from a different check.
   *   2. checkTargetScope -- a job outside declared scope should never even
   *      be evaluated against command/path/CA/DNS allowlists.
   *   3. checkCommandRef
   *   4. checkPath
   *   5. checkCaEndpoint
   *   6. checkDnsZone
   *   7. checkDnsProvider
   *
   * Each step only runs if the corresponding field is present on
   * `jobDescriptor`.
   *
   * @param {{
   *   requestsKeyExport?: boolean,
   *   targetSelector?: string,
   *   commandRef?: string,
   *   path?: string,
   *   caEndpoint?: string,
   *   dnsZone?: string,
   *   dnsProvider?: string,
   * }} jobDescriptor
   * @returns {{ allowed: true } | ReturnType<typeof reject>}
   */
  function evaluateJob(jobDescriptor) {
    const keyExportResult = checkNoKeyExport(jobDescriptor);
    if (!keyExportResult.allowed) {
      return keyExportResult;
    }

    if (jobDescriptor.targetSelector !== undefined) {
      const result = checkTargetScope(jobDescriptor.targetSelector);
      if (!result.allowed) {
        return result;
      }
    }

    if (jobDescriptor.commandRef !== undefined) {
      const result = checkCommandRef(jobDescriptor.commandRef);
      if (!result.allowed) {
        return result;
      }
    }

    if (jobDescriptor.path !== undefined) {
      const result = checkPath(jobDescriptor.path);
      if (!result.allowed) {
        return result;
      }
    }

    if (jobDescriptor.caEndpoint !== undefined) {
      const result = checkCaEndpoint(jobDescriptor.caEndpoint);
      if (!result.allowed) {
        return result;
      }
    }

    if (jobDescriptor.dnsZone !== undefined) {
      const result = checkDnsZone(jobDescriptor.dnsZone);
      if (!result.allowed) {
        return result;
      }
    }

    if (jobDescriptor.dnsProvider !== undefined) {
      const result = checkDnsProvider(jobDescriptor.dnsProvider);
      if (!result.allowed) {
        return result;
      }
    }

    return { allowed: true };
  }

  return {
    checkCommandRef,
    checkPath,
    checkCaEndpoint,
    checkDnsZone,
    checkDnsProvider,
    checkVerifyHost,
    checkTargetScope,
    checkNoKeyExport,
    evaluateJob,
  };
}

module.exports = {
  loadPolicyConfig,
  createPolicyEngine,
  REJECTION_REASONS,
  SHELL_METACHARACTER_PATTERN,
};
