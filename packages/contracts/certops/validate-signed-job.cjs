"use strict";

/**
 * Discriminated-union validator selecting between job-payload.schema.json
 * (certificate lifecycle actions) and protocol-smoke-payload.schema.json
 * (the diagnostic-only protocol_smoke action), keyed on the payload's own
 * "action" field (ADR-0012 decision 3).
 *
 * WHY a discriminated union rather than one relaxed schema: job-payload.
 * schema.json requires certificateId/target/keyMode (all about certificate
 * custody), and a protocol_smoke job deliberately has none of them. Adding a
 * bare required key to job-payload.schema.json to admit smoke jobs would
 * weaken certificate validation to admit a shape that carries no certificate;
 * relaxing job-payload's required array would weaken it for every existing
 * certificate job. Instead each action family keeps its own schema, and this
 * module is the single place that decides which one applies -- so a smoke
 * job is never validated against the certificate schema and vice versa.
 *
 * SINGLE SOURCE OF TRUTH shared by BOTH sides of the signature boundary in
 * spirit (mirroring canonical-json.cjs's pattern): the control plane and any
 * future agent-side strict validator should both resolve "which schema does
 * this action use" through this module rather than re-deriving the mapping
 * ad hoc, so the two action families cannot silently drift apart.
 *
 * NOTE on the .cjs extension: packages/contracts/package.json declares
 * "type": "module", so this module ships as .cjs to stay requireable from
 * the CommonJS API service, matching canonical-json.cjs.
 *
 * SCOPE: this module validates a SIGNED PAYLOAD -- the fields that were
 * signed -- not a wire wrapper. For v1 the two coincide on the wire (the
 * per-action schemas also carry the wrapper's signature field), but for v2
 * the caller validates the wrapper against signed-dispatch-wire-v2.schema.
 * json, verifies payloadB64's bytes, and only then hands the DECODED payload
 * here. The wrapper schemas are registered with Ajv below so a caller can
 * resolve them by $id through this module's Ajv instance rather than building
 * a second one.
 */

const JOB_PAYLOAD_SCHEMA = require("./job-payload.schema.json");
const PROTOCOL_SMOKE_PAYLOAD_SCHEMA = require("./protocol-smoke-payload.schema.json");
const SIGNED_DISPATCH_PAYLOAD_SCHEMA = require("./signed-dispatch-payload.schema.json");
const SIGNED_DISPATCH_WIRE_V1_SCHEMA = require("./signed-dispatch-wire-v1.schema.json");
const SIGNED_DISPATCH_WIRE_V2_SCHEMA = require("./signed-dispatch-wire-v2.schema.json");

// Certificate lifecycle actions from job-payload.schema.json's own "action"
// enum, duplicated here ONLY as the discriminator's action->schema routing
// key (not as a second copy of the field's validation rules, which stay
// owned by job-payload.schema.json itself).
const CERTIFICATE_ACTIONS = Object.freeze([
  "renew",
  "deploy",
  "reload",
  "revoke",
  "noop",
]);
const PROTOCOL_SMOKE_ACTION = "protocol_smoke";

let ajvInstance = null;

/**
 * Lazily constructs a shared Ajv instance with both per-action schemas and
 * the cross-file-referenced envelope definition registered. Ajv and
 * ajv-formats are required lazily (not at module load) so a caller that only
 * wants selectSchemaForAction() (no actual validation) never pays for Ajv's
 * compile step or needs it installed.
 */
function getAjv() {
  if (ajvInstance) return ajvInstance;

  // eslint-disable-next-line global-require -- see doc comment above
  const Ajv = require("ajv");
  // eslint-disable-next-line global-require
  const addFormats = require("ajv-formats");

  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  ajv.addSchema(SIGNED_DISPATCH_PAYLOAD_SCHEMA);
  ajv.addSchema(SIGNED_DISPATCH_WIRE_V1_SCHEMA);
  ajv.addSchema(SIGNED_DISPATCH_WIRE_V2_SCHEMA);
  ajv.addSchema(JOB_PAYLOAD_SCHEMA);
  ajv.addSchema(PROTOCOL_SMOKE_PAYLOAD_SCHEMA);

  ajvInstance = ajv;
  return ajvInstance;
}

/**
 * Selects which schema applies to a given "action" value.
 *
 * @param {unknown} action
 * @returns {{ schema: object, schemaId: string } | null} null when the
 *   action matches neither family (the caller should treat that as its own
 *   validation failure; this module does not invent a rejection reason).
 */
function selectSchemaForAction(action) {
  if (typeof action !== "string") return null;
  if (action === PROTOCOL_SMOKE_ACTION) {
    return {
      schema: PROTOCOL_SMOKE_PAYLOAD_SCHEMA,
      schemaId: PROTOCOL_SMOKE_PAYLOAD_SCHEMA.$id,
    };
  }
  if (CERTIFICATE_ACTIONS.includes(action)) {
    return { schema: JOB_PAYLOAD_SCHEMA, schemaId: JOB_PAYLOAD_SCHEMA.$id };
  }
  return null;
}

/**
 * Validates an untrusted job payload against whichever schema its "action"
 * field selects. Never throws on malformed input; an unrecognized or absent
 * action is reported as a validation error rather than a thrown exception,
 * since this runs on untrusted, pre-verification data in some callers.
 *
 * @param {unknown} job
 * @returns {{ valid: boolean, schemaId: string|null, errors: Array<object>|null }}
 */
function validateSignedJob(job) {
  const action =
    job && typeof job === "object" && !Array.isArray(job)
      ? job.action
      : undefined;
  const selection = selectSchemaForAction(action);

  if (!selection) {
    return {
      valid: false,
      schemaId: null,
      errors: [
        {
          message:
            typeof action === "string"
              ? `unrecognized action "${action}": matches neither the certificate ` +
                `action family (${CERTIFICATE_ACTIONS.join(", ")}) nor "${PROTOCOL_SMOKE_ACTION}"`
              : "job.action is missing or not a string; cannot select a schema",
        },
      ],
    };
  }

  const ajv = getAjv();
  const validateFn = ajv.getSchema(selection.schemaId);
  if (!validateFn) {
    throw new Error(
      `validate-signed-job: schema "${selection.schemaId}" was not registered ` +
        "with Ajv; this is a programmer error, not an untrusted-input problem",
    );
  }

  const valid = validateFn(job);
  return {
    valid,
    schemaId: selection.schemaId,
    errors: valid ? null : validateFn.errors,
  };
}

module.exports = {
  CERTIFICATE_ACTIONS,
  PROTOCOL_SMOKE_ACTION,
  selectSchemaForAction,
  validateSignedJob,
  _test: {
    getAjv,
    JOB_PAYLOAD_SCHEMA,
    PROTOCOL_SMOKE_PAYLOAD_SCHEMA,
    SIGNED_DISPATCH_PAYLOAD_SCHEMA,
    SIGNED_DISPATCH_WIRE_V1_SCHEMA,
    SIGNED_DISPATCH_WIRE_V2_SCHEMA,
  },
};
