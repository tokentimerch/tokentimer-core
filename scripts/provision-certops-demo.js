"use strict";

// Provisions demo CertOps data against a running dev API server:
//   - imports several public certificates into a workspace
//   - creates several scoped machine API tokens
//   - creates several certificate jobs and drives them through the
//     executor HTTP routes (lifecycle events + evidence) as a fake
//     executor would.
//
// Usage:
//   node scripts/provision-certops-demo.js
//
// Requires a dev server already running (pnpm dev) with CERTOPS_ENABLED=true
// and ADMIN_EMAIL / ADMIN_PASSWORD set (see .env). Talks over plain HTTP
// using fetch + a cookie jar for the session-authenticated admin routes,
// and Bearer tokens for the executor routes. Job creation connects directly
// to Postgres (same as tests/integration/fake-executor.js) since there is
// no session-authenticated HTTP route to create a job.

const { loadRootEnv } = require("./load-root-env");
loadRootEnv();

const crypto = require("crypto");

const API_URL = process.env.API_URL || "http://localhost:4000";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@localhost.local";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "AdminPassword123!";
const WORKSPACE_NAME =
  process.env.CERTOPS_DEMO_WORKSPACE_NAME || "CertOps Demo Workspace";

// --- Minimal cookie jar so session cookies survive across fetch() calls ---
class CookieJar {
  constructor() {
    this.cookies = new Map();
  }

  storeFromResponse(response) {
    const setCookie =
      typeof response.headers.getSetCookie === "function"
        ? response.headers.getSetCookie()
        : response.headers.raw?.()["set-cookie"] || [];
    for (const raw of setCookie) {
      const [pair] = raw.split(";");
      const eqIndex = pair.indexOf("=");
      if (eqIndex === -1) continue;
      const name = pair.slice(0, eqIndex).trim();
      const value = pair.slice(eqIndex + 1).trim();
      this.cookies.set(name, value);
    }
  }

  header() {
    return Array.from(this.cookies.entries())
      .map(([name, value]) => `${name}=${value}`)
      .join("; ");
  }
}

async function apiFetch(jar, path, { method = "GET", body, headers = {} } = {}) {
  const response = await fetch(`${API_URL}${path}`, {
    method,
    headers: {
      "Content-Type": "application/json",
      Cookie: jar.header(),
      ...headers,
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  jar.storeFromResponse(response);

  const text = await response.text();
  let json = null;
  if (text) {
    try {
      json = JSON.parse(text);
    } catch (_err) {
      json = { raw: text };
    }
  }

  if (!response.ok) {
    const error = new Error(
      `${method} ${path} failed: ${response.status} ${JSON.stringify(json)}`,
    );
    error.status = response.status;
    error.body = json;
    throw error;
  }

  return json;
}

// --- Auth / workspace bootstrap ---

async function login(jar) {
  await apiFetch(jar, "/auth/login", {
    method: "POST",
    body: { email: ADMIN_EMAIL, password: ADMIN_PASSWORD },
  });
  console.log(`[auth] logged in as ${ADMIN_EMAIL}`);
}

async function ensureWorkspace(jar) {
  const { items } = await apiFetch(jar, "/api/v1/workspaces");
  const existing = items.find((w) => w.name === WORKSPACE_NAME);
  if (existing) {
    console.log(`[workspace] reusing "${existing.name}" (${existing.id})`);
    return existing.id;
  }

  const created = await apiFetch(jar, "/api/v1/workspaces", {
    method: "POST",
    body: { name: WORKSPACE_NAME },
  });
  console.log(`[workspace] created "${WORKSPACE_NAME}" (${created.id})`);
  return created.id;
}

// --- Certificates ---
// Fixed set of distinct self-signed public certificate PEMs (generated with
// the `selfsigned` package, 2048-bit RSA, SAN = commonName, 2-year validity).
// Public certs only; no private key material is embedded here.
const DEMO_CERTIFICATES = [
  {
    name: "seed-01.tokentimer.test",
    pem: "-----BEGIN CERTIFICATE-----\nMIIC7TCCAdWgAwIBAgIJadAv5Xs7aTqVMA0GCSqGSIb3DQEBBQUAMCIxIDAeBgNV\nBAMTF3NlZWQtMDEudG9rZW50aW1lci50ZXN0MB4XDTI2MDcxNjE2MzUwMFoXDTI3\nMDcxNjE2MzUwMFowIjEgMB4GA1UEAxMXc2VlZC0wMS50b2tlbnRpbWVyLnRlc3Qw\nggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDWpFC++sZ/BiBeDdPg/C1x\ney++BZv5CEZaaePgaleFKfj2nF+lvN0AVLclucYfHkZq/vDiO/Z/hQhQrqhPxES0\npcShckCDeApwTeMKh+0AsDf+sZ/4KzQuBJ4aMDIWxmM1w89zYNrx0oHQFi7KK3nE\n9o7wTGg32ihKqJUG/0QUniJwfXufR89bLpamFdUBRJ8SHW71dPkEUlctSjkl3nLs\nNz6I9H2fWDPYeExTQr23Rcty7hKx+ysd7B+9la9AU5H7TPnTTHRiE1KOcSGxB3jJ\nThBq/Ft0cYyey469yO9NiFdX+rEPzv5kFpEcWB6od0pgui/U8QXZqKxg0M04rTRx\nAgMBAAGjJjAkMCIGA1UdEQQbMBmCF3NlZWQtMDEudG9rZW50aW1lci50ZXN0MA0G\nCSqGSIb3DQEBBQUAA4IBAQCbUXMODVZp+tQw/XvzgA1ZbQ293g8g9DHZEiPr5fkb\n8DNJsS5hRshVO5brESLSOnYWTKgKdWX03zPCj5GsEN+MFv7+EqgKDR/Bjx3thfXq\ngfzByeXqpCbonNSu2pdqT/+fiuDVOl9k+ir13NNHugrbSxNX2Zgwld4lQ4swAE9d\nK+PDn+UvYne5n6w4vLDlzdAJhOTYGDV5Mib2+vUnZw66ypEGIeC6TVCvK5I/R/xL\n0LoVFiGndw44f/iDbMxW40GT/94/z2cqO3gdZ/sbFXIRDLxL0pZQbSDxXXpWWSvu\nOBF9nkPN5wV+LxDl6V+G6oZ4Bi05kB7vLdQvnearxTZo\n-----END CERTIFICATE-----",
  },
  {
    name: "seed-02.tokentimer.test",
    pem: "-----BEGIN CERTIFICATE-----\nMIIC7TCCAdWgAwIBAgIJE+X/06dCIWNwMA0GCSqGSIb3DQEBBQUAMCIxIDAeBgNV\nBAMTF3NlZWQtMDIudG9rZW50aW1lci50ZXN0MB4XDTI2MDcxNjE2MzUwMFoXDTI3\nMDcxNjE2MzUwMFowIjEgMB4GA1UEAxMXc2VlZC0wMi50b2tlbnRpbWVyLnRlc3Qw\nggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCZ16vvRFqUfq8FcWqFQqQ7\nb0PSkQg9jYQDWQbQF2sr2efZ0k1MQJbIEXlU4IsvSIrqwhHhoEmR3kRuK91+L5e1\nW+4+Usxv7I2jXbcBFiQ+g061iKhSrkyPsIQ75fZyv/O3EAql8i4lbjWJtvYO6CHP\n0oP2+tCpv5UInk0fHZHx1oxSS2hrljDkkVfkPV+Sym530y0JeXP5QfSpy8YHB0NG\n6f4BnNyoihsn7VY0bGis9YKcHbcfybatQ09yQCyezlLPp68+TEHE6ssHi58fb2en\njMwGfteikRh4ncwkpFOdbjJFoB15zwvCfn3gLSWgYIxJ/v0i7A3jh/kfOkry1u51\nAgMBAAGjJjAkMCIGA1UdEQQbMBmCF3NlZWQtMDIudG9rZW50aW1lci50ZXN0MA0G\nCSqGSIb3DQEBBQUAA4IBAQA6zhXgP5/mVgDtU1lhZwvW3w9GfJp0+4DBNWQ4RYJO\nHLv3mL5+n1UiHw42l/pd9XXQqvhO/5E8Yn4rU4toNC+MAeIJ6MT/+tP/61GjcUqe\n6KXGErUvzjizCr3YehibQ9FMzz8ez9RvZh6FOe3Py4C9sEQRmlSgNEZUQuHnVHsJ\nBUR0saSEsyQjD5CRf0y4Usnddwow+EWTy0EP3wssu0G2jM01IWNnAg42tYSSwtU3\nc3FqykUdGp5E6QKsVaJDEdAblaqxe1r8e0qnjVpgQkBOIHyYlGI/a0kkHsKZwIJh\nyJG1BOsYCJ1WrduytPxVtDZQWMWCmxYmJyXwANOaT8cY\n-----END CERTIFICATE-----",
  },
  {
    name: "seed-03.tokentimer.test",
    pem: "-----BEGIN CERTIFICATE-----\nMIIC7TCCAdWgAwIBAgIJTzJyrBeqv8BCMA0GCSqGSIb3DQEBBQUAMCIxIDAeBgNV\nBAMTF3NlZWQtMDMudG9rZW50aW1lci50ZXN0MB4XDTI2MDcxNjE2MzUwMFoXDTI3\nMDcxNjE2MzUwMFowIjEgMB4GA1UEAxMXc2VlZC0wMy50b2tlbnRpbWVyLnRlc3Qw\nggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDJNfVd90M8bVInQdvsBT6+\noQxiHc082NFMXiOsP8cSpFVC4n0uyAxwUDt08DsK7uz/gVI/QJWnm/8UrRD1YFDU\nDBQFbix+xTpIoQlDm9MdMFdNXsWvHZpD1gOsFdxlfecM64aPF5Z+E5b4++LcInoY\nOwwKJdGG/oIa28X+/9rYUrsWAtsnusE+cFdZDHGns99P2GePRw/vOUhe1RiEk+ci\nczj+sdKrEkcEqnoGJ/sJb4oBtH81Ess/r2ic3xgc9HA0KKpEfur9pgyzNqLDMYD6\n8sMGWuzTF4Bbnq0Qy6UBj0MKiA2CUVvxnXNViK0+ncMSRCDeGk+whQncyyyDfkXf\nAgMBAAGjJjAkMCIGA1UdEQQbMBmCF3NlZWQtMDMudG9rZW50aW1lci50ZXN0MA0G\nCSqGSIb3DQEBBQUAA4IBAQCpReSmw4faS5yuPIqrFsZC/JE2QWHgqU3eS4SzpqcH\nDhXDxIKjXyx4I2rQ0WNpGEJMtxvgcajw/x5w03NscNTR5nZG7EhzdXLmd1YQtSgi\nbAaxEnxFwmHluxM4B3hmB7tQK/KeNOQU+P2c+1IX3L/0kBoxbVtU5d98+dXmvtuG\nTB8om5oUmvHcwCW7gg0cqQ/QPq/v5UzWp1T3h1bkvj8NfEtbs8s+9bUg04nPGSz4\npo8lfZN4+wudnDxdR5FalyZCmI3BNxu71bc2bTXkEPXp5khxzUgxeQ+5goCC1oE0\nmYftRRV3WguocA91EhdNM3OegEm03rz66zkl35urZ53o\n-----END CERTIFICATE-----",
  },
  {
    name: "seed-04.tokentimer.test",
    pem: "-----BEGIN CERTIFICATE-----\nMIIC7TCCAdWgAwIBAgIJXGCORKrNHqn1MA0GCSqGSIb3DQEBBQUAMCIxIDAeBgNV\nBAMTF3NlZWQtMDQudG9rZW50aW1lci50ZXN0MB4XDTI2MDcxNjE2MzUwMFoXDTI3\nMDcxNjE2MzUwMFowIjEgMB4GA1UEAxMXc2VlZC0wNC50b2tlbnRpbWVyLnRlc3Qw\nggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8bClOZlKbi43PKR0lrwq2\nlu4eyz2CT8b0e0m4k/7GjFLzMc9VV2t+YiZjyyycCEDHx0miMN3lqnxOtHfeq4Ke\no7agFVhs3GPRvb6Va4zBs20eJUtHb40X71hwbDk3/PaVLNn1KQXS3uED8BYUTsuH\nSv8pz+z/s1oUB/LcjGYNNPGrXUz1qX0wO/v0Mj9HVIveE2M3/qnpO8GEj7hTL0rJ\nxbfabHkvJQ20LAnpgh7xuwETZQnRfHyXBmDs0yck6Q0jCY/JlYgXuxUSUy7HZDC4\noCVbO0peaz+W9pwgLBeMkXUwC0ERDPI/xQROF0Q4XV9EFrYLC8eWo2upUccOfeyj\nAgMBAAGjJjAkMCIGA1UdEQQbMBmCF3NlZWQtMDQudG9rZW50aW1lci50ZXN0MA0G\nCSqGSIb3DQEBBQUAA4IBAQB9pyz/mshpDpgnnx2kNr5+DCybqYnyQwv+fN1FW+pz\nXJQWnr4zmFaVvgCsBHp9TejiMpnHd0RvIXaRdDH0rVZnVgdUkPywB879JGHAx0bf\nrwqslohXS8OE5MruZy9gkPb2//SHjoBQANOXHvoQcs6ZTTjiRLZ22MW9zEV5AMPO\nypcsZAt7GIurpu8f2mbFSd7sB08SkfLKmdgn9Wghc+aLCjHdfCt5nLzVc98J3vc0\nkPybs8HUl4GVzGKDarAqKM1nIwA+9CgNykAsuSy6VvOPh9BVyU1j6s3iJQV/TGoj\nP4ltjT7niAvcHk+DWo4WNt4Vx5YqYgHbveAZv8CIafqF\n-----END CERTIFICATE-----",
  },
  {
    name: "seed-05.tokentimer.test",
    pem: "-----BEGIN CERTIFICATE-----\nMIIC7TCCAdWgAwIBAgIJaLYXVheA5vcHMA0GCSqGSIb3DQEBBQUAMCIxIDAeBgNV\nBAMTF3NlZWQtMDUudG9rZW50aW1lci50ZXN0MB4XDTI2MDcxNjE2MzUwMFoXDTI3\nMDcxNjE2MzUwMFowIjEgMB4GA1UEAxMXc2VlZC0wNS50b2tlbnRpbWVyLnRlc3Qw\nggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDO0Xd2v6VoJyXWttbv8TML\nMLsGa4YYK1jc0Vesw23CD20PQqk5k/eTuj5wpq/sQRUgXkvmL1Oprid5bekGA/GJ\nBHQL0bAsmlybzuudBdlglPbXDjLgU6WNP2MiTxMAg+D11thbSlUk3WxW34eOaPU5\nqkIr8e+Xu8Kv5VNdg06S9rubbh8EDIhHrdb3Hj50mB43fBj1gjXVR56baalzGdgN\nnQkYbF3YVHGhVWA30OmcF0SiaazRR052kS6JaHhUnP3Pd3yyd1prUvY1RmzzvMwx\nXv+agC3JUNJLnyg2y6vFQ6sUzBVEsDkA2wXZw6cOJO1WJqVeN37cwAmeLYWWEQ5V\nAgMBAAGjJjAkMCIGA1UdEQQbMBmCF3NlZWQtMDUudG9rZW50aW1lci50ZXN0MA0G\nCSqGSIb3DQEBBQUAA4IBAQBhEuU/T3LHNu9Oxtb2lrUQjaXB3vus/EyUt6Sbdn/Z\n7gEBZd7TCYBafIewMCzF3KmZlLVKH3bPpIMWGXCUmc7RGFmnGZYFx4SuNRBrEVJU\nqI4ztCmyb1xVf1SGqyb57cvbJAVVtja0sxKLUVWm2hSuIIrdjyvRQeJsts6h6/4e\nANdfPtE/XpkBvZqOc6WavTvbmLUWi/E0zzdVVauV4MzY01eDrrsFjfa9nQaR4Q8o\nDezF7kR5pzsuhWSEOCzU9q3XEpontD0Q5wskp9hhIdjLJVgRQhsuhbsxBmQBzRkJ\n3a4CK3tJ2PweLkgqbWng3i3Kl53iewOyEHMRJCCeqfs8\n-----END CERTIFICATE-----",
  },
];

async function importCertificates(jar, workspaceId) {
  const created = [];
  for (const cert of DEMO_CERTIFICATES) {
    const result = await apiFetch(
      jar,
      `/api/v1/workspaces/${workspaceId}/certops/certificates`,
      {
        method: "POST",
        body: {
          certificatePem: cert.pem,
          name: cert.name,
          source: "api",
          sourceRef: `provision-certops-demo:${cert.name}`,
          keyMode: "external-unknown",
        },
      },
    );
    for (const item of result.items) {
      console.log(`[certificate] imported ${cert.name} (${item.id})`);
      created.push(item);
    }
  }
  return created;
}

// --- Machine API tokens ---

const TOKEN_SPECS = [
  { name: "provision-demo-executor-1", scopes: ["certops:events:write"] },
  { name: "provision-demo-executor-2", scopes: ["certops:events:write"] },
  {
    name: "provision-demo-full-access",
    scopes: ["certops:read", "certops:events:write", "certops:evidence:write"],
  },
];

async function createApiTokens(jar, workspaceId) {
  const created = [];
  for (const spec of TOKEN_SPECS) {
    const result = await apiFetch(
      jar,
      `/api/v1/workspaces/${workspaceId}/certops/tokens`,
      {
        method: "POST",
        body: { name: spec.name, scopes: spec.scopes },
      },
    );
    console.log(
      `[token] created "${spec.name}" (${result.token.id}) -> ${result.plaintextToken}`,
    );
    created.push({ ...result.token, plaintextToken: result.plaintextToken });
  }
  return created;
}

// --- Certificate jobs ---
// There is no session-authenticated HTTP route to create a certificate job
// directly (jobs are normally system/automation-created); this mirrors
// tests/integration/fake-executor.js by calling the service function
// directly against the same Postgres instance the dev server uses.
const JOB_SPECS = [
  { operation: "renew", subjectIndex: 0 },
  { operation: "deploy", subjectIndex: 1 },
  { operation: "reload", subjectIndex: 2 },
  { operation: "revoke", subjectIndex: 3 },
  { operation: "noop", subjectIndex: 4 },
];

async function createJobs(workspaceId, certificates) {
  const { createCertificateJob } = require("../apps/api/services/certops/jobs");
  const created = [];
  for (const spec of JOB_SPECS) {
    const certificate = certificates[spec.subjectIndex % certificates.length];
    const job = await createCertificateJob({
      workspaceId,
      operation: spec.operation,
      source: "api",
      subjectType: "managed_certificate",
      subjectId: certificate.id,
      payload: {
        provisionedBy: "provision-certops-demo",
        certificateName: certificate.name || null,
      },
    });
    console.log(`[job] created ${spec.operation} job (${job.id})`);
    created.push(job);
  }
  return created;
}

// --- Executor lifecycle simulation (real HTTP, Bearer machine token) ---

function eventPayload({ workspaceId, jobId, eventType, status, extra = {} }) {
  return {
    schemaVersion: 1,
    eventId: `event-${crypto.randomUUID()}`,
    workspaceId,
    jobId,
    eventType,
    status,
    occurredAt: new Date().toISOString(),
    message: `provision-certops-demo: ${eventType}`,
    metadata: [{ name: "executor", value: "provision-certops-demo" }],
    ...extra,
  };
}

async function postExecutorEvent(token, payload) {
  const response = await fetch(`${API_URL}/api/v1/certops/executor/events`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(payload),
  });
  const json = await response.json();
  if (!response.ok) {
    throw new Error(
      `executor event ${payload.eventType} failed: ${response.status} ${JSON.stringify(json)}`,
    );
  }
  return json;
}

async function driveJobsThroughExecutor(workspaceId, jobs, executorToken) {
  for (const job of jobs) {
    await postExecutorEvent(
      executorToken,
      eventPayload({
        workspaceId,
        jobId: job.id,
        eventType: "job.accepted",
        status: "claimed",
      }),
    );
    await postExecutorEvent(
      executorToken,
      eventPayload({
        workspaceId,
        jobId: job.id,
        eventType: "job.started",
        status: "running",
      }),
    );
    await postExecutorEvent(
      executorToken,
      eventPayload({
        workspaceId,
        jobId: job.id,
        eventType: "job.completed",
        status: "succeeded",
        extra: {
          evidence: [
            {
              eventType: "deployment.updated",
              certificateId: job.subjectId,
              observedAt: new Date().toISOString(),
              metadata: [{ name: "note", value: "provision-certops-demo" }],
            },
          ],
        },
      }),
    );
    console.log(`[executor] drove job ${job.id} to succeeded`);
  }
}

// --- Main ---

async function main() {
  const jar = new CookieJar();
  await login(jar);
  const workspaceId = await ensureWorkspace(jar);

  const certificates = await importCertificates(jar, workspaceId);
  const tokens = await createApiTokens(jar, workspaceId);
  const jobs = await createJobs(workspaceId, certificates);

  const executorToken =
    tokens.find((t) => t.scopes.includes("certops:evidence:write"))
      ?.plaintextToken || tokens[0].plaintextToken;
  await driveJobsThroughExecutor(workspaceId, jobs, executorToken);

  console.log("\nDone.");
  console.log(`Workspace: ${workspaceId}`);
  console.log(`Certificates: ${certificates.length}`);
  console.log(`API tokens: ${tokens.length}`);
  console.log(`Jobs: ${jobs.length}`);
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
