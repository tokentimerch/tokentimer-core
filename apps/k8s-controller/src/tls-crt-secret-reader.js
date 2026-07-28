"use strict";

const http = require("node:http");
const https = require("node:https");

const DEFAULT_SECRET_READ_TIMEOUT_MS = 5_000;
const MAX_SECRET_RESPONSE_BYTES = 256 * 1024;
const MAX_TLS_CRT_JSON_BYTES = 128 * 1024;

function readerError(code, statusCode) {
  const error = new Error(`Kubernetes Secret read failed: ${code}`);
  error.code = code;
  if (statusCode !== undefined) error.statusCode = statusCode;
  return error;
}

class BoundedByteReader {
  constructor(stream, maxBytes) {
    this.iterator = stream[Symbol.asyncIterator]();
    this.maxBytes = maxBytes;
    this.chunk = Buffer.alloc(0);
    this.index = 0;
    this.total = 0;
    this.pushedBack = null;
  }

  async read() {
    if (this.pushedBack !== null) {
      const value = this.pushedBack;
      this.pushedBack = null;
      return value;
    }
    while (this.index >= this.chunk.length) {
      const next = await this.iterator.next();
      if (next.done) return null;
      this.chunk = Buffer.isBuffer(next.value)
        ? next.value
        : Buffer.from(next.value);
      this.index = 0;
      this.total += this.chunk.length;
      if (this.total > this.maxBytes) {
        throw readerError("CERTOPS_SECRET_RESPONSE_TOO_LARGE");
      }
    }
    const value = this.chunk[this.index];
    this.index += 1;
    return value;
  }

  unread(value) {
    if (value === null || this.pushedBack !== null) {
      throw readerError("CERTOPS_SECRET_RESPONSE_INVALID");
    }
    this.pushedBack = value;
  }
}

function isWhitespace(value) {
  return value === 0x20 || value === 0x09 || value === 0x0a || value === 0x0d;
}

async function nextNonWhitespace(reader) {
  let value;
  do {
    value = await reader.read();
  } while (value !== null && isWhitespace(value));
  return value;
}

async function skipStringEscape(reader) {
  const escaped = await reader.read();
  if (escaped === null) throw readerError("CERTOPS_SECRET_RESPONSE_INVALID");
  if (escaped === 0x75) {
    for (let index = 0; index < 4; index += 1) {
      const digit = await reader.read();
      if (digit === null || !(
        (digit >= 0x30 && digit <= 0x39) ||
        (digit >= 0x41 && digit <= 0x46) ||
        (digit >= 0x61 && digit <= 0x66)
      )) {
        throw readerError("CERTOPS_SECRET_RESPONSE_INVALID");
      }
    }
    return;
  }
  if (![0x22, 0x5c, 0x2f, 0x62, 0x66, 0x6e, 0x72, 0x74].includes(escaped)) {
    throw readerError("CERTOPS_SECRET_RESPONSE_INVALID");
  }
}

// Compares a JSON object key without allocating or decoding non-target key
// names. In particular, other Secret.data member names are never enumerated.
async function readStringMatches(reader, expected) {
  const expectedBytes = Buffer.from(expected, "ascii");
  let matches = true;
  let index = 0;
  while (true) {
    const value = await reader.read();
    if (value === null || value < 0x20) {
      throw readerError("CERTOPS_SECRET_RESPONSE_INVALID");
    }
    if (value === 0x22) return matches && index === expectedBytes.length;
    if (value === 0x5c) {
      matches = false;
      await skipStringEscape(reader);
      continue;
    }
    if (matches && (index >= expectedBytes.length || value !== expectedBytes[index])) {
      matches = false;
    }
    index += 1;
  }
}

async function readCapturedString(reader, maxBytes) {
  const bytes = [];
  while (true) {
    const value = await reader.read();
    if (value === null || value < 0x20) {
      throw readerError("CERTOPS_SECRET_RESPONSE_INVALID");
    }
    if (value === 0x22) break;
    if (value === 0x5c) {
      // Kubernetes base64 Secret values never require JSON escapes. Rejecting
      // them keeps this boundary ASCII-only and avoids a permissive decoder.
      throw readerError("CERTOPS_SECRET_RESPONSE_INVALID");
    }
    bytes.push(value);
    if (bytes.length > maxBytes) {
      throw readerError("CERTOPS_TLS_CRT_TOO_LARGE");
    }
  }
  return Buffer.from(bytes).toString("ascii");
}

async function skipJsonString(reader) {
  while (true) {
    const value = await reader.read();
    if (value === null || value < 0x20) {
      throw readerError("CERTOPS_SECRET_RESPONSE_INVALID");
    }
    if (value === 0x22) return;
    if (value === 0x5c) await skipStringEscape(reader);
  }
}

async function skipJsonValue(reader, initialValue) {
  const first = initialValue ?? await nextNonWhitespace(reader);
  if (first === null) throw readerError("CERTOPS_SECRET_RESPONSE_INVALID");
  if (first === 0x22) return skipJsonString(reader);
  if (first === 0x7b) return skipJsonObject(reader);
  if (first === 0x5b) return skipJsonArray(reader);

  let value = first;
  while (value !== null && !isWhitespace(value) && ![0x2c, 0x5d, 0x7d].includes(value)) {
    value = await reader.read();
  }
  if (value !== null && [0x2c, 0x5d, 0x7d].includes(value)) reader.unread(value);
}

async function skipJsonObject(reader) {
  let delimiter = await nextNonWhitespace(reader);
  if (delimiter === 0x7d) return;
  while (true) {
    if (delimiter !== 0x22) throw readerError("CERTOPS_SECRET_RESPONSE_INVALID");
    await skipJsonString(reader);
    if (await nextNonWhitespace(reader) !== 0x3a) {
      throw readerError("CERTOPS_SECRET_RESPONSE_INVALID");
    }
    await skipJsonValue(reader);
    delimiter = await nextNonWhitespace(reader);
    if (delimiter === 0x7d) return;
    if (delimiter !== 0x2c) throw readerError("CERTOPS_SECRET_RESPONSE_INVALID");
    delimiter = await nextNonWhitespace(reader);
  }
}

async function skipJsonArray(reader) {
  let value = await nextNonWhitespace(reader);
  if (value === 0x5d) return;
  while (true) {
    await skipJsonValue(reader, value);
    const delimiter = await nextNonWhitespace(reader);
    if (delimiter === 0x5d) return;
    if (delimiter !== 0x2c) throw readerError("CERTOPS_SECRET_RESPONSE_INVALID");
    value = await nextNonWhitespace(reader);
  }
}

async function readDataObject(reader) {
  const first = await nextNonWhitespace(reader);
  if (first !== 0x7b) {
    await skipJsonValue(reader, first);
    return undefined;
  }

  let certificate;
  let delimiter = await nextNonWhitespace(reader);
  if (delimiter === 0x7d) return certificate;
  while (true) {
    if (delimiter !== 0x22) throw readerError("CERTOPS_SECRET_RESPONSE_INVALID");
    const isTlsCertificate = await readStringMatches(reader, "tls.crt");
    if (await nextNonWhitespace(reader) !== 0x3a) {
      throw readerError("CERTOPS_SECRET_RESPONSE_INVALID");
    }
    const valueStart = await nextNonWhitespace(reader);
    if (isTlsCertificate) {
      if (certificate !== undefined || valueStart !== 0x22) {
        throw readerError("CERTOPS_SECRET_RESPONSE_INVALID");
      }
      certificate = await readCapturedString(reader, MAX_TLS_CRT_JSON_BYTES);
    } else {
      await skipJsonValue(reader, valueStart);
    }
    delimiter = await nextNonWhitespace(reader);
    if (delimiter === 0x7d) return certificate;
    if (delimiter !== 0x2c) throw readerError("CERTOPS_SECRET_RESPONSE_INVALID");
    delimiter = await nextNonWhitespace(reader);
  }
}

async function extractTlsCertificateFromSecretJson(stream, {
  maxResponseBytes = MAX_SECRET_RESPONSE_BYTES,
} = {}) {
  const reader = new BoundedByteReader(stream, maxResponseBytes);
  if (await nextNonWhitespace(reader) !== 0x7b) {
    throw readerError("CERTOPS_SECRET_RESPONSE_INVALID");
  }

  let certificate;
  let sawData = false;
  let delimiter = await nextNonWhitespace(reader);
  if (delimiter === 0x7d) return undefined;
  while (true) {
    if (delimiter !== 0x22) throw readerError("CERTOPS_SECRET_RESPONSE_INVALID");
    const isData = await readStringMatches(reader, "data");
    if (await nextNonWhitespace(reader) !== 0x3a) {
      throw readerError("CERTOPS_SECRET_RESPONSE_INVALID");
    }
    if (isData) {
      if (sawData) throw readerError("CERTOPS_SECRET_RESPONSE_INVALID");
      sawData = true;
      certificate = await readDataObject(reader);
    } else {
      await skipJsonValue(reader);
    }
    delimiter = await nextNonWhitespace(reader);
    if (delimiter === 0x7d) break;
    if (delimiter !== 0x2c) throw readerError("CERTOPS_SECRET_RESPONSE_INVALID");
    delimiter = await nextNonWhitespace(reader);
  }
  if (await nextNonWhitespace(reader) !== null) {
    throw readerError("CERTOPS_SECRET_RESPONSE_INVALID");
  }
  return certificate;
}

function defaultRequest(url, options, onResponse) {
  return (url.protocol === "https:" ? https : http).request(url, options, onResponse);
}

function createTlsCrtSecretReader({
  kubeConfig,
  maxResponseBytes = MAX_SECRET_RESPONSE_BYTES,
  requestFn = defaultRequest,
  timeoutMs = DEFAULT_SECRET_READ_TIMEOUT_MS,
} = {}) {
  if (!kubeConfig?.getCurrentCluster || !kubeConfig?.applyToHTTPSOptions) {
    throw new TypeError("An in-cluster Kubernetes configuration is required");
  }
  const activeRequests = new Set();
  let closed = false;

  async function read({ namespace, secretName } = {}) {
    if (closed) throw readerError("CERTOPS_SECRET_READER_CLOSED");
    const cluster = kubeConfig.getCurrentCluster();
    if (!cluster?.server) throw readerError("CERTOPS_KUBERNETES_CLUSTER_UNAVAILABLE");
    const endpoint = new URL(
      `/api/v1/namespaces/${encodeURIComponent(namespace)}/secrets/${encodeURIComponent(secretName)}`,
      cluster.server,
    );
    const options = {
      headers: { Accept: "application/json" },
      method: "GET",
      timeout: timeoutMs,
    };
    await kubeConfig.applyToHTTPSOptions(options);

    const { request, response } = await new Promise((resolve, reject) => {
      let request;
      try {
        request = requestFn(endpoint, options, (response) => resolve({ request, response }));
      } catch (error) {
        reject(error);
        return;
      }
      activeRequests.add(request);
      request.once("close", () => activeRequests.delete(request));
      request.once("error", reject);
      request.setTimeout?.(timeoutMs, () => {
        request.destroy(readerError("CERTOPS_SECRET_READ_TIMEOUT"));
      });
      request.end();
    });

    try {
      if (response.statusCode !== 200) {
        throw readerError("CERTOPS_SECRET_READ_FAILED", response.statusCode);
      }
      const contentType = String(response.headers?.["content-type"] || "").toLowerCase();
      if (contentType && !contentType.includes("application/json")) {
        throw readerError("CERTOPS_SECRET_RESPONSE_INVALID");
      }
      const contentLength = Number(response.headers?.["content-length"]);
      if (Number.isFinite(contentLength) && contentLength > maxResponseBytes) {
        throw readerError("CERTOPS_SECRET_RESPONSE_TOO_LARGE");
      }
      return await extractTlsCertificateFromSecretJson(response, { maxResponseBytes });
    } finally {
      activeRequests.delete(request);
      response.destroy?.();
    }
  }

  async function close() {
    closed = true;
    const error = readerError("CERTOPS_SECRET_READER_CLOSED");
    for (const request of activeRequests) request.destroy(error);
    activeRequests.clear();
  }

  return Object.freeze({ close, read });
}

module.exports = {
  DEFAULT_SECRET_READ_TIMEOUT_MS,
  MAX_SECRET_RESPONSE_BYTES,
  MAX_TLS_CRT_JSON_BYTES,
  createTlsCrtSecretReader,
  extractTlsCertificateFromSecretJson,
};
