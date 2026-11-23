"use strict";

const { execFile } = require("node:child_process");
const { createHmac, randomBytes, timingSafeEqual } = require("node:crypto");
const { EventEmitter } = require("node:events");
const { createConnection } = require("node:net");
const { win32 } = require("node:path");
const { promisify } = require("node:util");

const ADMISSION_ENV = "TOKENTIMER_AGENT_HOST_ADMISSION";
const ADMISSION_DENIED = "OBSERVATION_ADMISSION_DENIED";
const operations = Object.freeze({ claim: 1, native: 2, "cng-create": 3, "ca-submit": 4,
  "ca-retrieve": 5, "store-accept": 6, "store-cleanup": 7 });

function admissionDenied() {
  return Object.assign(new Error("Required observation admission unavailable"), { code: ADMISSION_DENIED });
}

function aborted() {
  return Object.assign(new Error("Observed operation aborted"), { code: "ABORT_ERR" });
}

function takeAdmissionBinding(env = process.env) {
  const raw = env[ADMISSION_ENV];
  if (raw === undefined) return null;
  delete env[ADMISSION_ENV];
  const match = /^([1-9][0-9]{0,4}):([a-f0-9]{64})$/.exec(raw);
  if (!match || Number(match[1]) > 65535) throw admissionDenied();
  return { port: Number(match[1]), key: Buffer.from(match[2], "hex") };
}

function mac(key, domain, request) {
  return createHmac("sha256", key).update(domain).update(request).digest();
}

function requestPermit({ port, key }, stage, signal) {
  if (signal?.aborted) return Promise.reject(aborted());
  const code = operations[stage];
  if (!Number.isInteger(code)) return Promise.reject(admissionDenied());
  const request = Buffer.concat([Buffer.from([code]), randomBytes(16)]);
  const frame = Buffer.concat([request, mac(key, "request", request)]);
  const expected = mac(key, "permit", request);
  return new Promise((resolve, reject) => {
    const socket = createConnection({ host: "127.0.0.1", port });
    const reply = Buffer.alloc(expected.length);
    let size = 0;
    let settled = false;
    const timer = setTimeout(() => finish(admissionDenied()), 2_500);
    function finish(error) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      socket.destroy();
      if (error) reject(error);
      else resolve();
    }
    const abort = () => finish(aborted());
    socket.once("connect", () => socket.write(frame));
    socket.on("data", (chunk) => {
      if (chunk.length > reply.length - size) return finish(admissionDenied());
      chunk.copy(reply, size);
      size += chunk.length;
      if (size === reply.length) finish(timingSafeEqual(reply, expected) ? null : admissionDenied());
    });
    socket.once("error", () => finish(admissionDenied()));
    socket.once("close", () => finish(admissionDenied()));
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
  });
}

function createOperationAdmission(binding, onLoss) {
  let denied = false;
  return async function admit(stage, signal) {
    if (signal?.aborted) throw aborted();
    if (denied) throw admissionDenied();
    try {
      await requestPermit(binding, stage, signal);
    } catch (error) {
      if (error.code === "ABORT_ERR") throw error;
      if (!denied) {
        denied = true;
        onLoss();
      }
      throw admissionDenied();
    }
    if (denied) throw admissionDenied();
    if (signal?.aborted) throw aborted();
  };
}

function nativeOperation(file, args) {
  const executable = win32.basename(file).toLowerCase();
  const flags = args.map((arg) => String(arg).toLowerCase());
  if (executable === "certreq.exe" || executable === "certreq") {
    if (flags.includes("-new")) return "cng-create";
    if (flags.includes("-submit")) return "ca-submit";
    if (flags.includes("-retrieve")) return "ca-retrieve";
    if (flags.includes("-accept")) return "store-accept";
  }
  if (flags.some((flag) => ["-delkey", "-deleterow", "-delstore", "--delete-key"].includes(flag))) return "store-cleanup";
  return "native";
}

// Both AD CS protocol and Windows Store tools use this path. Retain the
// callback caller's cancellation and exit notification before child creation.
function guardNativeExec(admit, workerSignal, launch = execFile) {
  const launchAsync = promisify(launch);
  return function observedExecFile(file, args, options, callback) {
    const operation = nativeOperation(file, args);
    const nativeSignal = options?.signal;
    const parents = [workerSignal, nativeSignal].filter(Boolean);
    if (typeof callback !== "function") {
      const signal = AbortSignal.any(parents);
      return admit(operation, signal).then(() => {
        if (signal.aborted) throw aborted();
        return launchAsync(file, args, { ...options, signal });
      });
    }

    const cancel = new AbortController();
    const signal = AbortSignal.any([...parents, cancel.signal]);
    const events = new EventEmitter();
    let child;
    const failed = (error) => callback(error, "", "");
    admit(operation, signal).then(() => {
      if (signal.aborted) return failed(aborted());
      try {
        child = launch(file, args, options, callback);
        child?.once?.("exit", (...status) => events.emit("exit", ...status));
      } catch (error) {
        failed(error);
      }
    }, failed);
    return {
      once: events.once.bind(events),
      kill() {
        cancel.abort();
        if (child) return child.kill();
        return true;
      },
    };
  };
}

module.exports = { ADMISSION_DENIED, createOperationAdmission, guardNativeExec, takeAdmissionBinding };
