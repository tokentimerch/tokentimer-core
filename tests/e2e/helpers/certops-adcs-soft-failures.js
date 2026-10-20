"use strict";
/* Lets the native AD CS suite keep running after an isolated journey (or its scratch cleanup)
 * fails, so a single lab run reports every independent failure instead of the first one.
 *
 * Journey helpers export `qualify*` functions that the harness awaits in sequence. When the gate is in
 * continue-on-failure mode each of those calls is routed through `gate.guard`, which records the
 * bounded failure and returns. The gate still ends the suite as failed, so this never turns a failing
 * run into release evidence. Outside that mode the original function is called unchanged. */
const Module = require("node:module");

const HELPER = /[\\/]tests[\\/]e2e[\\/]helpers[\\/]certops-adcs-[a-z0-9-]+\.js$/;
const JOURNEY = /^qualify[A-Za-z0-9]*$/;

function wrapExports(exported, file, getGate) {
  const label = String(file).split(/[\\/]/).pop().replace(/\.js$/, "");
  for (const name of Object.keys(exported)) {
    const original = exported[name];
    if (!JOURNEY.test(name) || typeof original !== "function") continue;
    const descriptor = Object.getOwnPropertyDescriptor(exported, name);
    if (!descriptor || (!descriptor.writable && !descriptor.configurable)) continue;
    const guarded = function (...args) {
      const gate = getGate();
      if (!gate || gate.continueOnFailure !== true) return original.apply(this, args);
      return gate.guard(`${label}.${name}`, () => original.apply(this, args));
    };
    try { Object.defineProperty(exported, name, { ...descriptor, ...(descriptor.get ? {} : { value: guarded }) }); } catch { /* frozen export: leave unguarded */ }
  }
}

function install(getGate, moduleApi = Module) {
  const original = moduleApi.prototype.require;
  const seen = new WeakSet();
  moduleApi.prototype.require = function (request) {
    const exported = original.apply(this, arguments);
    if (typeof request !== "string" || !request.startsWith(".") || !exported || typeof exported !== "object" || seen.has(exported)) return exported;
    let file;
    try { file = moduleApi._resolveFilename(request, this); } catch { return exported; }
    if (!HELPER.test(file)) return exported;
    seen.add(exported);
    wrapExports(exported, file, getGate);
    return exported;
  };
  return () => { moduleApi.prototype.require = original; };
}

module.exports = { install, wrapExports };
