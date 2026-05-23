"use strict";

const { expect } = require("chai");
const {
  getRuntimeLabels,
  normalizeMode,
  resetRuntimeLabelsCacheForTests,
} = require("../../apps/api/config/runtime-labels");

describe("runtime-labels", () => {
  beforeEach(() => resetRuntimeLabelsCacheForTests("oss"));
  afterEach(() => {
    delete process.env.LOG_SERVICE_NAME;
    delete process.env.API_RATE_LIMIT_LOG_LABEL;
    resetRuntimeLabelsCacheForTests();
  });

  it("defaults to core/oss labels", () => {
    expect(normalizeMode()).to.equal("oss");
    expect(getRuntimeLabels()).to.deep.equal({
      service: "tokentimer-core-api",
      rateLabel: "oss",
      plan: "oss",
      limitsKey: "oss",
    });
  });

  it("uses enterprise labels when TT_MODE=enterprise", () => {
    resetRuntimeLabelsCacheForTests("enterprise");
    expect(getRuntimeLabels()).to.deep.equal({
      service: "tokentimer-enterprise-api",
      rateLabel: "enterprise",
      plan: "enterprise",
      limitsKey: "enterprise",
    });
  });

  it("honours explicit env overrides", () => {
    resetRuntimeLabelsCacheForTests("enterprise");
    process.env.LOG_SERVICE_NAME = "custom-api";
    process.env.API_RATE_LIMIT_LOG_LABEL = "custom";
    resetRuntimeLabelsCacheForTests("enterprise");
    const labels = getRuntimeLabels();
    expect(labels.service).to.equal("custom-api");
    expect(labels.rateLabel).to.equal("custom");
    expect(labels.plan).to.equal("enterprise");
  });
});
