"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

const deliveryWorkerUrl = pathToFileURL(
  path.join(
    __dirname,
    "..",
    "..",
    "apps",
    "worker",
    "src",
    "delivery-worker.js",
  ),
).href;

const alert = {
  alert_key: "cert_renewal_failed:07acbb05-3f66-43fc-89ce-9fdb65ed4f8f",
  token_id: 91,
  name: "win.hardgates-az.tokentimer.io",
};
const job = {
  id: "07acbb05-3f66-43fc-89ce-9fdb65ed4f8f",
  error_code: "ACME_RATE_LIMITED",
};

describe("cert_renewal_failed webhook content", () => {
  it("does not use the expiry Slack template or days-remaining fields", async () => {
    const { _test } = await import(deliveryWorkerUrl);
    const payload = _test.buildCertRenewalFailedWebhookPayload("slack", alert, {
      job,
    });
    const dumped = JSON.stringify(payload);
    assert.match(payload.text, /Certificate Renewal Failed/);
    assert.doesNotMatch(dumped, /Token Expiry Alert/);
    assert.doesNotMatch(dumped, /undefined day/);
    assert.doesNotMatch(dumped, /expires in/);
    assert.doesNotMatch(dumped, /days remaining/);
    assert.match(dumped, /win\.hardgates-az\.tokentimer\.io/);
    assert.match(dumped, /07acbb05-3f66-43fc-89ce-9fdb65ed4f8f/);
    assert.match(dumped, /ACME_/);
    assert.match(dumped, /RATE_/);
    assert.match(dumped, /LIMITED/);
  });

  it("escapes the title, certificate name, and job id in Slack fallback text", async () => {
    const { _test } = await import(deliveryWorkerUrl);
    const payload = _test.buildCertRenewalFailedWebhookPayload(
      "slack",
      { ...alert, name: "@here <prod> & *cert*" },
      {
        title: "@channel <renewal> & *urgent*",
        job: { ...job, id: "@channel-job" },
      },
    );

    assert.equal(
      payload.text,
      "@\u200bchannel &lt;renewal&gt; &amp; *\u200burgent*\u200b: " +
        "@\u200bhere &lt;prod&gt; &amp; *\u200bcert*\u200b (job @\u200bchannel-job)",
    );
  });

  it("renders Discord and Teams without expiry language", async () => {
    const { _test } = await import(deliveryWorkerUrl);
    const discord = _test.buildCertRenewalFailedWebhookPayload(
      "discord",
      alert,
      { job },
    );
    const teams = _test.buildCertRenewalFailedWebhookPayload("teams", alert, {
      job,
    });
    assert.match(JSON.stringify(discord), /Certificate Renewal Failed/);
    assert.doesNotMatch(JSON.stringify(discord), /expires in/);
    assert.match(JSON.stringify(teams), /Certificate Renewal Failed/);
    assert.doesNotMatch(JSON.stringify(teams), /Token Expiry Alert/);
  });

  it("falls back to the alert_key job id when the job row is missing", async () => {
    const { _test } = await import(deliveryWorkerUrl);
    const context = _test.getCertRenewalFailedContext(alert, null);
    assert.equal(context.jobId, "07acbb05-3f66-43fc-89ce-9fdb65ed4f8f");
    assert.equal(context.errorCode, "unknown");
  });
});
