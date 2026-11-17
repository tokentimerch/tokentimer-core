"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { inspectOwnedTransport } = require("./native-openbao-bootstrap.cjs");

test("native OpenBao transport refuses wildcard, mutable, duplicate and foreign routes", () => {
  const project = "tt-wildcard-ux-qual-abc", id = "a".repeat(64), image = "sha256:" + "b".repeat(64);
  const wanted = { project, customerImage: image, apiAddress: "https://127.0.0.1:60806", baoAddress: "https://127.0.0.1:60807" };
  const container = { State: { Running: true }, Id: id, Image: image,
    Config: { Labels: { "com.docker.compose.project": project, "com.docker.compose.service": "customers" } },
    NetworkSettings: { Ports: { "18443/tcp": [{ HostIp: "127.0.0.1", HostPort: "60806" }],
      "18201/tcp": [{ HostIp: "127.0.0.1", HostPort: "60807" }] } } };
  const docker = args => {
    if (args[0] === "ps") return id;
    if (args[0] === "container") return JSON.stringify([container]);
    assert.equal(args[0], "exec");
    assert.equal(args[args.indexOf("cat") - 1], id);
    return "{}";
  };
  assert.deepEqual(inspectOwnedTransport(wanted, docker).credentials(), {});
  assert.throws(() => inspectOwnedTransport({ ...wanted, baoAddress: wanted.apiAddress }, docker));
  assert.throws(() => inspectOwnedTransport({ ...wanted, customerImage: "customer:mutable" }, docker));
  container.NetworkSettings.Ports["18201/tcp"][0].HostIp = "0.0.0.0";
  assert.throws(() => inspectOwnedTransport(wanted, docker));
  container.NetworkSettings.Ports["18201/tcp"][0].HostIp = "127.0.0.1";
  container.Config.Labels["com.docker.compose.project"] = "other";
  assert.throws(() => inspectOwnedTransport(wanted, docker));
});
