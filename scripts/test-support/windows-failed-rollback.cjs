"use strict";
const {windowsArtifact} = require("./qualification-artifact.cjs");
/** Synthetic contract fixture only; never native execution evidence. */
const h = require("../../tests/e2e/helpers/certops-windows-installed-failed-rollback");
const {
  fixture,
} = require("../fixtures/certops-windows-installed-failed-rollback.cjs");
const candidateSha = "a".repeat(40);
function artifact(version = "2022") {
 return windowsArtifact(require("../certops-windows-failed-rollback"), h, fixture, "nativeInstalledFailedRollback", version, "2026-10-15T12:00:00.000Z", candidateSha);
}
module.exports = { fixture, artifact, candidateSha };
