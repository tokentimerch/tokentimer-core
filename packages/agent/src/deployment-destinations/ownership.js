"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { createHash } = require("node:crypto");

const HOLD_DIRECTORY = "deployment-destination-ownership";
const DIGEST = /^[a-f0-9]{64}$/;
const WORKSPACE_ID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
const JOB_ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const { O_CREAT, O_DIRECTORY, O_EXCL, O_NOFOLLOW, O_NONBLOCK, O_RDONLY, O_WRONLY } = fs.constants;

function unavailable() {
  return Object.assign(new Error("Destination ownership storage is unavailable"), {
    code: "destination_execution_ownership_unavailable",
  });
}

function throughDirectory(fd, name) {
  return "/proc/self/fd/" + fd + "/" + name;
}

function privateDirectory(fd) {
  const stat = fs.fstatSync(fd);
  if (!stat.isDirectory() || stat.uid !== process.geteuid() || (stat.mode & 0o7777) !== 0o700) throw unavailable();
  return stat;
}

function assertSamePrivateDirectory(pinnedFd, reopenedFd) {
  const pinned = privateDirectory(pinnedFd);
  const reopened = privateDirectory(reopenedFd);
  if (pinned.dev !== reopened.dev || pinned.ino !== reopened.ino) throw unavailable();
}

function openStateRoot(stateDir) {
  let fd = fs.openSync("/", O_RDONLY | O_DIRECTORY);
  try {
    for (const part of stateDir.slice(1).split("/")) {
      const child = fs.openSync(throughDirectory(fd, part), O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
      const parent = fd;
      fd = child;
      fs.closeSync(parent);
    }
    privateDirectory(fd);
    return fd;
  } catch (error) {
    fs.closeSync(fd);
    throw error;
  }
}

function confirmHold({ stateDir, rootFd, holdDirectoryFd, holdFd, filename, contents }) {
  const currentRootFd = openStateRoot(stateDir);
  try {
    assertSamePrivateDirectory(rootFd, currentRootFd);
    const currentHoldDirectoryFd = fs.openSync(
      throughDirectory(currentRootFd, HOLD_DIRECTORY), O_RDONLY | O_DIRECTORY | O_NOFOLLOW,
    );
    try {
      assertSamePrivateDirectory(holdDirectoryFd, currentHoldDirectoryFd);
      const currentMarkerFd = fs.openSync(
        throughDirectory(currentHoldDirectoryFd, filename), O_RDONLY | O_NOFOLLOW | O_NONBLOCK,
      );
      try {
        const pinned = fs.fstatSync(holdFd);
        const marker = fs.fstatSync(currentMarkerFd);
        if (pinned.dev !== marker.dev || pinned.ino !== marker.ino || !marker.isFile() ||
            marker.uid !== process.geteuid() || (marker.mode & 0o7777) !== 0o600 ||
            marker.nlink !== 1 || marker.size !== contents.length) throw unavailable();
        const readback = Buffer.alloc(contents.length + 1);
        const length = fs.readSync(currentMarkerFd, readback, 0, readback.length, 0);
        if (length !== contents.length || !readback.subarray(0, length).equals(contents)) throw unavailable();
      } finally {
        fs.closeSync(currentMarkerFd);
      }
    } finally {
      fs.closeSync(currentHoldDirectoryFd);
    }
  } finally {
    fs.closeSync(currentRootFd);
  }
}

/**
 * Acquires a durable hold on the actual local writer domain. Any existing
 * marker, including a partial or unreadable one, fences acquisition. A job
 * result, lease loss, process restart, or read-only operation cannot remove it.
 */
function holdDestinationOwnership({ stateDir, workspaceId, jobId, operation }) {
  if (process.platform !== "linux" || typeof stateDir !== "string" ||
      stateDir === "/" || path.resolve(stateDir) !== stateDir ||
      typeof workspaceId !== "string" || !WORKSPACE_ID.test(workspaceId) ||
      typeof jobId !== "string" || !JOB_ID.test(jobId) ||
      operation?.version !== 1 ||
      typeof operation.operationId !== "string" || !DIGEST.test(operation.operationId) ||
      typeof operation.mutationDomainSha256 !== "string" || !DIGEST.test(operation.mutationDomainSha256) ||
      typeof operation.ownerClaimId !== "string" || !JOB_ID.test(operation.ownerClaimId)) {
    throw unavailable();
  }

  const record = {
    version: 1,
    workspaceId: workspaceId.toLowerCase(),
    jobId,
    ownerClaimId: operation.ownerClaimId,
    operationId: operation.operationId,
    mutationDomainSha256: operation.mutationDomainSha256,
  };
  const domainKey = createHash("sha256").update(JSON.stringify([
    record.workspaceId, record.mutationDomainSha256,
  ])).digest("hex");
  const filename = domainKey + ".json";
  const contents = Buffer.from(JSON.stringify(record) + "\n", "utf8");

  const rootFd = openStateRoot(stateDir);
  try {
    const directory = throughDirectory(rootFd, HOLD_DIRECTORY);
    try {
      fs.mkdirSync(directory, { mode: 0o700 });
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
    }
    const holdDirectoryFd = fs.openSync(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    try {
      privateDirectory(holdDirectoryFd);
      // A previous process may have died after creating the directory without
      // syncing its parent. Confirm the directory entry on every acquisition.
      fs.fsyncSync(rootFd);

      let holdFd;
      try {
        holdFd = fs.openSync(
          throughDirectory(holdDirectoryFd, filename),
          O_CREAT | O_EXCL | O_NOFOLLOW | O_WRONLY, 0o600,
        );
      } catch (error) {
        if (error.code === "EEXIST") return false;
        throw error;
      }
      try {
        fs.fchmodSync(holdFd, 0o600);
        fs.writeFileSync(holdFd, contents);
        fs.fsyncSync(holdFd);
        fs.fsyncSync(holdDirectoryFd);
        // This proves ownership at acquisition. A future mutator has to
        // recheck the same owner immediately before each external effect.
        confirmHold({ stateDir, rootFd, holdDirectoryFd, holdFd, filename, contents });
        return true;
      } finally {
        // Once created, even a partial record remains a fail-closed hold.
        fs.closeSync(holdFd);
      }
    } finally {
      fs.closeSync(holdDirectoryFd);
    }
  } finally {
    fs.closeSync(rootFd);
  }
}

module.exports = { holdDestinationOwnership };
