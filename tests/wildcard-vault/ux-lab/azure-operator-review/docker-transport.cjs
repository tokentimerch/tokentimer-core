"use strict";
// Docker CLI adapter for the owned teardown engine. No command runs on import.
const assert = require("node:assert/strict");
const { execFileSync } = require("node:child_process");
const PROJECT_LABEL = "com.docker.compose.project";
const commands = {
  container: { list: ["ps", "-a", "--no-trunc"], key: "ID", inspect: ["container", "inspect"], remove: ["container", "rm", "--force"] },
  volume: { list: ["volume", "ls"], key: "Name", inspect: ["volume", "inspect"], remove: ["volume", "rm"] },
  network: { list: ["network", "ls", "--no-trunc"], key: "ID", inspect: ["network", "inspect"], remove: ["network", "rm"] },
};
function createDockerTransport({ project, execute = args => execFileSync("docker", args, { encoding: "utf8", timeout: 30000, maxBuffer: 1024 * 1024 }) }) {
  assert.match(project || "", /^tt-wildcard-ux-(?:qual|ci)-[a-z0-9-]+$/);
  function ids({ list, key }, filter = true) {
    const text = execute([...list, ...(filter ? ["--filter", `label=${PROJECT_LABEL}=${project}`] : []), "--format", `{{.${key}}}`]).trim();
    return text ? text.split(/\r?\n/) : [];
  }
  async function inspect(kind, id) {
    assert.ok(Object.hasOwn(commands, kind));
    assert.match(id, /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/);
    const selected = commands[kind];
    if (!ids(selected, false).includes(id)) return null;
    const result = JSON.parse(execute([...selected.inspect, id]));
    assert.ok(Array.isArray(result) && result.length === 1, "ambiguous Docker inspect");
    const target = result[0];
    assert.equal(kind === "volume" ? target.Name : target.Id, id, "Docker identity mismatch");
    const labels = kind === "container" ? target.Config?.Labels : target.Labels;
    assert.equal(labels?.[PROJECT_LABEL], project, "Docker ownership mismatch");
    return { kind, id, project };
  }
  return {
    async inventory() {
      const result = [];
      for (const [kind, selected] of Object.entries(commands)) {
        for (const id of ids(selected)) {
          const item = await inspect(kind, id);
          assert.ok(item, "inventory changed");
          result.push(item);
        }
      }
      return result;
    },
    inspect,
    async remove(kind, id) {
      assert.ok(await inspect(kind, id), "owned resource missing or changed");
      execute([...commands[kind].remove, id]);
    },
  };
}
module.exports = { createDockerTransport };
