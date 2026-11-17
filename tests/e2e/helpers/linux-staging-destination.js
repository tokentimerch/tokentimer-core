"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { randomUUID } = require("node:crypto");

module.exports = function watchDestination(directory, waitFor) {
  const markers = new Map();
  let mutations = 0;
  let watchError;
  const watcher = fs.watch(directory, (_event, file) => {
    if (markers.has(file)) markers.set(file, true);
    else mutations++;
  });
  watcher.on("error", error => { watchError = error; });
  return {
    async checkpoint() {
      // On the Linux host, the marker event on the same inotify watch
      // follows previously queued mutations. Use a fresh marker each time.
      const name = `.staging-watch-${randomUUID()}`;
      const marker = path.join(directory, name);
      markers.set(name, false);
      fs.writeFileSync(marker, "", { flag: "wx", mode: 0o600 });
      fs.unlinkSync(marker);
      await waitFor(() => {
        assert.ifError(watchError);
        return markers.get(name);
      }, "Live destination watch reached its marker", 5000);
      return mutations;
    },
    close() { watcher.close(); },
  };
};
