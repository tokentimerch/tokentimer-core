#!/usr/bin/env node

// Compat wrapper. Prefer: node scripts/boot-published-images.js worker <image>

const {
  BOOT_TIMEOUT_MS,
  WORKER_IMAGE_ENTRYPOINTS,
  bootWorker,
} = require("./boot-published-images");

function main(argv = process.argv.slice(2)) {
  bootWorker(argv[0]);
}

if (require.main === module) {
  main();
}

module.exports = {
  BOOT_TIMEOUT_MS,
  WORKER_IMAGE_ENTRYPOINTS,
  main,
};
