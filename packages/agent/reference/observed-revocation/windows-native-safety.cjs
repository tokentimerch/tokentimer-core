"use strict";

async function cleanupFixture({ close, remove, cleanupDir, created }) {
  try { await close(); }
  finally {
    try { if (created) remove(); }
    finally { cleanupDir(); }
  }
}

module.exports = { cleanupFixture };
