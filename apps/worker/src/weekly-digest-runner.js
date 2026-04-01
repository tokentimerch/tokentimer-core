#!/usr/bin/env node
import { weeklyDigestJob } from "./weekly-digest.js";
import { logger } from "./logger.js";
import {
  gWeeklyDigestLastRun,
  gWeeklyDigestLastRunSuccess,
  pushMetrics,
} from "./metrics.js";

async function run() {
  logger.info("Starting weekly digest runner...");
  try {
    await weeklyDigestJob();
    logger.info("Weekly digest job completed successfully");
    process.exit(0);
  } catch (error) {
    logger.error("Weekly digest job failed", {
      error: error.message,
      stack: error.stack,
    });

    // Mark run as failed in metrics
    try {
      gWeeklyDigestLastRun.set(Date.now() / 1000);
      gWeeklyDigestLastRunSuccess.set(0);
      await pushMetrics("weekly-digest");
    } catch (_err) {
      logger.debug("Non-critical operation failed", { error: _err.message });
    }

    process.exit(1);
  }
}

run();
