import { logger } from "../logger.js";

export function safeInc(counter, labels = {}) {
  try {
    counter.labels(labels).inc();
  } catch (_) {
    logger.debug("Metrics recording failed", {
      metric: counter?.name,
      error: _?.message,
    });
  }
}

export function safeObserve(histogram, labels = {}, value) {
  try {
    histogram.labels(labels).observe(value);
  } catch (_) {
    logger.debug("Metrics recording failed", {
      metric: histogram?.name,
      error: _?.message,
    });
  }
}
