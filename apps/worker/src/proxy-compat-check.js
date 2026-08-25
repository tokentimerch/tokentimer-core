import { isNodeUseEnvProxySupported } from "@tokentimer/node-compat";
import { logger } from "./logger.js";

// Called explicitly by every worker entrypoint and by runner.js, since Helm
// CronJobs run entrypoints directly and skip runner.js.
export function warnIfNodeUseEnvProxyUnsupported() {
  if (
    process.env.NODE_USE_ENV_PROXY === "1" &&
    !isNodeUseEnvProxySupported()
  ) {
    logger.warn(
      `NODE_USE_ENV_PROXY=1 is set but Node.js ${process.version} does not support it for fetch/undici (requires 22.21.0+ or 24.0.0+). This has no effect here: this worker's webhook delivery uses axios, which reads HTTP_PROXY/HTTPS_PROXY on its own and will keep proxying regardless.`,
    );
  }
}

