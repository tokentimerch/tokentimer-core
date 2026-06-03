import path from "path";
import { pathToFileURL } from "url";

export function isNodeEntrypoint(moduleUrl, argv = process.argv) {
  const entry = argv[1];
  if (!entry) return false;
  return moduleUrl === pathToFileURL(path.resolve(entry)).href;
}
