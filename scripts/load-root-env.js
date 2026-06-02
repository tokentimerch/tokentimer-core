const fs = require("fs");
const path = require("path");

function unquote(value) {
  if (value.length < 2) return value;
  const quote = value[0];
  if ((quote !== '"' && quote !== "'") || value[value.length - 1] !== quote) {
    return value.replace(/\s+#.*$/, "");
  }

  const inner = value.slice(1, -1);
  if (quote === "'") return inner;

  return inner.replace(/\\([nrt"\\])/g, (_match, char) => {
    if (char === "n") return "\n";
    if (char === "r") return "\r";
    if (char === "t") return "\t";
    return char;
  });
}

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) return false;

  const content = fs.readFileSync(filePath, "utf8");
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;

    const normalized = line.startsWith("export ") ? line.slice(7).trim() : line;
    const separatorIndex = normalized.indexOf("=");
    if (separatorIndex === -1) continue;

    const key = normalized.slice(0, separatorIndex).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    if (Object.prototype.hasOwnProperty.call(process.env, key)) continue;

    process.env[key] = unquote(normalized.slice(separatorIndex + 1).trim());
  }

  return true;
}

function loadRootEnv() {
  const repoRoot = path.resolve(__dirname, "..");
  loadEnvFile(path.join(repoRoot, ".env"));

  if (!process.env.VITE_API_URL && process.env.API_URL) {
    process.env.VITE_API_URL = process.env.API_URL;
  }

  return repoRoot;
}

module.exports = {
  loadEnvFile,
  loadRootEnv,
};
