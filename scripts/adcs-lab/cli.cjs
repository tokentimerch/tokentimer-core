#!/usr/bin/env node
"use strict";
const fs = require("node:fs"),
  path = require("node:path"),
  http = require("node:http");
const { spawn, spawnSync } = require("node:child_process");
const {
  root,
  dir,
  stateFile,
  project,
  readState,
  saveState,
  newState,
  environment,
} = require("./common.cjs");
const { killProcessTree } = require("../process-utils");
const compose = [
  "compose",
  "-p",
  project,
  "-f",
  "deploy/compose/docker-compose.adcs-lab.yml",
];
function run(command, args, env, options = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    env,
    encoding: "utf8",
    windowsHide: true,
    timeout: 180000,
    ...options,
  });
  if (result.status !== 0)
    throw Error(
      `${command} ${args[0]} failed: ${result.stdout || ""}${result.stderr || result.error || ""}`,
    );
  return result.stdout;
}
function ownership(env) {
  const ids = run(
    "docker",
    ["ps", "-aq", "--filter", `label=com.docker.compose.project=${project}`],
    env,
  )
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  for (const id of ids) {
    const info = JSON.parse(run("docker", ["inspect", id], env))[0];
    if (
      info.Config.Labels["tokentimer.lab"] !== "adcs-simulated" ||
      info.Config.Labels["tokentimer.lab.owner"] !== env.ADCS_LAB_OWNER
    )
      throw Error("Refusing resources owned by another checkout");
  }
  const volumes = run(
    "docker",
    [
      "volume",
      "ls",
      "-q",
      "--filter",
      `label=com.docker.compose.project=${project}`,
    ],
    env,
  )
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  for (const volume of volumes) {
    const info = JSON.parse(
      run("docker", ["volume", "inspect", volume], env),
    )[0];
    if (info.Labels["tokentimer.lab.owner"] !== env.ADCS_LAB_OWNER)
      throw Error("Refusing another checkout's volume");
  }
}
async function control(state, command, args = []) {
  const response = await fetch("http://127.0.0.1:55474/", {
    method: "POST",
    signal: AbortSignal.timeout(180000),
    headers: {
      authorization: `Bearer ${state.token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ command, args }),
  });
  const result = await response.json();
  if (!response.ok) throw Error(result.error);
  return result;
}
async function ready(url) {
  for (let i = 0; i < 120; i++) {
    try {
      if ((await fetch(url, { signal: AbortSignal.timeout(1000) })).ok) return;
    } catch {
      /* starting */
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw Error(`${url} unavailable; inspect ${dir}`);
}
async function serve() {
  const state = readState(),
    env = environment(state),
    children = new Set();
  let busy = false,
    stopping = false,
    paused = false;
  function service(name, args, cwd = root, serviceEnv = env) {
    const fd = fs.openSync(path.join(dir, `${name}.log`), "a");
    const child = spawn(process.execPath, args, {
      cwd,
      env: serviceEnv,
      detached: process.platform !== "win32",
      stdio: ["ignore", fd, fd],
      windowsHide: true,
    });
    fs.closeSync(fd);
    children.add(child);
    child.on("exit", () => children.delete(child));
    return child;
  }
  const api = service("api", ["apps/api/index.js"]);
  const ui = service(
    "dashboard",
    [
      path.join(root, "apps/dashboard/node_modules/vite/bin/vite.js"),
      "--host",
      "127.0.0.1",
      "--port",
      "55174",
    ],
    path.join(root, "apps/dashboard"),
  );
  async function step(args) {
    if (busy)
      throw Error("Worker cycle already running; retry after it finishes");
    busy = true;
    try {
      const child = service("worker", ["scripts/adcs-lab/step.cjs", ...args]);
      await new Promise((resolve, reject) => {
        child.on("error", reject);
        child.on("exit", (code) =>
          code === 0
            ? resolve()
            : reject(Error("Lab worker failed; see worker.log")),
        );
      });
    } finally {
      busy = false;
    }
  }
  const timer = setInterval(() => {
    if (readState().seedComplete && !busy && !paused)
      step(["tick"]).catch((error) => console.error(error.message));
  }, 15000);
  const server = http.createServer(async (req, res) => {
    res.setHeader("content-type", "application/json");
    if (
      req.method !== "POST" ||
      req.headers.authorization !== `Bearer ${state.token}`
    ) {
      res.writeHead(403);
      res.end('{"error":"Forbidden"}');
      return;
    }
    try {
      let input = "";
      for await (const chunk of req) {
        input += chunk;
        if (input.length > 4096) throw Error("Control request too large");
      }
      const { command, args = [] } = JSON.parse(input);
      if (command === "pause" || command === "resume") {
        paused = command === "pause";
        while (busy) await new Promise((resolve) => setTimeout(resolve, 100));
        res.end(JSON.stringify({ paused }));
        return;
      }
      if (command === "stop") {
        stopping = true;
        clearInterval(timer);
        for (const child of children) killProcessTree(child);
        res.end('{"stopped":true}');
        server.close();
        setTimeout(() => process.exit(0), 6000).unref();
        return;
      }
      if (command === "ping") {
        res.end(JSON.stringify({ ready: true, busy, paused }));
        return;
      }
      if (
        ![
          "tick",
          "agent",
          "scheduler",
          "scenario",
          "advance",
          "expire",
          "expire-lease",
          "manual",
          "status",
        ].includes(command) ||
        !Array.isArray(args) ||
        args.some((x) => typeof x !== "string")
      )
        throw Error("Unsupported control");
      await step([command, ...args]);
      res.end('{"ok":true}');
    } catch (error) {
      res.writeHead(409);
      res.end(JSON.stringify({ error: error.message }));
    }
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(55474, "127.0.0.1", resolve);
  });
  for (const child of [api, ui])
    child.on("exit", () => {
      if (!stopping) {
        console.error("Required service exited");
        process.exitCode = 1;
        server.close();
        clearInterval(timer);
        for (const c of children) killProcessTree(c);
      }
    });
  await Promise.all([
    ready("http://localhost:55471/"),
    ready("http://localhost:55174/"),
  ]);
  console.log("SIMULATED AD CS services ready on loopback");
}
async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (process.env.NODE_ENV === "production")
    throw Error("Development lab cannot run in production mode");
  if (command === "serve") return serve();
  if (command === "up") {
    if (!args.includes("--simulated"))
      throw Error(
        "Explicit acknowledgement required: pnpm adcs:lab up --simulated",
      );
    // dotenv imports cannot introduce ambient production settings into this lab.
    for (const file of [".env", "apps/api/.env", "apps/worker/.env"])
      if (fs.existsSync(path.join(root, file)))
        throw Error(
          `Move ${file} aside or use a clean worktree; lab refuses ambient dotenv credentials`,
        );
    const state = fs.existsSync(stateFile) ? readState() : newState();
    saveState(state);
    const env = environment(state);
    ownership(env);
    console.log(run("docker", [...compose, "up", "-d", "--wait"], env));
    run(process.execPath, ["apps/api/migrations/migrate.js"], env);
    try {
      await control(state, "ping");
    } catch {
      const fd = fs.openSync(path.join(dir, "supervisor.log"), "a");
      const child = spawn(
        process.execPath,
        ["scripts/adcs-lab/cli.cjs", "serve"],
        {
          cwd: root,
          env,
          detached: true,
          windowsHide: true,
          stdio: ["ignore", fd, fd],
        },
      );
      fs.closeSync(fd);
      child.unref();
    }
    await Promise.all([
      ready("http://localhost:55471/"),
      ready("http://localhost:55174/"),
    ]);
    if (!state.workspaceId) {
      console.log(
        run(process.execPath, ["scripts/adcs-lab/seed.cjs"], env, {
          timeout: 300000,
        }),
      );
    }
    console.log(
      "Dashboard http://localhost:55174 — SMTP http://localhost:18025 — pnpm adcs:lab credentials",
    );
    return;
  }
  const state = readState(),
    env = environment(state);
  if (command === "verify" || command === "browser") {
    console.log(
      run(
        process.execPath,
        [
          `scripts/adcs-lab/${command === "browser" ? "browser" : "verify"}.cjs`,
        ],
        env,
        { timeout: 300000 },
      ),
    );
    return;
  }
  if (command === "credentials") {
    console.log(
      JSON.stringify(
        {
          email: state.email,
          stateFile,
          workspaceId: state.workspaceId,
        },
        null,
        2,
      ),
    );
    return;
  }
  if (command === "logs") {
    console.log(dir);
    for (const file of [
      "supervisor.log",
      "api.log",
      "dashboard.log",
      "worker.log",
    ])
      console.log(
        `--- ${file}\n${fs.existsSync(path.join(dir, file)) ? fs.readFileSync(path.join(dir, file), "utf8").split(/\r?\n/).slice(-20).join("\n") : "not started"}`,
      );
    return;
  }
  if (["stop", "clean", "reset"].includes(command)) {
    ownership(env);
    try {
      await control(state, "stop");
      await new Promise((r) => setTimeout(r, 6500));
    } catch (error) {
      if (!String(error.cause?.code || error.message).includes("ECONNREFUSED"))
        throw error;
    }
    console.log(
      run(
        "docker",
        [...compose, "down", ...(command === "stop" ? [] : ["--volumes"])],
        env,
      ),
    );
    if (command !== "stop") fs.unlinkSync(stateFile);
    if (command === "reset")
      return (
        run(
          process.execPath,
          ["scripts/adcs-lab/cli.cjs", "up", "--simulated"],
          env,
          { timeout: 360000 },
        ) && console.log("Clean reset and startup completed")
      );
    return;
  }
  if (command === "status") {
    console.log(
      run(process.execPath, ["scripts/adcs-lab/step.cjs", "status"], env),
    );
    return;
  }
  console.log(await control(state, command, args));
}
main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
