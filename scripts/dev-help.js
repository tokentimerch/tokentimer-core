#!/usr/bin/env node
"use strict";

// Prints the local development command map for tokentimer-core.
// package.json cannot carry comments; run `pnpm run dev:help` anytime.

const lines = `
TokenTimer Core — local development commands
============================================

HOST-NATIVE (fast iteration; processes run on your machine)
---------------------------------------------------------
  pnpm dev
      Postgres in Docker + API + worker + dashboard on the host.
      NOT the full containerized stack. Best for day-to-day work.

  pnpm dev:noDB
      Same as dev, but skips starting Postgres (you provide DB_HOST yourself).

  pnpm dev:postgres
      Start only the Postgres container (deploy/compose/docker-compose.postgres.yml).

  pnpm dev:api / dev:worker / dev:dashboard
      Run a single app with .env loaded (when Postgres is already up).

  pnpm dev:ports:check
      Fail fast if API or dashboard ports are already in use.


FULL STACK IN DOCKER (all services containerized)
-------------------------------------------------
  pnpm docker:up
      deploy/compose/docker-compose.yml up --build (foreground).
      Postgres + API + worker + dashboard all in containers. --build
      re-checks the image against the Dockerfile/context/build args on
      every run, so a stale image from a branch switch gets rebuilt
      automatically (cache hit = no-op if nothing changed).

  pnpm docker:down
      Stop all local Docker infra: full stack, dev stack, and postgres-only
      (pnpm dev / dev:postgres). Frees ports 4000, 5173, 5432.

  pnpm docker:down:stack
      Stop deploy/compose/docker-compose.yml only.

  pnpm docker:down:dev
      Stop deploy/compose/docker-compose.dev.yml only.

  pnpm docker:down:all
      Same as docker:down (alias).

  pnpm docker:build
      Build deploy/compose/docker-compose.yml images without starting.


INTEGRATION TEST STACK
----------------------
  pnpm test:up
      Start deploy/compose/docker-compose.test.yml (detached, rebuilt).

  pnpm test:down
      Tear down test compose and volumes.


OTHER
-----
  pnpm migrate
      Run API database migrations (with .env loaded).

  pnpm test:local:full
      Local validation loop (unit + integration + coverage).

  Helm: pnpm helm:lint, helm:template, helm:verify
`;

process.stdout.write(`${lines.trim()}\n`);
