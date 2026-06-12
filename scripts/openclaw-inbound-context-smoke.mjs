#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const files = [
  "plugins/openclaw-p2p-ddns-lan/src/inbound.ts",
  "plugins/openclaw-p2p-ddns-lan/src/inbound.js",
];

const failures = [];
for (const file of files) {
  const source = await readFile(resolve(repoRoot, file), "utf8");
  if (!source.includes("originatingTo: sender,")) {
    failures.push(`${file} does not route inbound reply context to sender`);
  }
}

if (failures.length) {
  throw new Error(failures.join("\n"));
}

console.log(JSON.stringify({ ok: true, files }, null, 2));
