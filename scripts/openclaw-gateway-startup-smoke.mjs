#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { mkdtemp, cp, mkdir, symlink, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pluginDir = resolve(repoRoot, "plugins/openclaw-p2p-ddns-lan");

const tempRoot = await mkdtemp(join(tmpdir(), "p2pddns-openclaw-startup-"));

try {
  const testPluginDir = join(tempRoot, "p2p-ddns-lan");
  const globalNodeModules = String(execFileSync("npm", ["root", "-g"])).trim();
  const openclawPackage = join(globalNodeModules, "openclaw");

  await cp(pluginDir, testPluginDir, { recursive: true });
  await mkdir(join(testPluginDir, "node_modules"), { recursive: true });
  await symlink(openclawPackage, join(testPluginDir, "node_modules", "openclaw"));

  const moduleUrl = pathToFileURL(join(testPluginDir, "index.js")).href;
  const { shouldStartInboundBridge } = await import(moduleUrl);

  if (typeof shouldStartInboundBridge !== "function") {
    throw new Error("index.js must export shouldStartInboundBridge for startup tests");
  }

  assertStartup(
    "foreground gateway run starts inbound bridge",
    true,
    ["node", "openclaw", "gateway", "run", "--port", "18789"],
  );
  assertStartup(
    "service gateway starts inbound bridge",
    true,
    ["node", "openclaw", "gateway", "--port", "18790"],
  );
  assertStartup(
    "gateway status does not start inbound bridge",
    false,
    ["node", "openclaw", "gateway", "status"],
  );
  assertStartup(
    "non-gateway registration does not start inbound bridge",
    false,
    ["node", "openclaw", "models", "status"],
  );

  console.log(JSON.stringify({ ok: true }, null, 2));

  function assertStartup(name, expected, argv) {
    const actual = shouldStartInboundBridge(
      { registrationMode: "full" },
      argv,
    );
    if (actual !== expected) {
      throw new Error(`${name}: expected ${expected}, got ${actual}`);
    }
  }
} finally {
  await rm(tempRoot, { recursive: true, force: true });
}
