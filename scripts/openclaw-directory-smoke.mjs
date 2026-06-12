#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { createServer as createTcpServer } from "node:net";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pluginDir = resolve(repoRoot, "plugins/openclaw-p2p-ddns-lan");
const profile = process.env.OPENCLAW_DIRECTORY_SMOKE_PROFILE ?? "p2pddns-directory-smoke";
const OPENCLAW_TIMEOUT_MS = 30_000;

let server;
const sockets = new Set();

try {
  const transportPort = await freePort();
  const transportUrl = `http://127.0.0.1:${transportPort}`;
  server = await startFakeTransport(transportPort);

  await runOpenClaw(["plugins", "install", "--link", pluginDir]);
  await runOpenClaw([
    "config",
    "set",
    'channels["p2p-ddns-lan"].transportUrl',
    transportUrl,
  ]);

  const raw = await runOpenClaw([
    "directory",
    "peers",
    "list",
    "--channel",
    "p2p-ddns-lan",
    "--json",
  ]);
  const entries = JSON.parse(raw);

  if (!Array.isArray(entries)) {
    throw new Error("directory output was not an array");
  }
  const ids = entries.map((entry) => entry.id);
  if (!ids.includes("agent-b") || !ids.includes("node-c")) {
    throw new Error(`missing expected contacts: ${ids.join(", ")}`);
  }
  if (ids.includes("agent-offline")) {
    throw new Error("non-sendable contact should not be listed");
  }

  console.log(
    JSON.stringify(
      {
        ok: true,
        profile,
        transportUrl,
        ids,
      },
      null,
      2,
    ),
  );
} finally {
  if (server) {
    server.closeAllConnections?.();
    for (const socket of sockets) {
      socket.destroy();
    }
    await closeServer(server);
  }
}

function startFakeTransport(port) {
  const contacts = [
    {
      id: "agent-b",
      node_id: "node-b-id",
      domain: "agent-b",
      name: "agent-b",
      addr: "10.1.0.2:39091",
      sendable: true,
    },
    {
      id: "node-c",
      node_id: "node-c",
      addr: "10.1.0.3:39091",
      sendable: true,
    },
    {
      id: "agent-offline",
      node_id: "node-offline",
      domain: "agent-offline",
      sendable: false,
    },
  ];
  const fake = createServer((req, res) => {
    if (req.method === "GET" && req.url === "/contacts") {
      writeJson(res, 200, contacts);
      return;
    }
    writeJson(res, 404, { ok: false, error: "not found" });
  });
  fake.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });

  return new Promise((resolveListen, rejectListen) => {
    fake.on("error", rejectListen);
    fake.listen(port, "127.0.0.1", () => resolveListen(fake));
  });
}

function runOpenClaw(args) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn("openclaw", ["--profile", profile, ...args], {
      cwd: repoRoot,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => {
      child.kill("SIGKILL");
      rejectRun(
        new Error(
          `openclaw ${args.join(" ")} timed out after ${OPENCLAW_TIMEOUT_MS}ms\n${stdout}\n${stderr}`,
        ),
      );
    }, OPENCLAW_TIMEOUT_MS);
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", rejectRun);
    child.on("exit", (code) => {
      clearTimeout(timeout);
      if (code === 0) {
        resolveRun(stdout);
      } else {
        rejectRun(
          new Error(
            `openclaw ${args.join(" ")} failed with ${code}\n${stdout}\n${stderr}`,
          ),
        );
      }
    });
  });
}

function freePort() {
  return new Promise((resolvePort, rejectPort) => {
    const probe = createTcpServer();
    probe.on("error", rejectPort);
    probe.listen(0, "127.0.0.1", () => {
      const address = probe.address();
      const port = typeof address === "object" && address ? address.port : 0;
      probe.close(() => resolvePort(port));
    });
  });
}

function writeJson(res, status, body) {
  const raw = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(raw),
  });
  res.end(raw);
}

function closeServer(target) {
  return new Promise((resolveClose) => {
    const timeout = setTimeout(resolveClose, 1000);
    target.close(() => {
      clearTimeout(timeout);
      resolveClose();
    });
  });
}
