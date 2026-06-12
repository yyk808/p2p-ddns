#!/usr/bin/env node

import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { createServer as createTcpServer, connect as tcpConnect } from "node:net";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pluginDir = resolve(repoRoot, "plugins/openclaw-p2p-ddns-lan");
const profile = process.env.OPENCLAW_INBOUND_SMOKE_PROFILE ?? "p2pddns-inbound-smoke";
const inboundText = `hello inbound ${Date.now()}`;

const children = new Set();
let transport;
let eventsResponse;
let sawEventsConnection = false;
let sawSend = false;
let sendBodies = [];
let gatewayOutput = "";
const transportSockets = new Set();

try {
  const transportPort = await freePort();
  const gatewayPort = await freePort();
  const transportUrl = `http://127.0.0.1:${transportPort}`;

  await runOpenClaw(["plugins", "install", "--link", pluginDir]);
  await runOpenClaw([
    "config",
    "set",
    'channels["p2p-ddns-lan"].transportUrl',
    transportUrl,
  ]);
  await runOpenClaw(["config", "set", 'channels["p2p-ddns-lan"].dmPolicy', "open"]);

  const gateway = spawnOpenClaw([
    "gateway",
    "run",
    "--port",
    String(gatewayPort),
    "--auth",
    "none",
    "--allow-unconfigured",
    "--force",
    "--verbose",
  ]);
  await waitForTcp("127.0.0.1", gatewayPort, 30_000);
  await waitFor(
    () => gatewayOutput.includes("[p2p-ddns-lan] event stream failed"),
    30_000,
    "OpenClaw did not attempt /events before the fake transport started",
  );
  transport = await startFakeTransport(transportPort);
  await waitFor(() => sawEventsConnection, 20_000, "OpenClaw did not connect to /events");

  const inboundMessageId = emitInboundEvent();
  await waitFor(
    () =>
      gatewayOutput.includes("message processed: channel=p2p-ddns-lan") &&
      gatewayOutput.includes(`messageId=${inboundMessageId}`),
    45_000,
    "inbound message was not processed by the OpenClaw Gateway",
  );
  await waitFor(
    () => sawSend,
    10_000,
    "OpenClaw did not send a reply through the p2p-ddns transport",
  );
  if (!sendBodies.some((body) => body.to === "peer-b")) {
    throw new Error(
      `OpenClaw reply was not addressed to inbound sender peer-b: ${JSON.stringify(
        sendBodies,
      )}`,
    );
  }

  console.log(
    JSON.stringify(
      {
        ok: true,
        profile,
        transportUrl,
        gatewayPort,
        sawEventsConnection,
        sawSend,
        inboundMessageId,
        inboundText,
      },
      null,
      2,
    ),
  );
} finally {
  if (eventsResponse) {
    eventsResponse.end();
    eventsResponse.destroy?.();
  }
  if (transport) {
    transport.closeAllConnections?.();
    for (const socket of transportSockets) {
      socket.destroy();
    }
    await closeServer(transport);
  }
  await Promise.all([...children].map((child) => stopChild(child)));
}

function spawnOpenClaw(args) {
  const child = spawn("openclaw", ["--profile", profile, ...args], {
    cwd: repoRoot,
    stdio: ["ignore", "pipe", "pipe"],
  });
  children.add(child);
  child.stdout.on("data", (chunk) => {
    const text = String(chunk);
    gatewayOutput += text;
    process.stderr.write(`[gateway] ${text}`);
  });
  child.stderr.on("data", (chunk) => {
    const text = String(chunk);
    gatewayOutput += text;
    process.stderr.write(`[gateway] ${text}`);
  });
  child.on("exit", () => {
    children.delete(child);
  });
  return child;
}

function runOpenClaw(args) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn("openclaw", ["--profile", profile, ...args], {
      cwd: repoRoot,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", rejectRun);
    child.on("exit", (code) => {
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

function startFakeTransport(port) {
  const server = createServer(async (req, res) => {
    if (req.method === "GET" && req.url === "/events") {
      sawEventsConnection = true;
      eventsResponse = res;
      res.writeHead(200, {
        "content-type": "text/event-stream",
        "cache-control": "no-cache",
        connection: "keep-alive",
      });
      res.write(": connected\n\n");
      return;
    }

    if (req.method === "POST" && req.url === "/send") {
      const rawBody = await readRequestBody(req);
      try {
        sendBodies.push(JSON.parse(rawBody || "{}"));
      } catch {
        sendBodies.push({ parseError: rawBody });
      }
      sawSend = true;
      writeJson(res, 200, { ok: true, message_id: "smoke-reply-1" });
      return;
    }

    writeJson(res, 404, { ok: false, error: "not found" });
  });
  server.on("connection", (socket) => {
    transportSockets.add(socket);
    socket.on("close", () => transportSockets.delete(socket));
  });

  return new Promise((resolveListen, rejectListen) => {
    server.on("error", rejectListen);
    server.listen(port, "127.0.0.1", () => resolveListen(server));
  });
}

function emitInboundEvent() {
  if (!eventsResponse) {
    throw new Error("cannot emit inbound event before /events connection");
  }
  const now = Math.floor(Date.now() / 1000);
  const id = `inbound-smoke-${now}`;
  const event = {
    message: {
      id,
      from: "peer-b",
      text: inboundText,
      conversation_id: "peer-b",
      timestamp: now,
      metadata: {},
    },
    peer_addr: "127.0.0.1:50000",
    received_at: now,
  };
  eventsResponse.write(`event: message\ndata: ${JSON.stringify(event)}\n\n`);
  return id;
}

function waitFor(predicate, timeoutMs, message) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolveWait, rejectWait) => {
    const tick = async () => {
      try {
        if (await predicate()) {
          resolveWait();
          return;
        }
      } catch (error) {
        rejectWait(error);
        return;
      }
      if (Date.now() >= deadline) {
        rejectWait(new Error(message));
        return;
      }
      setTimeout(tick, 250);
    };
    tick();
  });
}

function waitForTcp(host, port, timeoutMs) {
  return waitFor(
    () =>
      new Promise((resolveConnect) => {
        const socket = tcpConnect({ host, port });
        socket.once("connect", () => {
          socket.destroy();
          resolveConnect(true);
        });
        socket.once("error", () => resolveConnect(false));
        socket.setTimeout(500, () => {
          socket.destroy();
          resolveConnect(false);
        });
      }),
    timeoutMs,
    `gateway did not listen on ${host}:${port}`,
  );
}

function freePort() {
  return new Promise((resolvePort, rejectPort) => {
    const server = createTcpServer();
    server.on("error", rejectPort);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      server.close(() => resolvePort(port));
    });
  });
}

function readRequestBody(req) {
  return new Promise((resolveRead, rejectRead) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolveRead(Buffer.concat(chunks).toString("utf8")));
    req.on("error", rejectRead);
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

function closeServer(server) {
  return new Promise((resolveClose) => {
    const timeout = setTimeout(resolveClose, 1000);
    server.close(() => {
      clearTimeout(timeout);
      resolveClose();
    });
  });
}

function stopChild(child) {
  return new Promise((resolveStop) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolveStop();
      return;
    }
    const timeout = setTimeout(() => {
      child.kill("SIGKILL");
      resolveStop();
    }, 3000);
    child.once("exit", () => {
      clearTimeout(timeout);
      resolveStop();
    });
    child.kill("SIGTERM");
  });
}
