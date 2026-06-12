#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { basename } from "node:path";
import { fileURLToPath } from "node:url";

const DEFAULT_AGENTS = [
  { id: "agent-a", host: "127.0.0.1", port: 39091, name: "Local Agent A" },
  { id: "agent-b", host: "127.0.0.1", port: 39092, name: "Local Agent B" },
];

export function createLocalAgentRelay(agentConfigs, options = {}) {
  const agents = normalizeAgents(agentConfigs);
  const clients = new Map(agents.map((agent) => [agent.id, new Set()]));
  const queues = new Map(agents.map((agent) => [agent.id, []]));
  const pairEvents = new Map();
  const servers = [];
  const maxQueue = options.maxQueue ?? 100;
  const maxPairEventsPerWindow = positiveInteger(
    options.maxPairEventsPerWindow ?? 4,
  );
  const pairWindowMs = positiveInteger(options.pairWindowMs ?? 30_000);
  const log = options.log ?? (() => {});

  return {
    async start() {
      for (const agent of agents) {
        const server = createServer((req, res) => {
          handleRequest({
            req,
            res,
            source: agent,
            agents,
            clients,
            queues,
            pairEvents,
            maxQueue,
            maxPairEventsPerWindow,
            pairWindowMs,
            log,
          }).catch((error) => {
            writeJson(res, 500, { error: String(error?.message ?? error) });
          });
        });
        await listen(server, agent.host, agent.port);
        servers.push(server);
        log(`listening ${agent.id} http://${agent.host}:${agent.port}`);
      }
    },
    async stop() {
      for (const [, set] of clients) {
        for (const res of set) {
          res.end();
        }
        set.clear();
      }
      await Promise.all(servers.map((server) => closeServer(server)));
      servers.length = 0;
    },
    agents,
  };
}

async function handleRequest({
  req,
  res,
  source,
  agents,
  clients,
  queues,
  pairEvents,
  maxQueue,
  maxPairEventsPerWindow,
  pairWindowMs,
  log,
}) {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);

  if (req.method === "GET" && url.pathname === "/health") {
    writeJson(res, 200, {
      ok: true,
      id: source.id,
      contacts: agents.filter((agent) => agent.id !== source.id).length,
      eventClients: clients.get(source.id)?.size ?? 0,
      queuedEvents: queues.get(source.id)?.length ?? 0,
    });
    return;
  }

  if (req.method === "GET" && url.pathname === "/contacts") {
    writeJson(
      res,
      200,
      agents
        .filter((agent) => agent.id !== source.id)
        .map((agent) => ({
          id: agent.id,
          node_id: agent.id,
          domain: agent.id,
          name: agent.name ?? agent.id,
          addr: `${agent.host}:${agent.port}`,
          sendable: true,
        })),
    );
    return;
  }

  if (req.method === "GET" && url.pathname === "/events") {
    handleEvents(res, source, clients, queues);
    return;
  }

  if (req.method === "POST" && url.pathname === "/send") {
    const body = await readJsonBody(req);
    const target = readNonEmptyString(body.to);
    const text = readNonEmptyString(body.text);
    if (!target || !text) {
      writeJson(res, 400, { ok: false, error: "to and text are required" });
      return;
    }

    const targetAgent = agents.find((agent) => agent.id === target);
    if (!targetAgent) {
      writeJson(res, 404, { ok: false, error: `unknown target ${target}` });
      return;
    }

    if (
      recordPairEventAndCheckSuppression({
        pairEvents,
        sourceId: source.id,
        targetId: targetAgent.id,
        maxPairEventsPerWindow,
        pairWindowMs,
        nowMs: Date.now(),
      })
    ) {
      log(`dropped pair-loop ${source.id} -> ${targetAgent.id}`);
      writeJson(res, 429, {
        ok: false,
        error: "pair loop guard suppressed message",
      });
      return;
    }

    const messageId = `local-relay-${Date.now()}-${randomUUID()}`;
    const event = {
      message: {
        id: messageId,
        from: source.id,
        text,
        conversation_id:
          typeof body.conversation_id === "string" ? body.conversation_id : target,
        timestamp: Date.now(),
        metadata: normalizeMetadata(body.metadata),
      },
      peer_addr: `${source.host}:${source.port}`,
      received_at: Date.now(),
    };

    publishEvent(targetAgent.id, event, clients, queues, maxQueue);
    log(`delivered ${messageId} ${source.id} -> ${targetAgent.id}`);
    writeJson(res, 200, { ok: true, message_id: messageId });
    return;
  }

  writeJson(res, 404, { error: "not found" });
}

function handleEvents(res, source, clients, queues) {
  res.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache",
    connection: "keep-alive",
  });
  res.write(": connected\n\n");

  const set = clients.get(source.id);
  set.add(res);
  res.on("close", () => set.delete(res));

  const queue = queues.get(source.id);
  while (queue.length > 0) {
    writeEvent(res, queue.shift());
  }
}

function publishEvent(targetId, event, clients, queues, maxQueue) {
  const set = clients.get(targetId);
  if (set && set.size > 0) {
    for (const res of set) {
      writeEvent(res, event);
    }
    return;
  }

  const queue = queues.get(targetId);
  queue.push(event);
  if (queue.length > maxQueue) {
    queue.splice(0, queue.length - maxQueue);
  }
}

function writeEvent(res, event) {
  res.write(`data: ${JSON.stringify(event)}\n\n`);
}

async function readJsonBody(req) {
  let body = "";
  for await (const chunk of req) {
    body += chunk;
    if (body.length > 1024 * 1024) {
      throw new Error("request body too large");
    }
  }
  return body ? JSON.parse(body) : {};
}

function readNonEmptyString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function normalizeMetadata(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return Object.fromEntries(
    Object.entries(value)
      .filter(([, item]) => typeof item === "string")
      .map(([key, item]) => [key, item]),
  );
}

function recordPairEventAndCheckSuppression({
  pairEvents,
  sourceId,
  targetId,
  maxPairEventsPerWindow,
  pairWindowMs,
  nowMs,
}) {
  if (!maxPairEventsPerWindow || !pairWindowMs || sourceId === targetId) {
    return false;
  }
  const key = [sourceId, targetId].sort().join("\u0001");
  const cutoff = nowMs - pairWindowMs;
  const recent = (pairEvents.get(key) ?? []).filter((timestamp) => timestamp > cutoff);
  if (recent.length >= maxPairEventsPerWindow) {
    pairEvents.set(key, recent);
    return true;
  }
  recent.push(nowMs);
  pairEvents.set(key, recent);
  return false;
}

function positiveInteger(value) {
  return Number.isInteger(value) && value > 0 ? value : undefined;
}

function normalizeAgents(agentConfigs) {
  const agents = agentConfigs.map((agent) => ({
    id: readNonEmptyString(agent.id),
    host: readNonEmptyString(agent.host) ?? "127.0.0.1",
    port: Number(agent.port),
    name: readNonEmptyString(agent.name),
  }));

  for (const agent of agents) {
    if (!agent.id) throw new Error("agent id is required");
    if (!Number.isInteger(agent.port) || agent.port <= 0) {
      throw new Error(`invalid port for ${agent.id}`);
    }
  }

  const ids = new Set();
  for (const agent of agents) {
    if (ids.has(agent.id)) throw new Error(`duplicate agent id ${agent.id}`);
    ids.add(agent.id);
  }
  return agents;
}

function listen(server, host, port) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
}

function closeServer(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

function writeJson(res, status, body) {
  if (res.headersSent) return;
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

function parseArgs(argv) {
  const agents = [];
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--agent") {
      agents.push(parseAgentSpec(argv[++i]));
    } else if (arg === "--help" || arg === "-h") {
      printHelp();
      process.exit(0);
    } else {
      throw new Error(`unknown argument ${arg}`);
    }
  }
  return agents.length > 0 ? agents : DEFAULT_AGENTS;
}

function parseAgentSpec(spec) {
  const parts = String(spec ?? "").split(":");
  if (parts.length === 2) {
    return { id: parts[0], host: "127.0.0.1", port: Number(parts[1]) };
  }
  if (parts.length >= 3) {
    return {
      id: parts[0],
      host: parts[1],
      port: Number(parts[2]),
      name: parts.slice(3).join(":") || undefined,
    };
  }
  throw new Error(`invalid --agent spec ${spec}`);
}

function printHelp() {
  console.log(`Usage: node ${basename(process.argv[1])} [--agent id:port] [--agent id:host:port[:name]]

Starts local p2p-ddns-lan transport endpoints for OpenClaw-to-OpenClaw testing.
Defaults:
  agent-a:127.0.0.1:39091
  agent-b:127.0.0.1:39092`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const relay = createLocalAgentRelay(parseArgs(process.argv.slice(2)), {
    log: (message) => console.error(`[local-relay] ${message}`),
  });
  await relay.start();
  const stop = async () => {
    await relay.stop();
    process.exit(0);
  };
  process.once("SIGINT", stop);
  process.once("SIGTERM", stop);
}
