#!/usr/bin/env node

import { createServer as createTcpServer } from "node:net";

import { createLocalAgentRelay } from "./openclaw-local-agent-relay.mjs";

const portA = await freePort();
const portB = await freePort();
const relay = createLocalAgentRelay([
  { id: "agent-a", host: "127.0.0.1", port: portA, name: "Local Agent A" },
  { id: "agent-b", host: "127.0.0.1", port: portB, name: "Local Agent B" },
], {
  maxPairEventsPerWindow: 2,
  pairWindowMs: 60_000,
});

try {
  await relay.start();

  const contacts = await fetchJson(`http://127.0.0.1:${portA}/contacts`);
  if (!contacts.some((contact) => contact.id === "agent-b" && contact.sendable)) {
    throw new Error("agent-a contacts must include sendable agent-b");
  }

  const eventPromise = readNextEvent(`http://127.0.0.1:${portB}/events`);
  const sendResult = await fetchJson(`http://127.0.0.1:${portA}/send`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      to: "agent-b",
      text: "hello from smoke",
      conversation_id: "smoke-conversation",
    }),
  });
  if (!sendResult.ok || !sendResult.message_id) {
    throw new Error("send result must include ok=true and message_id");
  }

  const event = await eventPromise;
  if (event.message.from !== "agent-a") {
    throw new Error(`expected sender agent-a, got ${event.message.from}`);
  }
  if (event.message.text !== "hello from smoke") {
    throw new Error(`expected smoke text, got ${event.message.text}`);
  }

  await fetchJson(`http://127.0.0.1:${portB}/send`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      to: "agent-a",
      text: "reply from smoke",
      conversation_id: "smoke-conversation",
    }),
  });

  const loopResponse = await fetch(`http://127.0.0.1:${portA}/send`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      to: "agent-b",
      text: "loop from smoke",
      conversation_id: "smoke-conversation",
    }),
  });
  if (loopResponse.status !== 429) {
    const body = await loopResponse.text();
    throw new Error(`expected loop guard HTTP 429, got ${loopResponse.status}: ${body}`);
  }

  console.log(JSON.stringify({ ok: true, ports: [portA, portB] }, null, 2));
} finally {
  await relay.stop();
}

async function fetchJson(url, init) {
  const response = await fetch(url, init);
  const body = await response.json();
  if (!response.ok) {
    throw new Error(`${url} returned HTTP ${response.status}: ${JSON.stringify(body)}`);
  }
  return body;
}

async function readNextEvent(url) {
  const response = await fetch(url);
  if (!response.ok || !response.body) {
    throw new Error(`${url} returned HTTP ${response.status}`);
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  const timeout = AbortSignal.timeout(5000);
  while (!timeout.aborted) {
    const read = reader.read();
    const timer = new Promise((_, reject) => {
      timeout.addEventListener(
        "abort",
        () => reject(new Error("timed out waiting for relay event")),
        { once: true },
      );
    });
    const { value, done } = await Promise.race([read, timer]);
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const chunks = buffer.split("\n\n");
    buffer = chunks.pop() ?? "";
    for (const chunk of chunks) {
      const data = chunk
        .split("\n")
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.slice("data:".length).trimStart())
        .join("\n");
      if (data) {
        await reader.cancel();
        return JSON.parse(data);
      }
    }
  }
  throw new Error("relay event stream closed before receiving an event");
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = createTcpServer();
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => resolve(address.port));
    });
    server.on("error", reject);
  });
}
