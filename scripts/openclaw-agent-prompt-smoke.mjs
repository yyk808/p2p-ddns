#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { mkdtemp, cp, mkdir, symlink, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pluginDir = resolve(repoRoot, "plugins/openclaw-p2p-ddns-lan");

const tempRoot = await mkdtemp(join(tmpdir(), "p2pddns-openclaw-plugin-"));
const originalFetch = globalThis.fetch;

try {
  const testPluginDir = join(tempRoot, "p2p-ddns-lan");
  const globalNodeModules = String(execFileSync("npm", ["root", "-g"])).trim();
  const openclawPackage = join(globalNodeModules, "openclaw");

  await cp(pluginDir, testPluginDir, { recursive: true });
  await mkdir(join(testPluginDir, "node_modules"), { recursive: true });
  await symlink(openclawPackage, join(testPluginDir, "node_modules", "openclaw"));

  const moduleUrl = pathToFileURL(join(testPluginDir, "src/channel.js")).href;
  const { p2pDdnsLanPlugin } = await import(moduleUrl);
  const agentPrompt = p2pDdnsLanPlugin?.agentPrompt;

  if (!agentPrompt) {
    throw new Error("p2p-ddns-lan plugin must expose agentPrompt");
  }

  const hints = agentPrompt.messageToolHints?.({ cfg: {}, accountId: "default" });
  if (!Array.isArray(hints) || hints.length === 0) {
    throw new Error("agentPrompt.messageToolHints must return hints");
  }

  const hintText = hints.join("\n").toLowerCase();
  for (const expected of ["p2p-ddns-lan", "message", "directory", "target"]) {
    if (!hintText.includes(expected)) {
      throw new Error(`messageToolHints missing ${expected}`);
    }
  }

  const capabilities = agentPrompt.messageToolCapabilities?.({
    cfg: {},
    accountId: "default",
  });
  if (!Array.isArray(capabilities) || capabilities.length === 0) {
    throw new Error("agentPrompt.messageToolCapabilities must return capabilities");
  }

  const capabilityText = capabilities.join("\n").toLowerCase();
  for (const expected of ["direct", "lan", "directory"]) {
    if (!capabilityText.includes(expected)) {
      throw new Error(`messageToolCapabilities missing ${expected}`);
    }
  }

  const agentToolsEntry = p2pDdnsLanPlugin?.agentTools;
  if (!agentToolsEntry) {
    throw new Error("p2p-ddns-lan plugin must expose agentTools");
  }

  const sentBodies = [];
  globalThis.fetch = async (url, options = {}) => {
    const pathname = new URL(String(url)).pathname;
    if (pathname === "/contacts") {
      return new Response(
        JSON.stringify([
          {
            id: "agent-b",
            node_id: "node-b",
            domain: "agent-b.local",
            name: "Local Agent B",
            addr: "127.0.0.1:39092",
            sendable: true,
          },
        ]),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }
    if (pathname === "/send") {
      sentBodies.push(JSON.parse(String(options.body ?? "{}")));
      return new Response(JSON.stringify({ ok: true, message_id: "msg-1" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`unexpected fetch URL: ${url}`);
  };

  const cfg = {
    channels: {
      "p2p-ddns-lan": {
        transportUrl: "http://127.0.0.1:39091",
      },
    },
  };
  const tools =
    typeof agentToolsEntry === "function"
      ? agentToolsEntry({ cfg })
      : agentToolsEntry;
  const toolNames = new Set(tools.map((tool) => tool.name));
  for (const expected of ["p2p_ddns_lan_contacts", "p2p_ddns_lan_send"]) {
    if (!toolNames.has(expected)) {
      throw new Error(`agentTools missing ${expected}`);
    }
  }

  const contactsTool = tools.find(
    (tool) => tool.name === "p2p_ddns_lan_contacts",
  );
  const contactsResult = await contactsTool.execute("contacts-call", {
    query: "Agent B",
  });
  const contactsText = contactsResult.content
    .filter((item) => item.type === "text")
    .map((item) => item.text)
    .join("\n");
  if (
    !contactsText.includes("agent-b") ||
    !contactsText.includes("p2p_ddns_lan_send")
  ) {
    throw new Error("contacts tool must return agent-b and send-tool guidance");
  }

  const sendTool = tools.find((tool) => tool.name === "p2p_ddns_lan_send");
  const sendResult = await sendTool.execute("send-call", {
    target: "agent-b",
    message: "hello from smoke",
  });
  if (sendResult.details?.messageId !== "msg-1") {
    throw new Error("send tool must expose messageId in details");
  }
  if (
    !sentBodies.some(
      (body) => body.to === "agent-b" && body.text === "hello from smoke",
    )
  ) {
    throw new Error("send tool must POST target and message to transport");
  }

  console.log(
    JSON.stringify(
      {
        ok: true,
        hints,
        capabilities,
        toolNames: Array.from(toolNames).sort(),
      },
      null,
      2,
    ),
  );
} finally {
  globalThis.fetch = originalFetch;
  await rm(tempRoot, { recursive: true, force: true });
}
