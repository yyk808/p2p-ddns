import {
  createChannelPluginBase,
  createChatChannelPlugin,
} from "openclaw/plugin-sdk/channel-core";
import {
  createTopLevelChannelConfigAdapter,
  formatTrimmedAllowFromEntries,
} from "openclaw/plugin-sdk/channel-config-helpers";

import { listTransportContacts, sendTransportText } from "./client.js";
import { CHANNEL_ID, inspectLanAccount, resolveLanAccount } from "./config.js";

const lanConfigAdapter = createTopLevelChannelConfigAdapter({
  sectionKey: CHANNEL_ID,
  resolveAccount: (cfg) => resolveLanAccount(cfg, "default"),
  inspectAccount: (cfg) => inspectLanAccount(cfg, "default"),
  deleteMode: "clear-fields",
  clearBaseFields: [
    "transportUrl",
    "sharedSecret",
    "allowFrom",
    "dmPolicy",
    "dmSecurity",
  ],
  resolveAllowFrom: (account) => account.allowFrom,
  formatAllowFrom: formatTrimmedAllowFromEntries,
});

function normalizeLanTarget(raw) {
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  const withoutPrefix = trimmed.replace(/^p2p-ddns-lan:/i, "").trim();
  if (!withoutPrefix || /\s/.test(withoutPrefix)) return undefined;
  return withoutPrefix;
}

const lanMessagingAdapter = {
  targetPrefixes: [CHANNEL_ID],
  normalizeTarget: normalizeLanTarget,
  inferTargetChatType: () => "direct",
  targetResolver: {
    looksLikeId: (raw, normalized) =>
      Boolean(normalizeLanTarget(normalized ?? raw)),
    hint: "<p2p-ddns-node-id-or-domain>",
    resolveTarget: async ({ normalized }) => {
      const target = normalizeLanTarget(normalized);
      if (!target) return null;
      return {
        to: target,
        kind: "user",
        display: target,
        source: "normalized",
      };
    },
  },
};

const lanAgentPromptAdapter = {
  messageToolHints: () => [
    "- Use channel `p2p-ddns-lan` when the user asks to contact another OpenClaw agent on the p2p-ddns LAN.",
    '- For outbound sends, use `message(action="send", channel="p2p-ddns-lan", target="<peer-id>", message="...")`; targets are p2p-ddns node domains or node id prefixes.',
    "- If the user names a LAN agent but does not give an exact target, resolve it through the `p2p-ddns-lan` directory and use the returned peer `id` as the target.",
    "- This channel supports direct messages only; do not use it for groups or broadcast.",
  ],
  messageToolCapabilities: () => [
    "Direct LAN text messaging to OpenClaw agents discovered by p2p-ddns.",
    "Live peer directory from p2p-ddns contacts; returned peer ids are valid message targets.",
  ],
};

const lanContactsToolParameters = {
  type: "object",
  properties: {
    query: {
      type: "string",
      description: "Optional case-insensitive peer id, name, or node id filter.",
    },
    limit: {
      type: "number",
      description: "Optional maximum number of contacts to return.",
    },
  },
  additionalProperties: false,
};

const lanSendToolParameters = {
  type: "object",
  properties: {
    target: {
      type: "string",
      description:
        "p2p-ddns LAN peer id returned by p2p_ddns_lan_contacts, for example agent-b.",
    },
    message: {
      type: "string",
      description: "Plain text message to send to the target LAN agent.",
    },
    conversationId: {
      type: "string",
      description:
        "Optional conversation id. Defaults to the normalized target peer id.",
    },
  },
  required: ["target", "message"],
  additionalProperties: false,
};

const lanAgentTools = ({ cfg } = {}) => [
  {
    name: "p2p_ddns_lan_contacts",
    label: "p2p-ddns LAN Contacts",
    description:
      "List currently sendable OpenClaw agents reachable through the p2p-ddns LAN plugin. Use this when the user asks whether you can see contacts, local agents, LAN agents, peer agents, or who can receive p2p-ddns LAN messages.",
    parameters: lanContactsToolParameters,
    async execute(_toolCallId, rawParams) {
      const params = asParams(rawParams);
      const peers = await listLanDirectoryPeers({
        cfg: cfg ?? {},
        query: readOptionalString(params.query),
        limit: readPositiveInteger(params.limit),
      });
      const contacts = peers.map(directoryPeerToToolContact);
      return jsonToolResult({
        ok: true,
        channel: CHANNEL_ID,
        contacts,
        guidance:
          "Use p2p_ddns_lan_send with a contact target to message one of these LAN agents.",
      });
    },
  },
  {
    name: "p2p_ddns_lan_send",
    label: "p2p-ddns LAN Send",
    ownerOnly: true,
    description:
      "Send a direct text message to another OpenClaw agent through the p2p-ddns LAN transport. Use this after p2p_ddns_lan_contacts, or when the user gives an exact LAN peer id such as agent-b.",
    parameters: lanSendToolParameters,
    async execute(_toolCallId, rawParams, signal) {
      const params = asParams(rawParams);
      const target = normalizeLanTarget(
        readRequiredString(params.target, "target"),
      );
      if (!target) {
        throw new Error("target must be a non-empty p2p-ddns LAN peer id");
      }
      const message = readRequiredString(params.message, "message");
      const result = await sendTransportText(
        resolveLanAccount(cfg ?? {}, "default"),
        {
          to: target,
          text: message,
          conversationId: readOptionalString(params.conversationId) ?? target,
          signal,
        },
      );
      return jsonToolResult({
        ok: true,
        channel: CHANNEL_ID,
        target,
        messageId: result.message_id ?? null,
      });
    },
  },
];

async function listLanDirectoryPeers({ cfg, accountId, query, limit }) {
  const account = resolveLanAccount(cfg, accountId);
  const contacts = await listTransportContacts(account);
  const q = normalizeDirectoryQuery(query);
  const peers = [];
  for (const contact of contacts) {
    const peer = contactToDirectoryPeer(contact, q);
    if (!peer) continue;
    peers.push(peer);
    if (typeof limit === "number" && limit > 0 && peers.length >= limit) {
      break;
    }
  }
  return peers;
}

function contactToDirectoryPeer(contact, query) {
  if (!contact || contact.sendable === false) return null;
  const id = readContactString(contact.id);
  if (!id) return null;
  const name =
    readContactString(contact.name) ?? readContactString(contact.domain);
  const haystack = [id, name, readContactString(contact.node_id)]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  if (query && !haystack.includes(query)) return null;
  return {
    kind: "user",
    id,
    name,
    raw: contact,
  };
}

function directoryPeerToToolContact(peer) {
  return {
    id: peer.id,
    target: peer.id,
    name: peer.name,
    node_id: readContactString(peer.raw.node_id),
    domain: readContactString(peer.raw.domain),
    addr: readContactString(peer.raw.addr),
    sendable: peer.raw.sendable !== false,
    sendTool: "p2p_ddns_lan_send",
  };
}

function normalizeDirectoryQuery(query) {
  return typeof query === "string" && query.trim()
    ? query.trim().toLowerCase()
    : "";
}

function readContactString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function asParams(value) {
  return value && typeof value === "object" ? value : {};
}

function readOptionalString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function readRequiredString(value, label) {
  const resolved = readOptionalString(value);
  if (!resolved) {
    throw new Error(`${label} is required`);
  }
  return resolved;
}

function readPositiveInteger(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return undefined;
  const integer = Math.trunc(value);
  return integer > 0 ? integer : undefined;
}

function jsonToolResult(payload) {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(payload, null, 2),
      },
    ],
    details: payload,
  };
}

export const p2pDdnsLanPlugin = createChatChannelPlugin({
  base: {
    ...createChannelPluginBase({
      id: CHANNEL_ID,
      meta: {
        id: CHANNEL_ID,
        label: "p2p-ddns LAN",
        selectionLabel: "p2p-ddns LAN",
        docsPath: "/channels/p2p-ddns-lan",
        blurb:
          "Use p2p-ddns discovery plus a direct LAN transport for agent messages.",
      },
      capabilities: {
        chatTypes: ["direct"],
        media: false,
      },
      reload: { configPrefixes: [`channels.${CHANNEL_ID}`] },
      config: {
        ...lanConfigAdapter,
        isConfigured: (account) => Boolean(account.transportUrl),
        describeAccount: (account) => ({
          accountId: account.accountId,
          name: account.accountId,
          configured: Boolean(account.transportUrl),
          enabled: true,
          baseUrl: account.transportUrl,
          tokenStatus: account.sharedSecret ? "available" : "missing",
          dmPolicy: account.dmPolicy,
          allowFrom: account.allowFrom,
        }),
      },
    }),
    agentPrompt: lanAgentPromptAdapter,
    agentTools: lanAgentTools,
    messaging: lanMessagingAdapter,
    directory: {
      listPeers: listLanDirectoryPeers,
      listPeersLive: listLanDirectoryPeers,
    },
  },
  security: {
    dm: {
      channelKey: CHANNEL_ID,
      resolvePolicy: (account) => account.dmPolicy,
      resolveAllowFrom: (account) => account.allowFrom,
      defaultPolicy: "allowlist",
    },
  },
  threading: { topLevelReplyToMode: "reply" },
  outbound: {
    attachedResults: {
      sendText: async (params) => {
        const account =
          params.account ?? resolveLanAccount(params.cfg, params.accountId);
        const result = await sendTransportText(account, {
          to: params.to,
          text: params.text,
          conversationId:
            params.threadId == null ? params.to : String(params.threadId),
          signal: params.signal,
        });
        return { messageId: result.message_id };
      },
    },
  },
});
