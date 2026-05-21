import {
  createChannelPluginBase,
  createChatChannelPlugin,
} from "openclaw/plugin-sdk/channel-core";
import {
  createTopLevelChannelConfigAdapter,
  formatTrimmedAllowFromEntries,
} from "openclaw/plugin-sdk/channel-config-helpers";

import { sendTransportText } from "./client.js";
import {
  CHANNEL_ID,
  inspectLanAccount,
  resolveLanAccount,
  type ResolvedLanAccount,
} from "./config.js";

const lanConfigAdapter =
  createTopLevelChannelConfigAdapter<ResolvedLanAccount>({
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

function normalizeLanTarget(raw: string): string | undefined {
  const trimmed = raw.trim();
  if (!trimmed) return undefined;
  const withoutPrefix = trimmed.replace(/^p2p-ddns-lan:/i, "").trim();
  if (!withoutPrefix || /\s/.test(withoutPrefix)) return undefined;
  return withoutPrefix;
}

const lanMessagingAdapter = {
  targetPrefixes: [CHANNEL_ID],
  normalizeTarget: normalizeLanTarget,
  inferTargetChatType: () => "direct" as const,
  targetResolver: {
    looksLikeId: (raw: string, normalized?: string) =>
      Boolean(normalizeLanTarget(normalized ?? raw)),
    hint: "<p2p-ddns-node-id-or-domain>",
    resolveTarget: async ({ normalized }: { normalized: string }) => {
      const target = normalizeLanTarget(normalized);
      if (!target) return null;
      return {
        to: target,
        kind: "user" as const,
        display: target,
        source: "normalized" as const,
      };
    },
  },
};

export const p2pDdnsLanPlugin = createChatChannelPlugin<ResolvedLanAccount>({
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
    messaging: lanMessagingAdapter,
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
      sendText: async (params: any) => {
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
