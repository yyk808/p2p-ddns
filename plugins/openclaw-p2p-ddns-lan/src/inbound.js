import {
  dispatchInboundDirectDmWithRuntime,
} from "openclaw/plugin-sdk/channel-inbound";
import {
  deliverFormattedTextWithAttachments,
} from "openclaw/plugin-sdk/reply-payload";

import { sendTransportText, subscribeTransportEvents } from "./client.js";
import { CHANNEL_ID, resolveLanAccount } from "./config.js";

const INITIAL_RECONNECT_DELAY_MS = 1000;
const MAX_RECONNECT_DELAY_MS = 30_000;

export async function startLanInboundBridge(api) {
  const account = resolveLanAccount(api.config, null);
  const abort = new AbortController();
  registerShutdown(api, abort);

  let delayMs = INITIAL_RECONNECT_DELAY_MS;
  while (!abort.signal.aborted) {
    try {
      await subscribeTransportEvents(
        account,
        async (event) => {
          if (!isAllowedSender(account, event.message.from)) {
            api.logger.warn(
              `[${CHANNEL_ID}] dropped message from disallowed sender ${event.message.from}`,
            );
            return;
          }
          await dispatchInboundEvent(api, account, event);
        },
        abort.signal,
      );
      delayMs = INITIAL_RECONNECT_DELAY_MS;
      if (!abort.signal.aborted) {
        api.logger.warn(`[${CHANNEL_ID}] event stream closed; reconnecting`);
      }
    } catch (error) {
      if (abort.signal.aborted || isAbortError(error)) {
        return;
      }
      api.logger.warn(
        `[${CHANNEL_ID}] event stream failed: ${String(error)}; reconnecting in ${delayMs}ms`,
      );
    }
    await sleep(delayMs, abort.signal);
    delayMs = Math.min(delayMs * 2, MAX_RECONNECT_DELAY_MS);
  }
}

async function dispatchInboundEvent(api, account, event) {
  const sender = event.message.from;
  await dispatchInboundDirectDmWithRuntime({
    cfg: api.config,
    runtime: api.runtime,
    channel: CHANNEL_ID,
    channelLabel: "p2p-ddns LAN",
    accountId: account.accountId ?? "default",
    peer: { kind: "direct", id: sender },
    senderId: sender,
    senderAddress: sender,
    recipientAddress: account.accountId ?? CHANNEL_ID,
    conversationLabel: sender,
    rawBody: event.message.text,
    bodyForAgent: event.message.text,
    commandBody: event.message.text,
    messageId: event.message.id,
    timestamp: event.message.timestamp,
    commandAuthorized: true,
    provider: CHANNEL_ID,
    surface: CHANNEL_ID,
    originatingChannel: CHANNEL_ID,
    originatingTo: sender,
    extraContext: {
      PeerAddr: event.peer_addr,
      ReceivedAt: event.received_at,
      ConversationId: event.message.conversation_id ?? sender,
    },
    deliver: async (payload) => {
      await deliverReplyToSender(account, sender, event, payload);
    },
    onRecordError: (error) => {
      api.logger.warn(
        `[${CHANNEL_ID}] failed to record inbound message ${event.message.id}: ${String(error)}`,
      );
    },
    onDispatchError: (error, info) => {
      api.logger.warn(
        `[${CHANNEL_ID}] failed to dispatch inbound message ${event.message.id} (${info.kind}): ${String(error)}`,
      );
    },
  });
}

function isAllowedSender(account, sender) {
  return account.allowFrom.length === 0 || account.allowFrom.includes(sender);
}

async function deliverReplyToSender(account, sender, event, payload) {
  await deliverFormattedTextWithAttachments({
    payload,
    send: async ({ text }) => {
      await sendTransportText(account, {
        to: sender,
        text,
        conversationId: event.message.conversation_id ?? sender,
        metadata: {
          reply_to: event.message.id,
        },
      });
    },
  });
}

function registerShutdown(api, abort) {
  api.lifecycle.registerRuntimeLifecycle({
    id: `${CHANNEL_ID}.inbound-bridge`,
    description: "Stop the p2p-ddns LAN inbound bridge.",
    cleanup: () => abort.abort(),
  });
}

function sleep(ms, signal) {
  if (signal.aborted) {
    return Promise.resolve();
  }
  return new Promise((resolve) => {
    const timeout = setTimeout(resolve, ms);
    signal.addEventListener(
      "abort",
      () => {
        clearTimeout(timeout);
        resolve();
      },
      { once: true },
    );
  });
}

function isAbortError(error) {
  return error instanceof DOMException && error.name === "AbortError";
}
