import type { ResolvedLanAccount } from "./config.js";

export type TransportSendResponse = {
  ok: boolean;
  message_id?: string;
  error?: string;
};

export type TransportEvent = {
  message: {
    id: string;
    from: string;
    text: string;
    conversation_id?: string | null;
    timestamp: number;
    metadata?: Record<string, string>;
  };
  peer_addr: string;
  received_at: number;
};

export type TransportContact = {
  id: string;
  node_id: string;
  domain?: string;
  name?: string;
  addr?: string;
  sendable: boolean;
};

export async function sendTransportText(
  account: ResolvedLanAccount,
  params: {
    to: string;
    text: string;
    conversationId?: string | null;
    metadata?: Record<string, string>;
    signal?: AbortSignal;
  },
): Promise<TransportSendResponse> {
  const response = await fetch(`${account.transportUrl}/send`, {
    method: "POST",
    headers: transportHeaders(account),
    body: JSON.stringify({
      to: params.to,
      text: params.text,
      conversation_id: params.conversationId ?? null,
      metadata: params.metadata ?? {},
    }),
    signal: params.signal,
  });
  const result = (await response.json()) as TransportSendResponse;
  if (!response.ok || !result.ok) {
    throw new Error(
      result.error ??
        `p2p-ddns-lan transport returned HTTP ${response.status}`,
    );
  }
  return result;
}

export async function subscribeTransportEvents(
  account: ResolvedLanAccount,
  onEvent: (event: TransportEvent) => Promise<void> | void,
  signal?: AbortSignal,
): Promise<void> {
  const response = await fetch(`${account.transportUrl}/events`, {
    headers: transportHeaders(account),
    signal,
  });
  if (!response.ok || !response.body) {
    throw new Error(`p2p-ddns-lan events returned HTTP ${response.status}`);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { value, done } = await reader.read();
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
      if (!data) continue;
      await onEvent(JSON.parse(data) as TransportEvent);
    }
  }
}

export async function listTransportContacts(
  account: ResolvedLanAccount,
): Promise<TransportContact[]> {
  const response = await fetch(`${account.transportUrl}/contacts`, {
    headers: transportHeaders(account),
  });
  const result = (await response.json()) as TransportContact[] | { error?: string };
  if (!response.ok) {
    throw new Error(
      readTransportError(result) ||
        `p2p-ddns-lan contacts returned HTTP ${response.status}`,
    );
  }
  if (!Array.isArray(result)) {
    throw new Error("p2p-ddns-lan contacts returned invalid JSON");
  }
  return result;
}

function readTransportError(value: unknown): string | undefined {
  return value &&
    typeof value === "object" &&
    "error" in value &&
    typeof value.error === "string"
    ? value.error
    : undefined;
}

function transportHeaders(account: ResolvedLanAccount): Record<string, string> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
  };
  if (account.sharedSecret) {
    headers["x-p2p-ddns-agent-secret"] = account.sharedSecret;
  }
  return headers;
}
