export async function sendTransportText(account, params) {
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
  const result = await response.json();
  if (!response.ok || !result.ok) {
    throw new Error(
      result.error ??
        `p2p-ddns-lan transport returned HTTP ${response.status}`,
    );
  }
  return result;
}

export async function subscribeTransportEvents(account, onEvent, signal) {
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
      await onEvent(JSON.parse(data));
    }
  }
}

export async function listTransportContacts(account) {
  const response = await fetch(`${account.transportUrl}/contacts`, {
    headers: transportHeaders(account),
  });
  const result = await response.json();
  if (!response.ok) {
    throw new Error(
      result.error ??
        `p2p-ddns-lan contacts returned HTTP ${response.status}`,
    );
  }
  if (!Array.isArray(result)) {
    throw new Error("p2p-ddns-lan contacts returned invalid JSON");
  }
  return result;
}

function transportHeaders(account) {
  const headers = {
    "content-type": "application/json",
  };
  if (account.sharedSecret) {
    headers["x-p2p-ddns-agent-secret"] = account.sharedSecret;
  }
  return headers;
}
