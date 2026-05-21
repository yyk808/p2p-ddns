export const CHANNEL_ID = "p2p-ddns-lan";
export const DEFAULT_TRANSPORT_URL = "http://127.0.0.1:39091";

export function resolveLanAccount(cfg, accountId) {
  const section = cfg.channels?.[CHANNEL_ID] ?? {};
  const transportUrl = normalizeTransportUrl(
    readString(section.transportUrl) ??
      process.env.P2P_DDNS_AGENT_TRANSPORT_URL ??
      DEFAULT_TRANSPORT_URL,
  );
  return {
    accountId: accountId ?? "default",
    transportUrl,
    sharedSecret:
      readString(section.sharedSecret) ?? process.env.P2P_DDNS_AGENT_SECRET,
    allowFrom: readStringArray(section.allowFrom),
    dmPolicy: readString(section.dmPolicy) ?? readString(section.dmSecurity),
  };
}

export function inspectLanAccount(cfg, accountId) {
  const account = resolveLanAccount(cfg, accountId);
  return {
    enabled: true,
    configured: Boolean(account.transportUrl),
    tokenStatus: account.sharedSecret ? "available" : "missing",
  };
}

export function normalizeTransportUrl(value) {
  const trimmed = value.trim().replace(/\/+$/, "");
  if (!trimmed) {
    throw new Error(`${CHANNEL_ID}: transportUrl is required`);
  }
  return trimmed;
}

function readString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function readStringArray(value) {
  return Array.isArray(value)
    ? value.filter((item) => typeof item === "string")
    : [];
}
