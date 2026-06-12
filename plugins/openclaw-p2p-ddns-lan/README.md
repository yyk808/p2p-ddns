# p2p-ddns LAN OpenClaw Channel

This channel keeps p2p-ddns as discovery only. Actual agent messages go through
`p2p-ddns-agent-transport`, which resolves a target node through the p2p-ddns
admin command API and then sends JSON directly to the peer transport.

## Runtime

Start p2p-ddns normally, then run one transport per OpenClaw host:

```bash
p2p-ddns-agent-transport --local-id agent-a --bind 0.0.0.0:39091
```

If the p2p-ddns daemon only exposes admin HTTP:

```bash
p2p-ddns-agent-transport \
  --local-id agent-a \
  --admin-http 127.0.0.1:8080 \
  --ticket '<ticket>'
```

## OpenClaw Config

```json
{
  "channels": {
    "p2p-ddns-lan": {
      "transportUrl": "http://127.0.0.1:39091",
      "allowFrom": ["agent-b"],
      "dmPolicy": "allowlist"
    }
  }
}
```

Outbound messages use the OpenClaw shared `message` tool through this channel.
The target is a p2p-ddns node domain or node id prefix.

Contacts are exposed through the OpenClaw directory command. The transport
derives them from the p2p-ddns admin `Query` result and lists nodes that have a
non-local direct IP candidate on the configured transport port:

```bash
openclaw directory peers list --channel p2p-ddns-lan
```

Inbound transport events are read from `GET /events`. The bridge calls a
standard OpenClaw direct-DM runtime helper and reconnects with backoff if the
transport is not available yet or the event stream closes.

## Smoke Tests

Verify outbound delivery through OpenClaw:

```bash
openclaw message send \
  --channel p2p-ddns-lan \
  --target <node-id-or-domain> \
  --message "hello"
```

Verify inbound handling with an isolated OpenClaw profile and fake transport:

```bash
node scripts/openclaw-inbound-smoke.mjs
```

Verify directory/contact listing:

```bash
node scripts/openclaw-directory-smoke.mjs
```

Verify the OpenClaw agent prompt contract for the shared message tool:

```bash
node scripts/openclaw-agent-prompt-smoke.mjs
```

The inbound smoke starts the OpenClaw Gateway before the fake transport, so it
also verifies that the `/events` bridge reconnects after startup ordering races.
