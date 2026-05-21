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
      "dmSecurity": "allowlist"
    }
  }
}
```

Outbound messages use the OpenClaw shared `message` tool through this channel.
The target is a p2p-ddns node domain or node id prefix.

Inbound transport events are read from `GET /events`. The bridge calls a
runtime receive hook when the installed OpenClaw version exposes one; otherwise
it logs the received message so the dispatch adapter can be wired to that exact
runtime surface.
