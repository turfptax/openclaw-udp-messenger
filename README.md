# Local UDP Messenger

An [OpenClaw](https://docs.openclaw.ai) plugin that lets AI agents communicate with each other over local UDP. Discover peers on the same LAN, exchange messages, and collaborate — with configurable trust, hourly rate limits, and full message logging.

## Features

- **Peer Discovery** — broadcast a ping to find other agents on the network
- **Messaging** — send and receive text messages between agents (supports hostname and IP)
- **Manual Peer Addition** — add peers by hostname or IP without needing broadcast discovery
- **Trust Model** — `approve-once` or `always-confirm` modes, user must approve new peers
- **Hourly Rate Limits** — configurable max exchanges per peer per hour (default: 10) with rolling window
- **Message Log** — full history of all sent/received/system messages for human review
- **Agent Notifications** — agents are notified when trusted peers send messages
- **No Dependencies** — pure Node.js, no external packages required at runtime

## Install

**From npm:**
```bash
openclaw plugins install openclaw-udp-messenger
```

**From GitHub:**
```bash
openclaw plugins install https://github.com/turfptax/openclaw-udp-messenger.git
```

**From ClawHub:**
```bash
clawhub install udp-messenger
```

## Configuration

Add to your `openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "openclaw-udp-messenger": {
        "enabled": true,
        "config": {
          "port": 51337,
          "trustMode": "approve-once",
          "maxExchanges": 10
        }
      }
    }
  }
}
```

| Setting | Default | Description |
|---------|---------|-------------|
| `port` | `51337` | UDP port to listen on |
| `trustMode` | `approve-once` | `approve-once` or `always-confirm` |
| `maxExchanges` | `10` | Max message exchanges per peer **per hour** |

## Tools

The plugin registers these agent tools:

| Tool | Description |
|------|-------------|
| `udp_discover` | Broadcast a discovery ping to find agents on the LAN |
| `udp_send` | Send a message to an agent by ip:port or hostname:port |
| `udp_receive` | Check inbox for pending messages |
| `udp_add_peer` | Manually add and trust a peer by IP or hostname |
| `udp_approve_peer` | Trust a peer (user approval required) |
| `udp_revoke_peer` | Remove trust from a peer |
| `udp_log` | View full message history (sent, received, system events) |
| `udp_status` | View agent ID, port, peers, hourly exchange counts |
| `udp_set_config` | Change max_exchanges or trust_mode at runtime |

## How It Works

1. Each agent gets a unique ID (`hostname-randomhex`) on startup
2. `udp_discover` broadcasts a `CLAUDE-UDP-V1` ping on the LAN
3. Other agents respond with their identity
4. Messages from unknown peers queue up — the agent asks the user to approve
5. Once trusted, messages flow freely and the agent is **notified in real-time**
6. The agent responds to trusted peer messages as if a user is talking to it
7. Exchange counts use a **rolling hourly window** — limits reset automatically
8. All traffic is local UDP — nothing leaves your network
9. Every message is logged — use `udp_log` to review history

## Security

- Peers are **never auto-approved** — the user must explicitly trust each one
- Incoming messages from other agents are treated as **untrusted input**
- Sensitive project data is never shared unless the user explicitly instructs it
- Hourly rate limits prevent unbounded token consumption
- Use `always-confirm` mode on untrusted networks
- Full message log available for audit via `udp_log`

## License

MIT
