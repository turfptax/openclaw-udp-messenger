# Local UDP Messenger

An [OpenClaw](https://docs.openclaw.ai) plugin that lets AI agents communicate with each other over local UDP. Discover peers on the same LAN, exchange messages, and collaborate — with configurable trust and conversation limits.

## Features

- **Peer Discovery** — broadcast a ping to find other agents on the network
- **Messaging** — send and receive text messages between agents
- **Trust Model** — `approve-once` or `always-confirm` modes, user must approve new peers
- **Conversation Limits** — configurable max exchanges per peer (default: 10) to prevent runaway token usage
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
| `maxExchanges` | `10` | Max message exchanges per peer |

## Tools

The plugin registers these agent tools:

| Tool | Description |
|------|-------------|
| `udp_discover` | Broadcast a discovery ping to find agents on the LAN |
| `udp_send` | Send a message to an agent by ip:port |
| `udp_receive` | Check inbox for pending messages |
| `udp_approve_peer` | Trust a peer (user approval required) |
| `udp_revoke_peer` | Remove trust from a peer |
| `udp_status` | View agent ID, port, peers, exchange counts |
| `udp_set_config` | Change max_exchanges or trust_mode at runtime |

## How It Works

1. Each agent gets a unique ID (`hostname-randomhex`) on startup
2. `udp_discover` broadcasts a `CLAUDE-UDP-V1` ping on the LAN
3. Other agents respond with their identity
4. Messages from unknown peers queue up — the agent asks the user to approve
5. Once trusted, messages flow freely until the conversation limit is reached
6. All traffic is local UDP — nothing leaves your network

## Security

- Peers are **never auto-approved** — the user must explicitly trust each one
- Incoming messages from other agents are treated as **untrusted input**
- Sensitive project data is never shared unless the user explicitly instructs it
- Conversation limits prevent unbounded token consumption
- Use `always-confirm` mode on untrusted networks

## License

MIT
