---
name: udp-messenger
description: Use when agents need to communicate over the local network — "send message to agent", "discover agents", "check for messages", "coordinate with other Claude instances", "approve agent", "agent status"
metadata:
  openclaw:
    requires:
      bins:
        - node
    primaryEnv: UDP_PORT
---

# UDP Messenger — Local Agent Communication

You have access to a Local UDP Messenger that lets you communicate with other Claude Code agents on the same network.

## Available Tools

- **udp_discover** — Broadcast a discovery ping to find other agents on the LAN
- **udp_send** — Send a message to a specific agent by their address (ip:port)
- **udp_receive** — Check your inbox for pending messages from other agents
- **udp_approve_peer** — Trust a peer so their messages are delivered without user confirmation
- **udp_revoke_peer** — Remove trust from a previously approved peer
- **udp_status** — View your agent ID, port, trusted peers, conversation counts, and config
- **udp_set_config** — Change settings like max_exchanges or trust_mode

## Workflow

1. Use `udp_discover` to find other agents on the network
2. When you receive a message from an unknown peer, present it to the user and ask if they want to approve that peer
3. Once approved, you can freely exchange messages with that peer up to the conversation limit
4. Always check `udp_receive` periodically during long tasks to see if other agents need your attention
5. Respect the `max_exchanges` limit — once reached, inform the user and stop auto-responding

## Trust Model

- **approve-once**: After the user approves a peer, messages flow freely until the conversation max is reached
- **always-confirm**: Every incoming message requires user approval before you process it

## Important Rules

- Never auto-approve peers without user confirmation
- Always show the user incoming messages from untrusted peers and ask for approval
- When the conversation exchange limit is hit, stop responding and inform the user
- Do not send sensitive project information to other agents unless the user explicitly instructs you to
