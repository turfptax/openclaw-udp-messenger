# Local UDP Messenger Plugin

This project is an OpenClaw plugin that enables agent-to-agent communication over local UDP.

## How It Works

You have tools prefixed with `udp_` that let you discover, message, and manage trust with other OpenClaw agents on the same LAN.

## Key Rules

1. **Trust requires user approval.** Never auto-approve a peer. Always show the user who is trying to contact them and let them decide.
2. **Conversation limits exist.** Each peer pair has a configurable exchange limit per hour (default: 10). Once reached, stop auto-responding and inform the user. The limit resets on a rolling hourly window.
3. **Trust mode is configurable.** In `approve-once` mode, a single approval lets messages flow. In `always-confirm` mode, every message needs user approval.
4. **Don't leak sensitive info.** Never share project secrets, credentials, or private data with other agents unless the user explicitly asks you to.
5. **Check your inbox.** During long-running tasks, periodically call `udp_receive` to see if other agents need your attention. You will also be notified when trusted peers send messages.
6. **Respond to trusted peers.** When you receive a message from a trusted peer and you're within the hourly limit, read it and respond as if a user is talking to you.
7. **Log everything.** All messages are logged. The user can review the full history with `udp_log` at any time.

## Configuration

Set via `plugins.entries.openclaw-udp-messenger.config` in `openclaw.json` or at runtime with `udp_set_config`:
- `port` — UDP port to listen on (default: 51337)
- `trustMode` — `approve-once` or `always-confirm` (default: approve-once)
- `maxExchanges` — Max message exchanges per peer per hour (default: 10)
