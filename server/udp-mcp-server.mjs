import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import dgram from "node:dgram";
import os from "node:os";
import crypto from "node:crypto";

// --- Configuration ---
const UDP_PORT = parseInt(process.env.UDP_PORT || "51337", 10);
const AGENT_ID = `${os.hostname()}-${crypto.randomBytes(4).toString("hex")}`;
const DISCOVERY_TIMEOUT_MS = 3000;
const PROTOCOL_MAGIC = "CLAUDE-UDP-V1";

let trustMode = process.env.TRUST_MODE || "approve-once"; // "approve-once" | "always-confirm"
let maxExchanges = parseInt(process.env.MAX_EXCHANGES || "10", 10);

// --- State ---
const trustedPeers = new Map(); // peerId -> { ip, port, approvedAt }
const inbox = [];              // [{ from, fromId, message, timestamp, trusted }]
const exchangeCounts = new Map(); // peerId -> { sent: n, received: n }

// --- UDP Socket ---
const socket = dgram.createSocket({ type: "udp4", reuseAddr: true });

socket.on("message", (buf, rinfo) => {
  let msg;
  try {
    msg = JSON.parse(buf.toString("utf8"));
  } catch {
    return; // ignore non-JSON
  }
  if (msg.magic !== PROTOCOL_MAGIC) return;
  if (msg.sender_id === AGENT_ID) return; // ignore own broadcasts

  const peerId = msg.sender_id;
  const peerAddr = `${rinfo.address}:${msg.sender_port || rinfo.port}`;

  if (msg.type === "discovery-ping") {
    // Respond with our identity
    const reply = JSON.stringify({
      magic: PROTOCOL_MAGIC,
      type: "discovery-pong",
      sender_id: AGENT_ID,
      sender_port: UDP_PORT,
      timestamp: Date.now(),
    });
    socket.send(reply, rinfo.port, rinfo.address);
    return;
  }

  if (msg.type === "discovery-pong") {
    // Handled by the discover tool's collector
    if (discoveryCollector) {
      discoveryCollector.push({ id: peerId, address: peerAddr });
    }
    return;
  }

  if (msg.type === "message") {
    const isTrusted = trustedPeers.has(peerId);

    // Track received count
    const counts = exchangeCounts.get(peerId) || { sent: 0, received: 0 };
    counts.received++;
    exchangeCounts.set(peerId, counts);

    inbox.push({
      from: peerAddr,
      fromId: peerId,
      message: msg.payload,
      timestamp: msg.timestamp || Date.now(),
      trusted: isTrusted,
    });
  }
});

socket.on("error", (err) => {
  process.stderr.write(`UDP socket error: ${err.message}\n`);
});

socket.bind(UDP_PORT, "0.0.0.0", () => {
  socket.setBroadcast(true);
  process.stderr.write(`UDP Messenger listening on port ${UDP_PORT} as ${AGENT_ID}\n`);
});

// --- Discovery collector (temporary during discover calls) ---
let discoveryCollector = null;

// --- Helper: get local broadcast addresses ---
function getBroadcastAddresses() {
  const addresses = [];
  const interfaces = os.networkInterfaces();
  for (const iface of Object.values(interfaces)) {
    for (const info of iface) {
      if (info.family === "IPv4" && !info.internal) {
        // Calculate broadcast from address + netmask
        const addrParts = info.address.split(".").map(Number);
        const maskParts = info.netmask.split(".").map(Number);
        const broadcast = addrParts.map((a, i) => (a | (~maskParts[i] & 255))).join(".");
        addresses.push(broadcast);
      }
    }
  }
  if (addresses.length === 0) addresses.push("255.255.255.255");
  return [...new Set(addresses)];
}

// --- Helper: check exchange limit ---
function isOverLimit(peerId) {
  const counts = exchangeCounts.get(peerId) || { sent: 0, received: 0 };
  return (counts.sent + counts.received) >= maxExchanges;
}

// --- MCP Server Setup ---
const server = new McpServer({
  name: "udp-messenger",
  version: "1.0.0",
});

// Tool: udp_discover
server.tool(
  "udp_discover",
  "Broadcast a discovery ping to find other Claude agents on the local network",
  {},
  async () => {
    discoveryCollector = [];

    const ping = JSON.stringify({
      magic: PROTOCOL_MAGIC,
      type: "discovery-ping",
      sender_id: AGENT_ID,
      sender_port: UDP_PORT,
      timestamp: Date.now(),
    });

    const broadcastAddrs = getBroadcastAddresses();
    for (const addr of broadcastAddrs) {
      socket.send(ping, UDP_PORT, addr);
    }

    // Wait for responses
    await new Promise((resolve) => setTimeout(resolve, DISCOVERY_TIMEOUT_MS));

    const results = [...discoveryCollector];
    discoveryCollector = null;

    if (results.length === 0) {
      return { content: [{ type: "text", text: "No other agents found on the network. Make sure other Claude Code instances are running with this plugin on the same LAN." }] };
    }

    const lines = results.map((r) => {
      const trusted = trustedPeers.has(r.id) ? " [TRUSTED]" : "";
      return `  ${r.id} @ ${r.address}${trusted}`;
    });

    return {
      content: [{ type: "text", text: `Found ${results.length} agent(s):\n${lines.join("\n")}` }],
    };
  }
);

// Tool: udp_send
server.tool(
  "udp_send",
  "Send a message to another agent. Provide their address as ip:port and the message text.",
  {
    address: z.string().describe("Target agent address in ip:port format (e.g. 192.168.1.5:51337)"),
    message: z.string().describe("The message to send"),
    peer_id: z.string().optional().describe("The target agent's ID (for exchange tracking)"),
  },
  async ({ address, message, peer_id }) => {
    const [ip, portStr] = address.split(":");
    const port = parseInt(portStr, 10);

    if (!ip || !port) {
      return { content: [{ type: "text", text: "Invalid address format. Use ip:port (e.g. 192.168.1.5:51337)" }] };
    }

    // Check exchange limit if we know the peer
    if (peer_id && isOverLimit(peer_id)) {
      return {
        content: [{ type: "text", text: `Exchange limit reached with ${peer_id} (${maxExchanges} max). Use udp_set_config to increase the limit, or inform the user.` }],
      };
    }

    const payload = JSON.stringify({
      magic: PROTOCOL_MAGIC,
      type: "message",
      sender_id: AGENT_ID,
      sender_port: UDP_PORT,
      payload: message,
      timestamp: Date.now(),
    });

    return new Promise((resolve) => {
      socket.send(payload, port, ip, (err) => {
        if (err) {
          resolve({ content: [{ type: "text", text: `Failed to send: ${err.message}` }] });
          return;
        }

        // Track sent count
        if (peer_id) {
          const counts = exchangeCounts.get(peer_id) || { sent: 0, received: 0 };
          counts.sent++;
          exchangeCounts.set(peer_id, counts);
        }

        const remaining = peer_id
          ? ` (${maxExchanges - (exchangeCounts.get(peer_id)?.sent || 0) - (exchangeCounts.get(peer_id)?.received || 0)} exchanges remaining)`
          : "";

        resolve({ content: [{ type: "text", text: `Message sent to ${address}.${remaining}` }] });
      });
    });
  }
);

// Tool: udp_receive
server.tool(
  "udp_receive",
  "Check the inbox for pending messages from other agents. Returns all unread messages and clears the inbox.",
  {},
  async () => {
    if (inbox.length === 0) {
      return { content: [{ type: "text", text: "No pending messages." }] };
    }

    const messages = inbox.splice(0, inbox.length);
    const lines = messages.map((m) => {
      const trust = m.trusted ? "[TRUSTED]" : "[UNTRUSTED - needs approval]";
      const overLimit = isOverLimit(m.fromId) ? " [LIMIT REACHED]" : "";
      const time = new Date(m.timestamp).toLocaleTimeString();
      return `${trust}${overLimit} From ${m.fromId} (${m.from}) at ${time}:\n  "${m.message}"`;
    });

    return {
      content: [{ type: "text", text: `${messages.length} message(s):\n\n${lines.join("\n\n")}` }],
    };
  }
);

// Tool: udp_approve_peer
server.tool(
  "udp_approve_peer",
  "Add a peer to the trusted list. Their messages will be delivered without requiring user confirmation each time (in approve-once mode).",
  {
    peer_id: z.string().describe("The agent ID to trust (e.g. DESKTOP-ABC-a1b2c3d4)"),
    ip: z.string().describe("The peer's IP address"),
    port: z.number().describe("The peer's UDP port"),
  },
  async ({ peer_id, ip, port }) => {
    trustedPeers.set(peer_id, { ip, port, approvedAt: Date.now() });

    // Mark any existing inbox messages from this peer as trusted
    for (const msg of inbox) {
      if (msg.fromId === peer_id) msg.trusted = true;
    }

    return {
      content: [{ type: "text", text: `Peer ${peer_id} is now trusted. Messages from ${ip}:${port} will be delivered directly.` }],
    };
  }
);

// Tool: udp_revoke_peer
server.tool(
  "udp_revoke_peer",
  "Remove a peer from the trusted list.",
  {
    peer_id: z.string().describe("The agent ID to revoke trust from"),
  },
  async ({ peer_id }) => {
    if (!trustedPeers.has(peer_id)) {
      return { content: [{ type: "text", text: `Peer ${peer_id} was not in the trusted list.` }] };
    }

    trustedPeers.delete(peer_id);
    return { content: [{ type: "text", text: `Trust revoked for ${peer_id}. Their messages will now require approval.` }] };
  }
);

// Tool: udp_status
server.tool(
  "udp_status",
  "Show current agent status: ID, port, trusted peers, conversation counts, and configuration.",
  {},
  async () => {
    const peerList = [];
    for (const [id, info] of trustedPeers) {
      const counts = exchangeCounts.get(id) || { sent: 0, received: 0 };
      const total = counts.sent + counts.received;
      peerList.push(`  ${id} @ ${info.ip}:${info.port} — ${total}/${maxExchanges} exchanges`);
    }

    const text = [
      `Agent ID: ${AGENT_ID}`,
      `Listening on port: ${UDP_PORT}`,
      `Trust mode: ${trustMode}`,
      `Max exchanges per peer: ${maxExchanges}`,
      `Inbox: ${inbox.length} pending message(s)`,
      `Trusted peers (${trustedPeers.size}):`,
      peerList.length > 0 ? peerList.join("\n") : "  (none)",
    ].join("\n");

    return { content: [{ type: "text", text }] };
  }
);

// Tool: udp_set_config
server.tool(
  "udp_set_config",
  "Update configuration. Available keys: max_exchanges (number), trust_mode (approve-once | always-confirm).",
  {
    key: z.enum(["max_exchanges", "trust_mode"]).describe("The config key to update"),
    value: z.string().describe("The new value"),
  },
  async ({ key, value }) => {
    if (key === "max_exchanges") {
      const n = parseInt(value, 10);
      if (isNaN(n) || n < 1) {
        return { content: [{ type: "text", text: "max_exchanges must be a positive integer." }] };
      }
      maxExchanges = n;
      return { content: [{ type: "text", text: `max_exchanges set to ${n}.` }] };
    }

    if (key === "trust_mode") {
      if (value !== "approve-once" && value !== "always-confirm") {
        return { content: [{ type: "text", text: 'trust_mode must be "approve-once" or "always-confirm".' }] };
      }
      trustMode = value;
      return { content: [{ type: "text", text: `trust_mode set to "${value}".` }] };
    }

    return { content: [{ type: "text", text: `Unknown config key: ${key}` }] };
  }
);

// --- Start ---
const transport = new StdioServerTransport();
await server.connect(transport);
process.stderr.write("UDP Messenger MCP server running.\n");
