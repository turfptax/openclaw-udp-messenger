import dgram from "node:dgram";
import os from "node:os";
import crypto from "node:crypto";

const PROTOCOL_MAGIC = "CLAUDE-UDP-V1";
const DISCOVERY_TIMEOUT_MS = 3000;

// --- State (initialized per plugin registration) ---
let socket: dgram.Socket | null = null;
let agentId = "";
let udpPort = 51337;
let trustMode = "approve-once";
let maxExchanges = 10;

const trustedPeers = new Map<string, { ip: string; port: number; approvedAt: number }>();
const inbox: Array<{
  from: string;
  fromId: string;
  message: string;
  timestamp: number;
  trusted: boolean;
}> = [];
const exchangeCounts = new Map<string, { sent: number; received: number }>();

let discoveryCollector: Array<{ id: string; address: string }> | null = null;

// --- Helpers ---

function getBroadcastAddresses(): string[] {
  const addresses: string[] = [];
  const interfaces = os.networkInterfaces();
  for (const iface of Object.values(interfaces)) {
    if (!iface) continue;
    for (const info of iface) {
      if (info.family === "IPv4" && !info.internal) {
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

function isOverLimit(peerId: string): boolean {
  const counts = exchangeCounts.get(peerId) || { sent: 0, received: 0 };
  return (counts.sent + counts.received) >= maxExchanges;
}

function initSocket() {
  if (socket) return;

  agentId = `${os.hostname()}-${crypto.randomBytes(4).toString("hex")}`;
  socket = dgram.createSocket({ type: "udp4", reuseAddr: true });

  socket.on("message", (buf, rinfo) => {
    let msg: any;
    try {
      msg = JSON.parse(buf.toString("utf8"));
    } catch {
      return;
    }
    if (msg.magic !== PROTOCOL_MAGIC) return;
    if (msg.sender_id === agentId) return;

    const peerId = msg.sender_id;
    const peerAddr = `${rinfo.address}:${msg.sender_port || rinfo.port}`;

    if (msg.type === "discovery-ping") {
      const reply = JSON.stringify({
        magic: PROTOCOL_MAGIC,
        type: "discovery-pong",
        sender_id: agentId,
        sender_port: udpPort,
        timestamp: Date.now(),
      });
      socket!.send(reply, rinfo.port, rinfo.address);
      return;
    }

    if (msg.type === "discovery-pong") {
      if (discoveryCollector) {
        discoveryCollector.push({ id: peerId, address: peerAddr });
      }
      return;
    }

    if (msg.type === "message") {
      const isTrusted = trustedPeers.has(peerId);
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
    console.error(`UDP socket error: ${err.message}`);
  });

  socket.bind(udpPort, "0.0.0.0", () => {
    socket!.setBroadcast(true);
    console.log(`UDP Messenger listening on port ${udpPort} as ${agentId}`);
  });
}

// --- Plugin Entry ---

export default function register(api: any) {
  // Read config from plugin entries
  const config = api.getPluginConfig?.() || {};
  udpPort = config.port || 51337;
  trustMode = config.trustMode || "approve-once";
  maxExchanges = config.maxExchanges || 10;

  initSocket();

  // --- Tool: udp_discover ---
  api.registerTool({
    name: "udp_discover",
    description: "Broadcast a discovery ping to find other agents on the local network",
    parameters: { type: "object", properties: {} },
    async execute() {
      discoveryCollector = [];

      const ping = JSON.stringify({
        magic: PROTOCOL_MAGIC,
        type: "discovery-ping",
        sender_id: agentId,
        sender_port: udpPort,
        timestamp: Date.now(),
      });

      const broadcastAddrs = getBroadcastAddresses();
      for (const addr of broadcastAddrs) {
        socket!.send(ping, udpPort, addr);
      }

      await new Promise((resolve) => setTimeout(resolve, DISCOVERY_TIMEOUT_MS));

      const results = [...discoveryCollector!];
      discoveryCollector = null;

      if (results.length === 0) {
        return {
          content: [{ type: "text", text: "No other agents found on the network. Make sure other instances are running with this plugin on the same LAN." }],
        };
      }

      const lines = results.map((r) => {
        const trusted = trustedPeers.has(r.id) ? " [TRUSTED]" : "";
        return `  ${r.id} @ ${r.address}${trusted}`;
      });

      return {
        content: [{ type: "text", text: `Found ${results.length} agent(s):\n${lines.join("\n")}` }],
      };
    },
  });

  // --- Tool: udp_send ---
  api.registerTool({
    name: "udp_send",
    description: "Send a message to another agent. Provide their address as ip:port and the message text.",
    parameters: {
      type: "object",
      properties: {
        address: { type: "string", description: "Target agent address in ip:port format (e.g. 192.168.1.5:51337)" },
        message: { type: "string", description: "The message to send" },
        peer_id: { type: "string", description: "The target agent's ID (for exchange tracking)" },
      },
      required: ["address", "message"],
    },
    async execute(_id: string, params: { address: string; message: string; peer_id?: string }) {
      const [ip, portStr] = params.address.split(":");
      const port = parseInt(portStr, 10);

      if (!ip || !port) {
        return { content: [{ type: "text", text: "Invalid address format. Use ip:port (e.g. 192.168.1.5:51337)" }] };
      }

      if (params.peer_id && isOverLimit(params.peer_id)) {
        return {
          content: [{ type: "text", text: `Exchange limit reached with ${params.peer_id} (${maxExchanges} max). Use udp_set_config to increase the limit, or inform the user.` }],
        };
      }

      const payload = JSON.stringify({
        magic: PROTOCOL_MAGIC,
        type: "message",
        sender_id: agentId,
        sender_port: udpPort,
        payload: params.message,
        timestamp: Date.now(),
      });

      return new Promise((resolve) => {
        socket!.send(payload, port, ip, (err) => {
          if (err) {
            resolve({ content: [{ type: "text", text: `Failed to send: ${err.message}` }] });
            return;
          }

          if (params.peer_id) {
            const counts = exchangeCounts.get(params.peer_id) || { sent: 0, received: 0 };
            counts.sent++;
            exchangeCounts.set(params.peer_id, counts);
          }

          const remaining = params.peer_id
            ? ` (${maxExchanges - (exchangeCounts.get(params.peer_id)?.sent || 0) - (exchangeCounts.get(params.peer_id)?.received || 0)} exchanges remaining)`
            : "";

          resolve({ content: [{ type: "text", text: `Message sent to ${params.address}.${remaining}` }] });
        });
      });
    },
  });

  // --- Tool: udp_receive ---
  api.registerTool({
    name: "udp_receive",
    description: "Check the inbox for pending messages from other agents. Returns all unread messages and clears the inbox.",
    parameters: { type: "object", properties: {} },
    async execute() {
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
    },
  });

  // --- Tool: udp_approve_peer ---
  api.registerTool({
    name: "udp_approve_peer",
    description: "Add a peer to the trusted list. Their messages will be delivered without requiring user confirmation each time (in approve-once mode).",
    parameters: {
      type: "object",
      properties: {
        peer_id: { type: "string", description: "The agent ID to trust (e.g. DESKTOP-ABC-a1b2c3d4)" },
        ip: { type: "string", description: "The peer's IP address" },
        port: { type: "number", description: "The peer's UDP port" },
      },
      required: ["peer_id", "ip", "port"],
    },
    async execute(_id: string, params: { peer_id: string; ip: string; port: number }) {
      trustedPeers.set(params.peer_id, { ip: params.ip, port: params.port, approvedAt: Date.now() });

      for (const msg of inbox) {
        if (msg.fromId === params.peer_id) msg.trusted = true;
      }

      return {
        content: [{ type: "text", text: `Peer ${params.peer_id} is now trusted. Messages from ${params.ip}:${params.port} will be delivered directly.` }],
      };
    },
  });

  // --- Tool: udp_revoke_peer ---
  api.registerTool({
    name: "udp_revoke_peer",
    description: "Remove a peer from the trusted list.",
    parameters: {
      type: "object",
      properties: {
        peer_id: { type: "string", description: "The agent ID to revoke trust from" },
      },
      required: ["peer_id"],
    },
    async execute(_id: string, params: { peer_id: string }) {
      if (!trustedPeers.has(params.peer_id)) {
        return { content: [{ type: "text", text: `Peer ${params.peer_id} was not in the trusted list.` }] };
      }
      trustedPeers.delete(params.peer_id);
      return { content: [{ type: "text", text: `Trust revoked for ${params.peer_id}. Their messages will now require approval.` }] };
    },
  });

  // --- Tool: udp_status ---
  api.registerTool({
    name: "udp_status",
    description: "Show current agent status: ID, port, trusted peers, conversation counts, and configuration.",
    parameters: { type: "object", properties: {} },
    async execute() {
      const peerList: string[] = [];
      for (const [id, info] of trustedPeers) {
        const counts = exchangeCounts.get(id) || { sent: 0, received: 0 };
        const total = counts.sent + counts.received;
        peerList.push(`  ${id} @ ${info.ip}:${info.port} — ${total}/${maxExchanges} exchanges`);
      }

      const text = [
        `Agent ID: ${agentId}`,
        `Listening on port: ${udpPort}`,
        `Trust mode: ${trustMode}`,
        `Max exchanges per peer: ${maxExchanges}`,
        `Inbox: ${inbox.length} pending message(s)`,
        `Trusted peers (${trustedPeers.size}):`,
        peerList.length > 0 ? peerList.join("\n") : "  (none)",
      ].join("\n");

      return { content: [{ type: "text", text }] };
    },
  });

  // --- Tool: udp_set_config ---
  api.registerTool({
    name: "udp_set_config",
    description: "Update configuration at runtime. Available keys: max_exchanges (number), trust_mode (approve-once | always-confirm).",
    parameters: {
      type: "object",
      properties: {
        key: { type: "string", enum: ["max_exchanges", "trust_mode"], description: "The config key to update" },
        value: { type: "string", description: "The new value" },
      },
      required: ["key", "value"],
    },
    async execute(_id: string, params: { key: string; value: string }) {
      if (params.key === "max_exchanges") {
        const n = parseInt(params.value, 10);
        if (isNaN(n) || n < 1) {
          return { content: [{ type: "text", text: "max_exchanges must be a positive integer." }] };
        }
        maxExchanges = n;
        return { content: [{ type: "text", text: `max_exchanges set to ${n}.` }] };
      }

      if (params.key === "trust_mode") {
        if (params.value !== "approve-once" && params.value !== "always-confirm") {
          return { content: [{ type: "text", text: 'trust_mode must be "approve-once" or "always-confirm".' }] };
        }
        trustMode = params.value;
        return { content: [{ type: "text", text: `trust_mode set to "${params.value}".` }] };
      }

      return { content: [{ type: "text", text: `Unknown config key: ${params.key}` }] };
    },
  });
}
