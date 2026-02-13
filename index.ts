import dgram from "node:dgram";
import dns from "node:dns/promises";
import os from "node:os";
import crypto from "node:crypto";

const PROTOCOL_MAGIC = "CLAUDE-UDP-V1";
const DISCOVERY_TIMEOUT_MS = 3000;
const ONE_HOUR_MS = 60 * 60 * 1000;

// --- State (initialized per plugin registration) ---
let socket: dgram.Socket | null = null;
let agentId = "";
let udpPort = 51337;
let trustMode = "approve-once";
let maxExchangesPerHour = 10;
let pluginApi: any = null;

const trustedPeers = new Map<string, { ip: string; port: number; approvedAt: number; hostname?: string }>();
const inbox: Array<{
  from: string;
  fromId: string;
  message: string;
  timestamp: number;
  trusted: boolean;
}> = [];

// --- Rolling exchange tracking (per-hour window) ---
interface ExchangeRecord {
  timestamp: number;
  direction: "sent" | "received";
}
const exchangeHistory = new Map<string, ExchangeRecord[]>();

function pruneOldExchanges(peerId: string): ExchangeRecord[] {
  const cutoff = Date.now() - ONE_HOUR_MS;
  const records = (exchangeHistory.get(peerId) || []).filter((r) => r.timestamp > cutoff);
  exchangeHistory.set(peerId, records);
  return records;
}

function getHourlyCount(peerId: string): { sent: number; received: number; total: number } {
  const records = pruneOldExchanges(peerId);
  const sent = records.filter((r) => r.direction === "sent").length;
  const received = records.filter((r) => r.direction === "received").length;
  return { sent, received, total: sent + received };
}

function isOverLimit(peerId: string): boolean {
  return getHourlyCount(peerId).total >= maxExchangesPerHour;
}

function recordExchange(peerId: string, direction: "sent" | "received") {
  const records = exchangeHistory.get(peerId) || [];
  records.push({ timestamp: Date.now(), direction });
  exchangeHistory.set(peerId, records);
}

// --- Message log (persistent history for human review) ---
interface LogEntry {
  timestamp: number;
  direction: "sent" | "received" | "system";
  peerId: string;
  peerAddress: string;
  message: string;
  trusted: boolean;
}
const messageLog: LogEntry[] = [];
const MAX_LOG_ENTRIES = 500;

function addLog(entry: Omit<LogEntry, "timestamp">) {
  messageLog.push({ ...entry, timestamp: Date.now() });
  if (messageLog.length > MAX_LOG_ENTRIES) {
    messageLog.splice(0, messageLog.length - MAX_LOG_ENTRIES);
  }
}

// --- Discovery collector ---
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

async function resolveHostname(hostnameOrIp: string): Promise<string> {
  // If it already looks like an IP, return as-is
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostnameOrIp)) {
    return hostnameOrIp;
  }
  try {
    const result = await dns.lookup(hostnameOrIp, { family: 4 });
    return result.address;
  } catch {
    throw new Error(`Could not resolve hostname: ${hostnameOrIp}`);
  }
}

function formatTimestamp(ts: number): string {
  return new Date(ts).toLocaleString();
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
      addLog({
        direction: "system",
        peerId,
        peerAddress: peerAddr,
        message: `Discovery ping received, pong sent`,
        trusted: trustedPeers.has(peerId),
      });
      return;
    }

    if (msg.type === "discovery-pong") {
      if (discoveryCollector) {
        discoveryCollector.push({ id: peerId, address: peerAddr });
      }
      addLog({
        direction: "system",
        peerId,
        peerAddress: peerAddr,
        message: `Discovery pong received`,
        trusted: trustedPeers.has(peerId),
      });
      return;
    }

    if (msg.type === "message") {
      const isTrusted = trustedPeers.has(peerId);

      recordExchange(peerId, "received");
      addLog({
        direction: "received",
        peerId,
        peerAddress: peerAddr,
        message: msg.payload,
        trusted: isTrusted,
      });

      inbox.push({
        from: peerAddr,
        fromId: peerId,
        message: msg.payload,
        timestamp: msg.timestamp || Date.now(),
        trusted: isTrusted,
      });

      // Notify the agent about incoming trusted messages
      if (isTrusted && !isOverLimit(peerId) && pluginApi?.notify) {
        pluginApi.notify({
          title: `UDP message from ${peerId}`,
          body: msg.payload.length > 200 ? msg.payload.slice(0, 200) + "..." : msg.payload,
          urgency: "normal",
        });
      }
    }
  });

  socket.on("error", (err) => {
    console.error(`UDP socket error: ${err.message}`);
    addLog({
      direction: "system",
      peerId: "system",
      peerAddress: "local",
      message: `Socket error: ${err.message}`,
      trusted: false,
    });
  });

  socket.bind(udpPort, "0.0.0.0", () => {
    socket!.setBroadcast(true);
    console.log(`UDP Messenger listening on port ${udpPort} as ${agentId}`);
    addLog({
      direction: "system",
      peerId: "self",
      peerAddress: `0.0.0.0:${udpPort}`,
      message: `Agent started as ${agentId} on port ${udpPort}`,
      trusted: true,
    });
  });
}

// --- Plugin Entry ---

export default function register(api: any) {
  pluginApi = api;

  // Read config from plugin entries
  const config = api.getPluginConfig?.() || {};
  udpPort = config.port || 51337;
  trustMode = config.trustMode || "approve-once";
  maxExchangesPerHour = config.maxExchanges || 10;

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

      addLog({
        direction: "system",
        peerId: "self",
        peerAddress: "broadcast",
        message: `Discovery ping sent to ${broadcastAddrs.join(", ")}`,
        trusted: true,
      });

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
    description: "Send a message to another agent. Provide their address as ip:port (or hostname:port) and the message text.",
    parameters: {
      type: "object",
      properties: {
        address: { type: "string", description: "Target agent address in ip:port or hostname:port format (e.g. 192.168.1.5:51337 or raspberrypi:51337)" },
        message: { type: "string", description: "The message to send" },
        peer_id: { type: "string", description: "The target agent's ID (for exchange tracking)" },
      },
      required: ["address", "message"],
    },
    async execute(_id: string, params: { address: string; message: string; peer_id?: string }) {
      const colonIdx = params.address.lastIndexOf(":");
      if (colonIdx === -1) {
        return { content: [{ type: "text", text: "Invalid address format. Use ip:port or hostname:port (e.g. 192.168.1.5:51337 or raspberrypi:51337)" }] };
      }

      const hostPart = params.address.slice(0, colonIdx);
      const port = parseInt(params.address.slice(colonIdx + 1), 10);

      if (!hostPart || !port || isNaN(port)) {
        return { content: [{ type: "text", text: "Invalid address format. Use ip:port or hostname:port (e.g. 192.168.1.5:51337)" }] };
      }

      let ip: string;
      try {
        ip = await resolveHostname(hostPart);
      } catch (err: any) {
        return { content: [{ type: "text", text: err.message }] };
      }

      if (params.peer_id && isOverLimit(params.peer_id)) {
        return {
          content: [{ type: "text", text: `Hourly exchange limit reached with ${params.peer_id} (${maxExchangesPerHour}/hour). Wait for the window to roll over or use udp_set_config to increase the limit.` }],
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
            addLog({ direction: "system", peerId: params.peer_id || "unknown", peerAddress: params.address, message: `Send failed: ${err.message}`, trusted: false });
            resolve({ content: [{ type: "text", text: `Failed to send: ${err.message}` }] });
            return;
          }

          if (params.peer_id) {
            recordExchange(params.peer_id, "sent");
          }

          addLog({
            direction: "sent",
            peerId: params.peer_id || "unknown",
            peerAddress: params.address,
            message: params.message,
            trusted: params.peer_id ? trustedPeers.has(params.peer_id) : false,
          });

          const hourly = params.peer_id ? getHourlyCount(params.peer_id) : null;
          const remaining = hourly
            ? ` (${maxExchangesPerHour - hourly.total} exchanges remaining this hour)`
            : "";

          resolve({ content: [{ type: "text", text: `Message sent to ${params.address}${ip !== hostPart ? ` (resolved to ${ip})` : ""}.${remaining}` }] });
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
        const hourly = getHourlyCount(m.fromId);
        const overLimit = hourly.total >= maxExchangesPerHour ? " [HOURLY LIMIT REACHED]" : "";
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

      addLog({
        direction: "system",
        peerId: params.peer_id,
        peerAddress: `${params.ip}:${params.port}`,
        message: `Peer approved and added to trusted list`,
        trusted: true,
      });

      return {
        content: [{ type: "text", text: `Peer ${params.peer_id} is now trusted. Messages from ${params.ip}:${params.port} will be delivered directly.` }],
      };
    },
  });

  // --- Tool: udp_add_peer ---
  api.registerTool({
    name: "udp_add_peer",
    description: "Manually add a peer by IP address or hostname (with optional port). This trusts the peer and registers them for messaging without needing discovery.",
    parameters: {
      type: "object",
      properties: {
        host: { type: "string", description: "IP address or hostname of the peer (e.g. 192.168.1.5 or raspberrypi)" },
        port: { type: "number", description: "UDP port of the peer (default: same as local port)" },
        label: { type: "string", description: "Optional friendly label for this peer" },
      },
      required: ["host"],
    },
    async execute(_id: string, params: { host: string; port?: number; label?: string }) {
      const peerPort = params.port || udpPort;
      let ip: string;
      try {
        ip = await resolveHostname(params.host);
      } catch (err: any) {
        return { content: [{ type: "text", text: err.message }] };
      }

      // Send a discovery ping to learn their agent ID
      const ping = JSON.stringify({
        magic: PROTOCOL_MAGIC,
        type: "discovery-ping",
        sender_id: agentId,
        sender_port: udpPort,
        timestamp: Date.now(),
      });

      discoveryCollector = [];
      socket!.send(ping, peerPort, ip);

      await new Promise((resolve) => setTimeout(resolve, DISCOVERY_TIMEOUT_MS));

      const found = discoveryCollector!.find((r) => r.address.startsWith(ip));
      discoveryCollector = null;

      if (found) {
        trustedPeers.set(found.id, {
          ip,
          port: peerPort,
          approvedAt: Date.now(),
          hostname: params.host !== ip ? params.host : undefined,
        });

        addLog({
          direction: "system",
          peerId: found.id,
          peerAddress: `${ip}:${peerPort}`,
          message: `Peer manually added and trusted (${params.label || params.host})`,
          trusted: true,
        });

        return {
          content: [{ type: "text", text: `Peer discovered and trusted: ${found.id} @ ${ip}:${peerPort}${params.label ? ` (${params.label})` : ""}${params.host !== ip ? ` — resolved from ${params.host}` : ""}` }],
        };
      }

      // Agent didn't respond to ping — add as a "pending" peer with a generated ID
      const pendingId = `${params.label || params.host}-pending`;
      trustedPeers.set(pendingId, {
        ip,
        port: peerPort,
        approvedAt: Date.now(),
        hostname: params.host !== ip ? params.host : undefined,
      });

      addLog({
        direction: "system",
        peerId: pendingId,
        peerAddress: `${ip}:${peerPort}`,
        message: `Peer added but did not respond to ping (may be offline). Added as ${pendingId}`,
        trusted: true,
      });

      return {
        content: [{ type: "text", text: `No agent responded at ${ip}:${peerPort}${params.host !== ip ? ` (${params.host})` : ""}. Added as trusted with placeholder ID "${pendingId}" — their real ID will be captured when they come online and send a message.` }],
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
      addLog({
        direction: "system",
        peerId: params.peer_id,
        peerAddress: "",
        message: `Trust revoked`,
        trusted: false,
      });
      return { content: [{ type: "text", text: `Trust revoked for ${params.peer_id}. Their messages will now require approval.` }] };
    },
  });

  // --- Tool: udp_log ---
  api.registerTool({
    name: "udp_log",
    description: "View the message log. Shows a history of all sent, received, and system messages for human review. Optionally filter by peer ID or direction.",
    parameters: {
      type: "object",
      properties: {
        peer_id: { type: "string", description: "Filter logs to a specific peer ID" },
        direction: { type: "string", enum: ["sent", "received", "system", "all"], description: "Filter by message direction (default: all)" },
        limit: { type: "number", description: "Max number of entries to return (default: 50, max: 500)" },
      },
    },
    async execute(_id: string, params: { peer_id?: string; direction?: string; limit?: number }) {
      let entries = [...messageLog];

      if (params.peer_id) {
        entries = entries.filter((e) => e.peerId === params.peer_id);
      }
      if (params.direction && params.direction !== "all") {
        entries = entries.filter((e) => e.direction === params.direction);
      }

      const limit = Math.min(params.limit || 50, MAX_LOG_ENTRIES);
      entries = entries.slice(-limit);

      if (entries.length === 0) {
        return { content: [{ type: "text", text: "No log entries found matching the filter." }] };
      }

      const lines = entries.map((e) => {
        const dir = e.direction === "sent" ? "→ SENT" : e.direction === "received" ? "← RECV" : "◆ SYS ";
        const trust = e.trusted ? "" : " [untrusted]";
        return `[${formatTimestamp(e.timestamp)}] ${dir}${trust} ${e.peerId} (${e.peerAddress})\n  ${e.message}`;
      });

      const header = `Message log (${entries.length} entries${params.peer_id ? `, peer: ${params.peer_id}` : ""}${params.direction && params.direction !== "all" ? `, direction: ${params.direction}` : ""}):\n`;

      return {
        content: [{ type: "text", text: header + lines.join("\n\n") }],
      };
    },
  });

  // --- Tool: udp_status ---
  api.registerTool({
    name: "udp_status",
    description: "Show current agent status: ID, port, trusted peers, hourly conversation counts, and configuration.",
    parameters: { type: "object", properties: {} },
    async execute() {
      const peerList: string[] = [];
      for (const [id, info] of trustedPeers) {
        const hourly = getHourlyCount(id);
        const hostname = info.hostname ? ` (${info.hostname})` : "";
        peerList.push(`  ${id} @ ${info.ip}:${info.port}${hostname} — ${hourly.total}/${maxExchangesPerHour} exchanges this hour`);
      }

      const text = [
        `Agent ID: ${agentId}`,
        `Listening on port: ${udpPort}`,
        `Trust mode: ${trustMode}`,
        `Max exchanges per peer per hour: ${maxExchangesPerHour}`,
        `Inbox: ${inbox.length} pending message(s)`,
        `Log entries: ${messageLog.length}`,
        `Trusted peers (${trustedPeers.size}):`,
        peerList.length > 0 ? peerList.join("\n") : "  (none)",
      ].join("\n");

      return { content: [{ type: "text", text }] };
    },
  });

  // --- Tool: udp_set_config ---
  api.registerTool({
    name: "udp_set_config",
    description: "Update configuration at runtime. Available keys: max_exchanges (number, per hour), trust_mode (approve-once | always-confirm).",
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
        maxExchangesPerHour = n;
        addLog({ direction: "system", peerId: "self", peerAddress: "local", message: `max_exchanges set to ${n}/hour`, trusted: true });
        return { content: [{ type: "text", text: `max_exchanges set to ${n} per hour.` }] };
      }

      if (params.key === "trust_mode") {
        if (params.value !== "approve-once" && params.value !== "always-confirm") {
          return { content: [{ type: "text", text: 'trust_mode must be "approve-once" or "always-confirm".' }] };
        }
        trustMode = params.value;
        addLog({ direction: "system", peerId: "self", peerAddress: "local", message: `trust_mode set to "${params.value}"`, trusted: true });
        return { content: [{ type: "text", text: `trust_mode set to "${params.value}".` }] };
      }

      return { content: [{ type: "text", text: `Unknown config key: ${params.key}` }] };
    },
  });
}
