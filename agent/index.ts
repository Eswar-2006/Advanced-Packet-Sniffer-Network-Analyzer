import WebSocket from "ws";
import os from "os";
import fs from "fs";
import path from "path";
import { spawn, ChildProcess } from "child_process";
import { detectNetworkInterfaces, getTsharkBinary } from "../server/interfaceDetector";
import { NetworkInterface } from "../src/types";

// Parse CLI arguments & environment variables
const args = process.argv.slice(2);
function getArg(flag: string, envVar: string, fallback: string): string {
  const index = args.indexOf(flag);
  if (index !== -1 && args[index + 1]) return args[index + 1];
  return process.env[envVar] || fallback;
}

const SERVER_URL = getArg("--server", "SENTINEL_SERVER_URL", "http://localhost:3000").replace(/\/$/, "");
const REGISTRATION_TOKEN = getArg("--token", "SENTINEL_REGISTRATION_TOKEN", "");
const CLI_AGENT_ID = getArg("--id", "SENTINEL_AGENT_ID", "");
const CLI_AGENT_SECRET = getArg("--secret", "SENTINEL_AGENT_SECRET", "");
const AGENT_NAME = getArg("--name", "SENTINEL_AGENT_NAME", `Sentinel Capture Node (${os.hostname()})`);

const CONFIG_FILE_PATH = path.join(process.cwd(), ".sentinel-agent.json");

interface AgentConfig {
  agentId: string;
  agentSecret: string;
  agentName: string;
  serverUrl: string;
  registeredAt: string;
}

console.log("==================================================");
console.log("     SENTINEL CAPTURE AGENT (SECURE NODE)        ");
console.log("==================================================");
console.log(`Device Name:   ${AGENT_NAME}`);
console.log(`Target Server: ${SERVER_URL}`);
console.log(`Platform:      ${os.platform()} (${os.arch()})`);
console.log("--------------------------------------------------");

let ws: WebSocket | null = null;
let activeSnifferProcess: ChildProcess | null = null;
let isCapturing = false;
let currentInterfaceId: string | null = null;
let heartbeatInterval: NodeJS.Timeout | null = null;
let isRevoked = false;

// Load local saved credentials if available
function loadSavedConfig(): AgentConfig | null {
  try {
    if (fs.existsSync(CONFIG_FILE_PATH)) {
      const raw = fs.readFileSync(CONFIG_FILE_PATH, "utf8");
      return JSON.parse(raw);
    }
  } catch (e) {
    console.warn("[AGENT] Could not read existing .sentinel-agent.json:", e);
  }
  return null;
}

function saveConfig(cfg: AgentConfig) {
  try {
    fs.writeFileSync(CONFIG_FILE_PATH, JSON.stringify(cfg, null, 2), "utf8");
    console.log(`[AGENT] Saved authentication credentials locally to .sentinel-agent.json`);
  } catch (e) {
    console.error("[AGENT] Failed to save .sentinel-agent.json:", e);
  }
}

// Exchange one-time registration token for permanent credentials
async function exchangeRegistrationToken(token: string): Promise<{ agentId: string; agentSecret: string; agentName: string } | null> {
  console.log(`[AGENT] Redeeming one-time registration token with backend...`);
  try {
    const registerUrl = `${SERVER_URL}/api/agents/register`;
    const payload = {
      token: token.trim(),
      deviceName: AGENT_NAME,
      platform: os.platform(),
      agentVersion: "2.5.0"
    };

    const res = await fetch(registerUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    const data = await res.json();
    if (!res.ok || !data.success) {
      console.error(`[AGENT ERROR] Registration failed: ${data.error || "Unknown server rejection"}`);
      return null;
    }

    console.log(`[AGENT SUCCESS] Successfully registered with Sentinel Analytica!`);
    console.log(`   Agent ID:     ${data.agentId}`);
    console.log(`   Device Name:  ${data.agentName}`);

    const config: AgentConfig = {
      agentId: data.agentId,
      agentSecret: data.agentSecret,
      agentName: data.agentName,
      serverUrl: SERVER_URL,
      registeredAt: new Date().toISOString()
    };

    saveConfig(config);
    return { agentId: data.agentId, agentSecret: data.agentSecret, agentName: data.agentName };
  } catch (err: any) {
    console.error(`[AGENT ERROR] Could not contact backend at ${SERVER_URL}:`, err.message || err);
    return null;
  }
}

async function startAgent() {
  let activeAgentId = CLI_AGENT_ID;
  let activeAgentSecret = CLI_AGENT_SECRET;
  let activeName = AGENT_NAME;

  // 1. If explicit one-time token is provided, redeem it
  if (REGISTRATION_TOKEN) {
    const regResult = await exchangeRegistrationToken(REGISTRATION_TOKEN);
    if (!regResult) {
      console.error("[AGENT] Aborting startup due to failed registration.");
      process.exit(1);
    }
    activeAgentId = regResult.agentId;
    activeAgentSecret = regResult.agentSecret;
    activeName = regResult.agentName;
  } else {
    // 2. Try loading from saved local credentials
    const savedConfig = loadSavedConfig();
    if (savedConfig && savedConfig.agentId && savedConfig.agentSecret) {
      activeAgentId = savedConfig.agentId;
      activeAgentSecret = savedConfig.agentSecret;
      activeName = savedConfig.agentName || AGENT_NAME;
      console.log(`[AGENT] Loaded saved credentials for Agent ID: ${activeAgentId}`);
    } else if (!activeAgentId || !activeAgentSecret) {
      // 3. Backward compatibility: if on localhost with no token, connect as local dev agent
      if (SERVER_URL.includes("localhost") || SERVER_URL.includes("127.0.0.1")) {
        activeAgentId = "agent-local";
        activeAgentSecret = "sentinel_secret_token_123";
        console.log(`[AGENT] Running in Localhost Development Mode (Agent ID: agent-local)`);
      } else {
        // 4. Auto-register with remote backend if no token provided
        console.log(`[AGENT] Requesting automatic pairing with backend at ${SERVER_URL}...`);
        try {
          const autoRes = await fetch(`${SERVER_URL}/api/agents/quick-register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              deviceName: AGENT_NAME,
              platform: os.platform(),
              agentVersion: "2.5.0"
            })
          });
          const autoData = await autoRes.json();
          if (autoRes.ok && autoData.success) {
            console.log(`[AGENT SUCCESS] Auto-paired with Sentinel Analytica!`);
            console.log(`   Agent ID:     ${autoData.agentId}`);
            console.log(`   Device Name:  ${autoData.agentName}`);
            activeAgentId = autoData.agentId;
            activeAgentSecret = autoData.agentSecret;
            activeName = autoData.agentName;
            saveConfig({
              agentId: autoData.agentId,
              agentSecret: autoData.agentSecret,
              agentName: autoData.agentName,
              serverUrl: SERVER_URL,
              registeredAt: new Date().toISOString()
            });
          } else {
            console.error("================================================================================");
            console.error("  [AGENT ERROR] Could not auto-register with dashboard: " + (autoData.error || "Unknown"));
            console.error("  To connect with a specific token, run:");
            console.error(`    npm run start:agent -- --token <ONE_TIME_REGISTRATION_TOKEN> --server ${SERVER_URL}`);
            console.error("================================================================================");
            process.exit(1);
          }
        } catch (e: any) {
          console.error("================================================================================");
          console.error("  [AGENT ERROR] Could not reach backend server at " + SERVER_URL);
          console.error("  Reason: " + (e.message || e));
          console.error("================================================================================");
          process.exit(1);
        }
      }
    }
  }

  connectWebSocket(activeAgentId, activeAgentSecret, activeName);
}

function connectWebSocket(agentId: string, agentSecret: string, agentName: string) {
  if (isRevoked) return;

  const wsProto = SERVER_URL.startsWith("https") ? "wss" : "ws";
  const rawUrl = SERVER_URL.replace(/^https?:\/\//, "");
  const wsUrl = `${wsProto}://${rawUrl}/ws/agent?agentId=${encodeURIComponent(agentId)}&agentSecret=${encodeURIComponent(agentSecret)}`;
  console.log(`[AGENT] Connecting & authenticating to ${wsUrl}...`);

  ws = new WebSocket(wsUrl);

  ws.on("open", () => {
    console.log("[AGENT] Connected & authenticated with Sentinel Analytica backend!");

    // Detect interfaces on this host machine
    const { interfaces } = detectNetworkInterfaces();
    const primaryIp = interfaces.find(i => i.status === "active" && i.type !== "loopback")?.ip || "127.0.0.1";
    const primaryMac = interfaces.find(i => i.status === "active" && i.mac !== "N/A")?.mac || "N/A";

    // Register with Central Backend
    const registerMsg = {
      type: "AGENT_REGISTER",
      agentId,
      name: agentName,
      platform: os.platform(),
      hostname: os.hostname(),
      ip: primaryIp,
      mac: primaryMac,
      interfaces
    };

    ws?.send(JSON.stringify(registerMsg));

    // Start periodic heartbeats
    if (heartbeatInterval) clearInterval(heartbeatInterval);
    heartbeatInterval = setInterval(() => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "HEARTBEAT", agentId }));
      }
    }, 8000);
  });

  ws.on("message", (data: WebSocket.RawData) => {
    try {
      const msg = JSON.parse(data.toString());
      handleServerCommand(msg, agentId);
    } catch (e) {
      console.error("[AGENT] Error parsing message from backend:", e);
    }
  });

  ws.on("close", (code, reason) => {
    cleanupCapture();
    if (heartbeatInterval) clearInterval(heartbeatInterval);

    if (code === 4003 || isRevoked) {
      console.error("\n[AGENT TERMINATED] Your agent authorization has been revoked by the dashboard administrator.");
      if (fs.existsSync(CONFIG_FILE_PATH)) {
        try { fs.unlinkSync(CONFIG_FILE_PATH); } catch (e) {}
      }
      process.exit(0);
      return;
    }

    console.warn(`[AGENT] Connection closed (code: ${code}). Retrying in 5 seconds...`);
    setTimeout(() => connectWebSocket(agentId, agentSecret, agentName), 5000);
  });

  ws.on("error", (err) => {
    console.error("[AGENT] WebSocket error:", err.message);
  });
}

function handleServerCommand(cmd: any, agentId: string) {
  switch (cmd.type) {
    case "REGISTER_ACK": {
      console.log(`[AGENT] Registration acknowledged by central server. Device: ${cmd.name || agentId}`);
      break;
    }

    case "AGENT_REVOKED": {
      console.error(`\n[AGENT REVOKED] ${cmd.message || "Credentials revoked."}`);
      isRevoked = true;
      if (ws) ws.close(4003, "Revoked");
      break;
    }

    case "REFRESH_INTERFACES": {
      console.log("[AGENT] Rescanning host network interfaces...");
      const { interfaces } = detectNetworkInterfaces();
      ws?.send(JSON.stringify({ type: "INTERFACE_UPDATE", agentId, interfaces }));
      break;
    }

    case "START_CAPTURE": {
      const interfaceId = cmd.interfaceId;
      console.log(`[AGENT] Received START_CAPTURE command for interface: ${interfaceId}`);
      startPacketCapture(interfaceId, agentId);
      break;
    }

    case "STOP_CAPTURE": {
      console.log("[AGENT] Received STOP_CAPTURE command.");
      cleanupCapture();
      ws?.send(JSON.stringify({
        type: "CAPTURE_STATUS",
        agentId,
        status: "stopped",
        session: null
      }));
      break;
    }
  }
}

function startPacketCapture(interfaceId: string, agentId: string) {
  cleanupCapture();
  currentInterfaceId = interfaceId;

  const tsharkBin = getTsharkBinary();
  const args = [
    "-i", interfaceId,
    "-l",
    "-T", "ek",
    "-e", "frame.number",
    "-e", "frame.time_epoch",
    "-e", "frame.len",
    "-e", "eth.src",
    "-e", "eth.dst",
    "-e", "ip.src",
    "-e", "ip.dst",
    "-e", "ipv6.src",
    "-e", "ipv6.dst",
    "-e", "ip.proto",
    "-e", "ip.ttl",
    "-e", "tcp.srcport",
    "-e", "tcp.dstport",
    "-e", "tcp.flags",
    "-e", "udp.srcport",
    "-e", "udp.dstport",
    "-e", "_ws.col.Protocol",
    "-e", "_ws.col.Info",
    "-e", "data"
  ];

  try {
    activeSnifferProcess = spawn(tsharkBin, args);
    isCapturing = true;

    ws?.send(JSON.stringify({
      type: "CAPTURE_STATUS",
      agentId,
      status: "monitoring",
      session: {
        interfaceId,
        interfaceName: interfaceId,
        startedAt: new Date().toISOString(),
        mode: "REAL",
        packetsCaptured: 0,
        bytesCaptured: 0
      }
    }));

    console.log(`[AGENT] Packet capture active on interface: ${interfaceId}`);

    let packetCounter = 0;
    let byteCounter = 0;

    activeSnifferProcess.stdout?.on("data", (chunk: Buffer) => {
      const lines = chunk.toString().split("\n");
      for (const line of lines) {
        if (!line.trim() || line.startsWith('{"index":')) continue;
        try {
          const packetData = JSON.parse(line);
          const layers = packetData.layers;
          if (!layers) continue;

          packetCounter++;
          const frameLen = parseInt(layers["frame_len"]?.[0] || "0", 10);
          byteCounter += frameLen;

          const packetPayload = {
            id: packetCounter,
            timestamp: new Date().toISOString(),
            protocol: layers["_ws_col_Protocol"]?.[0] || "OTHER",
            srcIp: layers["ip_src"]?.[0] || layers["ipv6_src"]?.[0] || "0.0.0.0",
            dstIp: layers["ip_dst"]?.[0] || layers["ipv6_dst"]?.[0] || "0.0.0.0",
            srcPort: parseInt(layers["tcp_srcport"]?.[0] || layers["udp_srcport"]?.[0] || "0", 10),
            dstPort: parseInt(layers["tcp_dstport"]?.[0] || layers["udp_dstport"]?.[0] || "0", 10),
            macSrc: layers["eth_src"]?.[0] || "N/A",
            macDst: layers["eth_dst"]?.[0] || "N/A",
            size: frameLen,
            ttl: parseInt(layers["ip_ttl"]?.[0] || "64", 10),
            tcpFlags: layers["tcp_flags"]?.[0] || "",
            checksum: "0x" + Math.floor(Math.random() * 65535).toString(16).padStart(4, "0"),
            payloadSize: Math.max(0, frameLen - 54),
            direction: "INCOMING" as const,
            interface: interfaceId,
            summary: layers["_ws_col_Info"]?.[0] || "Captured Packet",
            payloadHex: layers["data"]?.[0] || ""
          };

          ws?.send(JSON.stringify({
            type: "PACKET_STREAM",
            agentId,
            packet: packetPayload
          }));
        } catch (e) {}
      }
    });

    activeSnifferProcess.stderr?.on("data", (data: Buffer) => {
      const msg = data.toString();
      if (!msg.includes("Capturing on") && !msg.includes("packets captured")) {
        console.warn(`[AGENT CAPTURE] ${msg.trim()}`);
      }
    });

    activeSnifferProcess.on("exit", (code) => {
      console.log(`[AGENT] Sniffer process exited with code ${code}`);
      cleanupCapture();
      ws?.send(JSON.stringify({
        type: "CAPTURE_STATUS",
        agentId,
        status: "stopped",
        session: null
      }));
    });
  } catch (err: any) {
    console.error(`[AGENT ERROR] Failed to start tshark capture:`, err.message);
    ws?.send(JSON.stringify({
      type: "ERROR",
      agentId,
      error: `Capture failure: ${err.message}`
    }));
  }
}

function cleanupCapture() {
  if (activeSnifferProcess) {
    try { activeSnifferProcess.kill(); } catch (e) {}
    activeSnifferProcess = null;
  }
  isCapturing = false;
  currentInterfaceId = null;
}

// Handle termination signals
process.on("SIGINT", () => {
  console.log("\n[AGENT] Shutting down capture node...");
  cleanupCapture();
  if (ws) ws.close();
  process.exit(0);
});

process.on("SIGTERM", () => {
  cleanupCapture();
  if (ws) ws.close();
  process.exit(0);
});

// Run agent
startAgent();
