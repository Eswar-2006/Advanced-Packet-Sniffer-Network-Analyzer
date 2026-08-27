import { WebSocket, WebSocketServer } from "ws";
import { Server as HttpServer } from "http";
import os from "os";
import { AgentInfo, NetworkInterface, AgentStatus, CaptureMode } from "../src/types";
import { detectNetworkInterfaces } from "./interfaceDetector";
import { agentAuthStore } from "./agentAuthStore";

export interface ConnectedAgent extends AgentInfo {
  ws?: WebSocket;
  ownerId?: string;
  revoked?: boolean;
}

class AgentManager {
  private agents = new Map<string, ConnectedAgent>();
  private localAgentId = "agent-local";
  private wss: WebSocketServer | null = null;
  private dashboardSockets = new Set<WebSocket>();

  constructor() {
    this.initLocalAgent();
    // Heartbeat check interval for remote agents
    setInterval(() => this.checkHeartbeats(), 10000);
  }

  public initLocalAgent(): AgentInfo {
    const { interfaces, tsharkAvailable } = detectNetworkInterfaces();
    const activeIface = interfaces.find(i => i.status === "active" && i.type !== "loopback") || interfaces[0];

    const localInfo: ConnectedAgent = {
      id: this.localAgentId,
      name: `Local Agent (${os.hostname()})`,
      type: "LOCAL",
      platform: os.platform(),
      hostname: os.hostname(),
      ip: activeIface?.ip || "127.0.0.1",
      mac: activeIface?.mac || "N/A",
      status: "connected",
      lastSeen: new Date().toISOString(),
      isLocal: true,
      selectedInterfaceId: activeIface?.id || (interfaces[0]?.id || ""),
      interfaces,
      activeSession: null
    };

    this.agents.set(this.localAgentId, localInfo);
    return localInfo;
  }

  public attachWebSocket(server: HttpServer) {
    this.wss = new WebSocketServer({ noServer: true });

    server.on("upgrade", (request, socket, head) => {
      const url = request.url || "";
      if (url.startsWith("/ws/agent")) {
        // Authenticate agent connection via query param or headers
        const reqUrl = new URL(url, `http://${request.headers.host || "localhost"}`);
        const agentId = reqUrl.searchParams.get("agentId") || (request.headers["x-agent-id"] as string);
        const agentSecret =
          reqUrl.searchParams.get("agentSecret") ||
          (request.headers["x-agent-secret"] as string) ||
          reqUrl.searchParams.get("token") ||
          (request.headers["x-agent-token"] as string);

        const isLocalhost =
          request.socket.remoteAddress === "127.0.0.1" ||
          request.socket.remoteAddress === "::1" ||
          request.socket.remoteAddress === "::ffff:127.0.0.1";

        // Backward compatibility: Allow Local Agent on localhost without manual token
        if (agentId === this.localAgentId && isLocalhost) {
          // Permitted
        } else {
          // Validate against persistent hashed agent auth store
          if (!agentId || !agentSecret) {
            console.warn(`[AgentManager] Rejected unauthenticated agent connection attempt from ${request.socket.remoteAddress}`);
            socket.write("HTTP/1.1 401 Unauthorized\r\nContent-Type: text/plain\r\n\r\nMissing Agent ID or Secret\r\n");
            socket.destroy();
            return;
          }

          const validation = agentAuthStore.validateAgentCredential(agentId, agentSecret);
          if (!validation.valid) {
            console.warn(`[AgentManager] Rejected invalid agent connection [${agentId}]: ${validation.reason}`);
            const statusCode = validation.reason?.includes("revoked") ? "403 Forbidden" : "401 Unauthorized";
            socket.write(`HTTP/1.1 ${statusCode}\r\nContent-Type: text/plain\r\n\r\n${validation.reason}\r\n`);
            socket.destroy();
            return;
          }
        }

        this.wss?.handleUpgrade(request, socket, head, (ws) => {
          this.wss?.emit("connection", ws, request, "agent");
        });
      } else if (url.startsWith("/ws/dashboard")) {
        this.wss?.handleUpgrade(request, socket, head, (ws) => {
          this.wss?.emit("connection", ws, request, "dashboard");
        });
      }
    });

    this.wss.on("connection", (ws: WebSocket, request: any, clientType: string) => {
      if (clientType === "dashboard") {
        this.dashboardSockets.add(ws);
        // Send initial agent state to dashboard
        ws.send(JSON.stringify({ type: "AGENTS_LIST", agents: this.getPublicAgents() }));

        ws.on("close", () => this.dashboardSockets.delete(ws));
        return;
      }

      if (clientType === "agent") {
        let connectedAgentId: string | null = null;

        ws.on("message", (rawMessage: string) => {
          try {
            const data = JSON.parse(rawMessage.toString());
            this.handleAgentMessage(ws, data, (registeredId) => {
              connectedAgentId = registeredId;
            });
          } catch (e) {
            console.error("[AgentManager] Error processing agent message:", e);
          }
        });

        ws.on("close", () => {
          if (connectedAgentId) {
            this.handleAgentDisconnect(connectedAgentId);
          }
        });
      }
    });
  }

  private handleAgentMessage(ws: WebSocket, message: any, setAgentId: (id: string) => void) {
    switch (message.type) {
      case "AGENT_REGISTER": {
        const { agentId, name, platform, hostname, ip, mac, interfaces } = message;
        setAgentId(agentId);

        // Update persistence store
        agentAuthStore.updateAgentActivity(agentId, "connected");
        const storedMeta = agentAuthStore.getAgentById(agentId);

        const agent: ConnectedAgent = {
          id: agentId,
          name: storedMeta?.name || name || `Agent (${hostname || agentId})`,
          type: "REMOTE",
          platform: platform || storedMeta?.platform || "unknown",
          hostname: hostname || agentId,
          ip: ip || "0.0.0.0",
          mac: mac || "N/A",
          status: "connected",
          lastSeen: new Date().toISOString(),
          isLocal: false,
          selectedInterfaceId: interfaces?.[0]?.id,
          interfaces: interfaces || [],
          activeSession: null,
          ownerId: storedMeta?.ownerId || "default-user",
          ws
        };

        this.agents.set(agentId, agent);
        console.log(`[AgentManager] Remote agent authenticated & connected: ${agent.name} [ID: ${agentId}]`);
        this.broadcastToDashboards({ type: "AGENT_REGISTERED", agent: this.sanitizeAgent(agent) });
        ws.send(JSON.stringify({ type: "REGISTER_ACK", status: "ok", agentId, name: agent.name }));
        break;
      }

      case "HEARTBEAT": {
        const { agentId } = message;
        const agent = this.agents.get(agentId);
        if (agent) {
          agent.lastSeen = new Date().toISOString();
          agentAuthStore.updateAgentActivity(agentId, "connected");
          if (agent.status === "disconnected") {
            agent.status = "connected";
            this.broadcastToDashboards({ type: "AGENT_STATUS_CHANGE", agentId, status: "connected" });
          }
        }
        break;
      }

      case "INTERFACE_UPDATE": {
        const { agentId, interfaces } = message;
        const agent = this.agents.get(agentId);
        if (agent) {
          agent.interfaces = interfaces;
          this.broadcastToDashboards({ type: "INTERFACES_UPDATED", agentId, interfaces });
        }
        break;
      }

      case "CAPTURE_STATUS": {
        const { agentId, status, session } = message;
        const agent = this.agents.get(agentId);
        if (agent) {
          agent.status = status;
          agent.activeSession = session;
          this.broadcastToDashboards({ type: "AGENT_SESSION_UPDATE", agentId, status, session });
        }
        break;
      }

      case "ERROR": {
        const { agentId, error } = message;
        const agent = this.agents.get(agentId);
        if (agent) {
          agent.status = "error";
        }
        this.broadcastToDashboards({ type: "AGENT_ERROR", agentId, error });
        break;
      }
    }
  }

  private handleAgentDisconnect(agentId: string) {
    const agent = this.agents.get(agentId);
    if (agent && !agent.isLocal) {
      agent.status = "disconnected";
      agent.ws = undefined;
      agent.activeSession = null;
      agentAuthStore.updateAgentActivity(agentId, "disconnected");
      console.warn(`[AgentManager] Remote agent disconnected: ${agent.name} [${agentId}]`);
      this.broadcastToDashboards({ type: "AGENT_DISCONNECTED", agentId, message: "Agent is currently offline." });
    }
  }

  public disconnectRevokedAgent(agentId: string) {
    const agent = this.agents.get(agentId);
    if (agent) {
      if (agent.ws && agent.ws.readyState === WebSocket.OPEN) {
        try {
          agent.ws.send(JSON.stringify({ type: "AGENT_REVOKED", message: "Your agent credentials have been revoked by the administrator." }));
          agent.ws.close(4003, "Agent Revoked");
        } catch (e) {}
      }
      this.agents.delete(agentId);
      this.broadcastToDashboards({ type: "AGENT_REVOKED", agentId });
      this.broadcastToDashboards({ type: "AGENTS_LIST", agents: this.getPublicAgents() });
    }
  }

  private checkHeartbeats() {
    const now = Date.now();
    for (const [id, agent] of this.agents.entries()) {
      if (agent.isLocal) continue;
      const elapsed = now - new Date(agent.lastSeen).getTime();
      if (elapsed > 25000 && agent.status !== "disconnected") {
        this.handleAgentDisconnect(id);
      }
    }
  }

  public refreshLocalInterfaces(): NetworkInterface[] {
    const localAgent = this.agents.get(this.localAgentId);
    if (localAgent) {
      const { interfaces } = detectNetworkInterfaces();
      localAgent.interfaces = interfaces;
      this.broadcastToDashboards({ type: "INTERFACES_UPDATED", agentId: this.localAgentId, interfaces });
      return interfaces;
    }
    return [];
  }

  public updateLocalSession(status: AgentStatus, session: AgentInfo['activeSession']) {
    const localAgent = this.agents.get(this.localAgentId);
    if (localAgent) {
      localAgent.status = status;
      localAgent.activeSession = session;
      this.broadcastToDashboards({ type: "LOCAL_SESSION_UPDATE", status, session });
    }
  }

  public getPublicAgents(): AgentInfo[] {
    const registeredRecords = agentAuthStore.getAgents("default-user");
    const activeAgents = Array.from(this.agents.values()).map(a => this.sanitizeAgent(a));

    // Merge registered offline records if they aren't currently in active memory
    for (const record of registeredRecords) {
      if (!record.revokedAt && !activeAgents.some(a => a.id === record.id)) {
        activeAgents.push({
          id: record.id,
          name: record.name,
          type: "REMOTE",
          platform: record.platform,
          hostname: record.name,
          ip: "0.0.0.0",
          mac: "N/A",
          status: "disconnected",
          lastSeen: record.lastSeenAt,
          isLocal: false,
          interfaces: [],
          activeSession: null
        });
      }
    }

    return activeAgents;
  }

  public getAgent(id: string): ConnectedAgent | undefined {
    return this.agents.get(id);
  }

  private sanitizeAgent(agent: ConnectedAgent): AgentInfo {
    // Strip private WebSocket instance and credentials before sending to dashboard!
    const { ws, ...publicAgent } = agent;
    return publicAgent;
  }

  public broadcastToDashboards(data: any) {
    const payload = JSON.stringify(data);
    for (const ws of this.dashboardSockets) {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(payload);
      }
    }
  }

  public sendCommandToAgent(agentId: string, command: any): boolean {
    const agent = this.agents.get(agentId);
    if (!agent) return false;
    if (agent.isLocal) return true; // Handled internally
    if (agent.ws && agent.ws.readyState === WebSocket.OPEN) {
      agent.ws.send(JSON.stringify(command));
      return true;
    }
    return false;
  }
}

export const agentManager = new AgentManager();
