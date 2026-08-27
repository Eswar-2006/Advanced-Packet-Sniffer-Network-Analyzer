import crypto from "crypto";
import fs from "fs";
import path from "path";

export interface AgentRecord {
  id: string;
  ownerId: string;
  name: string;
  platform: string;
  agentVersion: string;
  status: "registered" | "connected" | "disconnected" | "revoked";
  credentialHash: string;
  createdAt: string;
  lastSeenAt: string;
  revokedAt: string | null;
}

export interface AgentRegistrationToken {
  id: string;
  ownerId: string;
  tokenHash: string;
  name?: string;
  expiresAt: number; // timestamp in ms
  usedAt: string | null;
  createdAt: string;
}

interface AgentAuthData {
  agents: AgentRecord[];
  tokens: AgentRegistrationToken[];
}

export class AgentAuthStore {
  private dataFilePath: string;
  private data: AgentAuthData = { agents: [], tokens: [] };

  constructor(filePath?: string) {
    this.dataFilePath = filePath || path.join(process.cwd(), "data", "agent_auth.json");
    this.initStorage();
  }

  private initStorage() {
    try {
      const dir = path.dirname(this.dataFilePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }

      if (fs.existsSync(this.dataFilePath)) {
        const raw = fs.readFileSync(this.dataFilePath, "utf8");
        this.data = JSON.parse(raw);
        if (!this.data.agents) this.data.agents = [];
        if (!this.data.tokens) this.data.tokens = [];
      } else {
        this.save();
      }
    } catch (e) {
      console.error("[AgentAuthStore] Error loading auth data, initializing in-memory:", e);
      this.data = { agents: [], tokens: [] };
    }
  }

  private save() {
    try {
      const dir = path.dirname(this.dataFilePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      fs.writeFileSync(this.dataFilePath, JSON.stringify(this.data, null, 2), "utf8");
    } catch (e) {
      console.error("[AgentAuthStore] Error persisting auth data:", e);
    }
  }

  private hashSecret(secret: string): string {
    return crypto.createHash("sha256").update(secret).digest("hex");
  }

  /**
   * Generates a secure, single-use registration token valid for 15 minutes.
   */
  public createRegistrationToken(ownerId: string = "default-user", name?: string): {
    token: string;
    tokenId: string;
    expiresAt: number;
    expiresInSeconds: number;
  } {
    // Generate 32 bytes cryptographically secure random token (e.g. sat_reg_xxxxxxxx...)
    const rawSecret = crypto.randomBytes(24).toString("hex");
    const token = `sat_reg_${rawSecret}`;
    const tokenHash = this.hashSecret(token);
    const tokenId = `tok_${crypto.randomBytes(8).toString("hex")}`;
    const now = Date.now();
    const ttlMs = 15 * 60 * 1000; // 15 minutes
    const expiresAt = now + ttlMs;

    const tokenRecord: AgentRegistrationToken = {
      id: tokenId,
      ownerId,
      tokenHash,
      name: name?.trim() || "Remote Capture Device",
      expiresAt,
      usedAt: null,
      createdAt: new Date().toISOString()
    };

    // Cleanup expired unused tokens
    this.data.tokens = this.data.tokens.filter(t => t.usedAt !== null || t.expiresAt > now);
    this.data.tokens.push(tokenRecord);
    this.save();

    return {
      token,
      tokenId,
      expiresAt,
      expiresInSeconds: Math.floor(ttlMs / 1000)
    };
  }

  /**
   * Redeems a one-time registration token to register an agent and generate long-term credentials.
   */
  public redeemRegistrationToken(
    token: string,
    meta: {
      deviceName?: string;
      platform?: string;
      agentVersion?: string;
    }
  ): {
    success: boolean;
    agentId?: string;
    agentSecret?: string;
    error?: string;
    agentName?: string;
  } {
    if (!token || typeof token !== "string") {
      return { success: false, error: "Registration token is required" };
    }

    const tokenHash = this.hashSecret(token.trim());
    const now = Date.now();

    const tokenRecord = this.data.tokens.find(t => t.tokenHash === tokenHash);
    if (!tokenRecord) {
      return { success: false, error: "Invalid registration token" };
    }

    if (tokenRecord.usedAt) {
      return { success: false, error: "Registration token has already been used" };
    }

    if (tokenRecord.expiresAt < now) {
      return { success: false, error: "Registration token has expired. Please generate a new one from the dashboard." };
    }

    // Invalidate token (one-time use)
    tokenRecord.usedAt = new Date().toISOString();

    // Generate unique agentId and long-term secret
    const agentId = `agent_${crypto.randomBytes(8).toString("hex")}`;
    const agentSecret = `sat_sec_${crypto.randomBytes(32).toString("hex")}`;
    const credentialHash = this.hashSecret(agentSecret);

    const agentName = meta.deviceName?.trim() || tokenRecord.name || `Sentinel Agent (${meta.platform || "remote"})`;

    const agentRecord: AgentRecord = {
      id: agentId,
      ownerId: tokenRecord.ownerId,
      name: agentName,
      platform: meta.platform || "unknown",
      agentVersion: meta.agentVersion || "1.0.0",
      status: "registered",
      credentialHash,
      createdAt: new Date().toISOString(),
      lastSeenAt: new Date().toISOString(),
      revokedAt: null
    };

    this.data.agents.push(agentRecord);
    this.save();

    return {
      success: true,
      agentId,
      agentSecret,
      agentName
    };
  }

  /**
   * Validates an agent's long-term credential using constant-time hash comparison.
   */
  public validateAgentCredential(
    agentId: string,
    agentSecret: string
  ): { valid: boolean; agent?: AgentRecord; reason?: string } {
    if (!agentId || !agentSecret) {
      return { valid: false, reason: "Missing agent ID or secret" };
    }

    const agent = this.data.agents.find(a => a.id === agentId);
    if (!agent) {
      return { valid: false, reason: "Agent not found" };
    }

    if (agent.revokedAt) {
      return { valid: false, reason: "Agent has been revoked by owner" };
    }

    const inputHash = this.hashSecret(agentSecret.trim());
    const inputHashBuf = Buffer.from(inputHash, "utf8");
    const storedHashBuf = Buffer.from(agent.credentialHash, "utf8");

    if (inputHashBuf.length !== storedHashBuf.length || !crypto.timingSafeEqual(inputHashBuf, storedHashBuf)) {
      return { valid: false, reason: "Invalid agent credentials" };
    }

    return { valid: true, agent };
  }

  /**
   * Updates last seen timestamp and status for an agent.
   */
  public updateAgentActivity(agentId: string, status: "connected" | "disconnected" | "registered" = "connected") {
    const agent = this.data.agents.find(a => a.id === agentId);
    if (agent) {
      agent.lastSeenAt = new Date().toISOString();
      if (!agent.revokedAt) {
        agent.status = status;
      }
      this.save();
    }
  }

  /**
   * Revokes an agent, permanently invalidating its credentials.
   */
  public revokeAgent(agentId: string, ownerId?: string): { success: boolean; error?: string } {
    const agent = this.data.agents.find(a => a.id === agentId);
    if (!agent) {
      return { success: false, error: "Agent not found" };
    }

    if (ownerId && agent.ownerId !== ownerId) {
      return { success: false, error: "Unauthorized to revoke this agent" };
    }

    agent.revokedAt = new Date().toISOString();
    agent.status = "revoked";
    this.save();

    return { success: true };
  }

  /**
   * Retrieves all agents belonging to a user (masking sensitive credential hashes).
   */
  public getAgents(ownerId: string = "default-user"): Omit<AgentRecord, "credentialHash">[] {
    return this.data.agents
      .filter(a => !ownerId || a.ownerId === ownerId)
      .map(({ credentialHash, ...rest }) => rest);
  }

  /**
   * Retrieves single agent record by ID (masked).
   */
  public getAgentById(agentId: string): Omit<AgentRecord, "credentialHash"> | null {
    const agent = this.data.agents.find(a => a.id === agentId);
    if (!agent) return null;
    const { credentialHash, ...rest } = agent;
    return rest;
  }
}

export const agentAuthStore = new AgentAuthStore();
