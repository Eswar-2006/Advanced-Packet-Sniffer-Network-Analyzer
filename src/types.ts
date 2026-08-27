export interface LayerDetail {
  layer: 'FRAME' | 'ETHERNET' | 'IP' | 'TRANSPORT' | 'APPLICATION';
  title: string;
  fields: { name: string; value: string; note?: string }[];
}

export interface Packet {
  id: number;
  timestamp: string;
  protocol: string;
  srcIp: string;
  dstIp: string;
  srcPort?: number;
  dstPort?: number;
  macSrc: string;
  macDst: string;
  size: number;
  ttl?: number;
  hopLimit?: number;
  tcpFlags?: string;
  seqNumber?: number;
  ackNumber?: number;
  checksum: string;
  payloadSize: number;
  direction: 'INCOMING' | 'OUTGOING' | 'LOOPBACK';
  hostname?: string;
  vendor?: string;
  service?: string;
  appProtocol?: string;
  country?: string;
  asn?: string;
  interface: string;
  summary: string;
  payloadHex?: string;
  payloadAscii?: string;
  payloadBinary?: string;
  bookmarked?: boolean;
  blocked?: boolean;
  tagged?: string;
  packetExplanation?: string;
  layerDetails?: LayerDetail[];
}


export interface SnifferStats {
  totalPackets: number;
  packetsPerSec: number;
  bandwidthBps: number;
  incomingBytes: number;
  outgoingBytes: number;
  cpuUsage: number;
  memoryUsage: number;
  diskUsage: number;
  networkUtilization: number;
  activeConnections: number;
  interfaceStatus: 'ACTIVE' | 'IDLE' | 'DISCONNECTED';
  topSourceIp: string;
  topDstIp: string;
  topPort: number;
  topProtocol: string;
  topCountry: string;
  threatCounter: number;
  alertCounter: number;
  isCapturing: boolean;
  networkHealthScore: number;
}

export interface SecurityAlert {
  id: string;
  timestamp: string;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  type: string;
  source: string;
  destination: string;
  message: string;
  packetId?: number;
  resolved: boolean;
}

export interface SnifferFilter {
  protocol: string;
  ip: string;
  port: string;
  mac: string;
  sizeMin: string;
  sizeMax: string;
  country: string;
  tcpFlag: string;
  direction: string;
  searchQuery: string;
}

export interface DesktopSourceCode {
  filename: string;
  path: string;
  content: string;
}

export type InterfaceType = 'wireless' | 'ethernet' | 'vpn' | 'loopback' | 'virtual' | 'other';
export type AgentType = 'LOCAL' | 'REMOTE';
export type AgentStatus = 'connected' | 'disconnected' | 'monitoring' | 'stopped' | 'error';
export type CaptureMode = 'REAL' | 'SIMULATED';

export interface NetworkInterface {
  id: string;                // Exact tshark identifier, e.g. \Device\NPF_{...} or eth0
  name: string;              // User friendly display name (Wi-Fi, Ethernet 1)
  displayName: string;       // Full name with adapter details
  type: InterfaceType;       // wireless | ethernet | vpn | loopback | virtual | other
  ip: string;                // IP address
  mac: string;               // MAC address
  status: 'active' | 'inactive';
  captureSupported: boolean;
  notes?: string;
}

export interface AgentRecord {
  id: string;
  ownerId: string;
  name: string;
  platform: string;
  agentVersion: string;
  status: "registered" | "connected" | "disconnected" | "revoked";
  createdAt: string;
  lastSeenAt: string;
  revokedAt: string | null;
}

export interface AgentRegistrationResponse {
  success: boolean;
  token: string;
  tokenId: string;
  expiresAt: number;
  expiresInSeconds: number;
  setupCommand: string;
  npxCommand: string;
}

export interface AgentInfo {
  id: string;
  name: string;
  type: AgentType;
  platform: string;
  hostname: string;
  ip: string;
  mac: string;
  status: AgentStatus;
  lastSeen: string;
  isLocal: boolean;
  selectedInterfaceId?: string;
  activeSession?: {
    interfaceId: string;
    interfaceName: string;
    startedAt: string;
    mode: CaptureMode;
    packetsCaptured: number;
    bytesCaptured: number;
  } | null;
  interfaces: NetworkInterface[];
}

export interface PcapFinding {
  id: string;
  packetId?: number;
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  category: string; // 'PORT_SCAN' | 'CREDS_LEAK' | 'SUSPICIOUS_DNS' | 'UNSECURE_PROTOCOL' | 'ANOMALOUS_BURST'
  title: string;
  description: string;
  sourceIp: string;
  destinationIp: string;
  protocol: string;
  recommendation: string;
}

export interface CtfArtifact {
  id: string;
  type: 'CTF_FLAG' | 'CREDENTIAL' | 'FILE_TRANSFER' | 'DNS_TUNNEL' | 'SENSITIVE_STRING';
  title: string;
  value: string;
  packetId?: number;
  protocol: string;
  srcIp: string;
  dstIp: string;
  confidence: 'HIGH' | 'CRITICAL' | 'MEDIUM';
}

export interface ReconstructedFile {
  id: string;
  filename: string;
  mimeType: string;
  sizeBytes: number;
  packetId: number;
  sampleHex: string;
  protocol: string;
}

export interface PcapAnalysisReport {
  filename: string;
  fileSizeBytes: number;
  analyzedAt: string;
  totalPackets: number;
  totalBytes: number;
  durationSeconds: number;
  riskScore: number; // 0 to 100
  riskLevel: 'CLEAN' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  findings: PcapFinding[];
  protocolDistribution: { protocol: string; count: number; bytes: number }[];
  topTalkers: { ip: string; packets: number; bytes: number; role: 'SRC' | 'DST' | 'BOTH' }[];
  packets: Packet[];
  ctfArtifacts?: CtfArtifact[];
  reconstructedFiles?: ReconstructedFile[];
}


