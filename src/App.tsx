import React, { useState, useEffect } from 'react';
import { Packet, SecurityAlert, SnifferStats, SnifferFilter, AgentInfo, NetworkInterface, CaptureMode } from './types';
import { INITIAL_PACKETS, INITIAL_ALERTS, INITIAL_STATS, DEMO_PACKETS } from './mockData';
import { filterPackets, runSecurityAnalysis } from './utils';
import { exportToCSV, exportToJSON, generateHTMLReport } from './reportGenerator';
import { SecurityPanel } from './components/SecurityPanel';
import { DesktopCodePanel } from './components/DesktopCodePanel';
import { AICopilotPanel } from './components/AICopilotPanel';
import { DocsPanel } from './components/DocsPanel';
import { ToolsPanel } from './components/ToolsPanel';
import { MonitoringSourceBar } from './components/MonitoringSourceBar';
import { PcapAnalyzerPanel } from './components/PcapAnalyzerPanel';
import { DownloadDesktopModal } from './components/DownloadDesktopModal';
import { AddAgentModal } from './components/AddAgentModal';

// Lucide Icons
import {
  Activity,
  Shield,
  Search,
  Filter,
  FileDown,
  Play,
  Square,
  RefreshCw,
  Plus,
  AlertTriangle,
  Bookmark,
  BookOpen,
  Terminal,
  Cpu,
  HardDrive,
  Network,
  Download,
  AlertCircle,
  TrendingUp,
  Tag,
  Check,
  Code,
  Wrench,
  FileCode,
  ShieldAlert,
  Laptop
} from 'lucide-react';



// Recharts components
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  Legend
} from 'recharts';

export default function App() {
  // Navigation
  const [activeTab, setActiveTab] = useState<'DASHBOARD' | 'PACKETS' | 'TRAFFIC' | 'SECURITY' | 'PCAP' | 'SOURCE' | 'COPILOT' | 'DOCS' | 'TOOLS'>('DASHBOARD');


  // Packets & Alerts State
  const [packets, setPackets] = useState<Packet[]>(INITIAL_PACKETS);
  const [alerts, setAlerts] = useState<SecurityAlert[]>(INITIAL_ALERTS);
  const [stats, setStats] = useState<SnifferStats>(INITIAL_STATS);
  const [isDemoMode, setIsDemoMode] = useState<boolean>(false);

  // Live traffic intelligence state
  const [liveConnections, setLiveConnections] = useState<any[]>([]);
  const [dnsEntries, setDnsEntries] = useState<any[]>([]);
  const [topSites, setTopSites] = useState<any[]>([]);
  const [totalBytes, setTotalBytes] = useState(0);

  // Selected Packet for Inspector
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);

  // Filters state
  const [filters, setFilters] = useState<SnifferFilter>({
    protocol: 'ALL',
    ip: '',
    port: '',
    mac: '',
    sizeMin: '',
    sizeMax: '',
    country: 'ALL',
    tcpFlag: 'ALL',
    direction: 'ALL',
    searchQuery: ''
  });

  // Settings config
  const [showFiltersModal, setShowFiltersModal] = useState(false);
  const [captureInterface, setCaptureInterface] = useState('eth0 (Default Ethernet)');
  const [selectedFileForUpload, setSelectedFileForUpload] = useState<string | null>(null);

  // Right-click Context Menu State
  const [contextMenu, setContextMenu] = useState<{
    x: number;
    y: number;
    packet: Packet;
  } | null>(null);

  // WHOIS Modal / Panel State
  const [whoisModal, setWhoisModal] = useState<{
    ip: string;
    loading: boolean;
    data: {
      range: string;
      netName: string;
      country: string;
      org: string;
      status: string;
      raw: string;
    } | null;
    error: string | null;
  } | null>(null);

  // Synced List of blocked IPs to show in a badge or alert
  const [blockedIpsList, setBlockedIpsList] = useState<string[]>([]);

  // Local machine identity (whose traffic is being captured)
  const [localInfo, setLocalInfo] = useState<{
    hostname: string;
    username: string;
    localIp: string;
    macAddress: string;
    platform: string;
    captureNote: string;
  } | null>(null);

  // Multi-Agent and Interface State
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [selectedAgentId, setSelectedAgentId] = useState<string>('agent-local');
  const [selectedInterfaceId, setSelectedInterfaceId] = useState<string>('');
  const [captureMode, setCaptureMode] = useState<CaptureMode>('REAL');
  const [isRefreshingAgents, setIsRefreshingAgents] = useState(false);
  const [isDownloadModalOpen, setIsDownloadModalOpen] = useState(false);
  const [isAddAgentModalOpen, setIsAddAgentModalOpen] = useState(false);


  // Fetch agents list
  const fetchAgents = async () => {
    try {
      const res = await fetch('/api/agents');
      const data = await res.json();
      if (data.agents && data.agents.length > 0) {
        setAgents(data.agents);
        const currentAgent = data.agents.find((a: AgentInfo) => a.id === selectedAgentId) || data.agents[0];
        if (currentAgent && currentAgent.interfaces.length > 0 && !selectedInterfaceId) {
          setSelectedInterfaceId(currentAgent.interfaces[0].id);
          setCaptureInterface(currentAgent.interfaces[0].name);
        }
      }
    } catch (e) {
      console.error("Failed to fetch agents:", e);
    }
  };

  // Fetch current blocked IPs on mount and sync capture status
  const fetchInitialData = async () => {
    try {
      const [blocksRes, statusRes, localRes] = await Promise.all([
        fetch('/api/firewall/blocks'),
        fetch('/api/status'),
        fetch('/api/local-info')
      ]);
      const blocksData = await blocksRes.json();
      const statusData = await statusRes.json();
      const localData  = await localRes.json();

      if (blocksData.blockedIps) {
        setBlockedIpsList(blocksData.blockedIps);
      }
      if (statusData) {
        if (statusData.captureMode) setCaptureMode(statusData.captureMode);
        setStats(prev => ({
          ...prev,
          isCapturing: statusData.isCapturing,
          interfaceStatus: statusData.isCapturing ? 'ACTIVE' : 'IDLE',
          totalPackets: statusData.totalPacketsCaptured || prev.totalPackets,
          packetsPerSec: statusData.packetsPerSec || prev.packetsPerSec
        }));
      }
      if (localData?.hostname) {
        setLocalInfo(localData);
      }
      await fetchAgents();
    } catch (e) {
      console.error("Error fetching initial data from backend:", e);
    }
  };

  useEffect(() => {
    fetchInitialData();

    // WebSocket dashboard connection for real-time agent events
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/dashboard`;
    let ws: WebSocket | null = null;

    try {
      ws = new WebSocket(wsUrl);
      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'AGENTS_LIST') {
            setAgents(msg.agents);
          } else if (
            msg.type === 'AGENT_REGISTERED' ||
            msg.type === 'AGENT_STATUS_CHANGE' ||
            msg.type === 'INTERFACES_UPDATED' ||
            msg.type === 'AGENT_DISCONNECTED'
          ) {
            fetchAgents();
          }
        } catch (err) {
          console.error("WS message error:", err);
        }
      };
    } catch (err) {
      console.warn("WebSocket dashboard connection failed:", err);
    }

    return () => {
      if (ws) ws.close();
    };
  }, []);

  const handleSelectAgent = (agentId: string) => {
    setSelectedAgentId(agentId);
    const targetAgent = agents.find(a => a.id === agentId);
    if (targetAgent && targetAgent.interfaces.length > 0) {
      setSelectedInterfaceId(targetAgent.interfaces[0].id);
      setCaptureInterface(targetAgent.interfaces[0].name);
    }
  };

  const handleSelectInterface = (interfaceId: string) => {
    setSelectedInterfaceId(interfaceId);
    const targetAgent = agents.find(a => a.id === selectedAgentId);
    const iface = targetAgent?.interfaces.find(i => i.id === interfaceId);
    if (iface) {
      setCaptureInterface(iface.name);
    }
  };

  const handleRefreshInterfaces = async (agentId: string) => {
    setIsRefreshingAgents(true);
    try {
      await fetch(`/api/agents/${agentId}/refresh-interfaces`, { method: 'POST' });
      await fetchAgents();
    } catch (err) {
      console.error("Failed to refresh interfaces:", err);
    } finally {
      setIsRefreshingAgents(false);
    }
  };

  const handleStartMonitoring = async (agentId: string, interfaceId: string) => {
    try {
      setStats(prev => ({ ...prev, isCapturing: true, interfaceStatus: 'ACTIVE' }));
      const res = await fetch(`/api/agents/${agentId}/start-sniffing`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interfaceId })
      });
      const data = await res.json();
      if (data.mode) {
        setCaptureMode(data.mode);
      }
      fetchAgents();
    } catch (err) {
      console.error("Failed to start monitoring:", err);
    }
  };

  const handleStopMonitoring = async (agentId: string) => {
    try {
      setStats(prev => ({ ...prev, isCapturing: false, interfaceStatus: 'IDLE', packetsPerSec: 0 }));
      await fetch(`/api/agents/${agentId}/stop-sniffing`, { method: 'POST' });
      await fetch('/api/stop-sniffing', { method: 'POST' });
      fetchAgents();
    } catch (err) {
      console.error("Failed to stop monitoring:", err);
    }
  };


  // Handle Close of Context Menu
  useEffect(() => {
    const handleClose = () => setContextMenu(null);
    window.addEventListener('click', handleClose);
    return () => window.removeEventListener('click', handleClose);
  }, []);

  const handleFirewallBlock = async (ip: string) => {
    try {
      const res = await fetch('/api/firewall/block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      const data = await res.json();
      if (data.success) {
        setBlockedIpsList(data.blockedIps || []);
        
        // Push a new alert to the security notifications stream
        const newAlert: SecurityAlert = {
          id: `alert_fw_${Date.now()}`,
          timestamp: new Date().toISOString(),
          severity: 'HIGH',
          type: 'Firewall Policy Block',
          source: ip,
          destination: 'ANY',
          message: `Sentinel firewall rule enforced: Dropping all traffic vectors matching IP ${ip}. Heuristic routing actively blacklisting socket handlers.`,
          resolved: false
        };
        setAlerts(prev => [newAlert, ...prev]);
        setStats(prev => ({
          ...prev,
          threatCounter: prev.threatCounter + 1,
          alertCounter: prev.alertCounter + 1
        }));
      }
    } catch (err) {
      console.error("Failed to block IP in firewall:", err);
    }
  };

  const handleFirewallUnblock = async (ip: string) => {
    try {
      const res = await fetch('/api/firewall/unblock', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip })
      });
      const data = await res.json();
      if (data.success) {
        setBlockedIpsList(data.blockedIps || []);
      }
    } catch (err) {
      console.error("Failed to unblock IP in firewall:", err);
    }
  };

  const handleWhoisLookup = async (ip: string) => {
    setWhoisModal({ ip, loading: true, data: null, error: null });
    try {
      const res = await fetch(`/api/whois?ip=${ip}`);
      const data = await res.json();
      if (res.ok) {
        setWhoisModal({ ip, loading: false, data, error: null });
      } else {
        setWhoisModal({ ip, loading: false, data: null, error: data.error || 'Failed to fetch WHOIS info' });
      }
    } catch (err: any) {
      setWhoisModal({ ip, loading: false, data: null, error: err.message || err });
    }
  };

  const downloadPayload = (packetId: number, format: 'hex' | 'ascii' | 'raw') => {
    const url = `/api/packet/download-payload?id=${packetId}&format=${format}`;
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `packet_${packetId}_payload_${format}`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Poll real-time data from backend packet ingestion engine
  useEffect(() => {
    const fetchAll = async () => {
      try {
        const [packetsRes, statsRes, connsRes, dnsRes, sitesRes] = await Promise.all([
          fetch('/api/packets'),
          fetch('/api/system-stats'),
          fetch('/api/connections'),
          fetch('/api/dns-cache'),
          fetch('/api/top-sites'),
        ]);
        const packetsData = await packetsRes.json();
        const statsData   = await statsRes.json();
        const connsData   = await connsRes.json();
        const dnsData     = await dnsRes.json();
        const sitesData   = await sitesRes.json();

        if (packetsData.packets) {
          setPackets(packetsData.packets);
          setTotalBytes(packetsData.stats?.totalBytes || 0);

          // Compute conservative real threat analysis directly from observed packets
          const computedAlerts = runSecurityAnalysis(packetsData.packets);
          setAlerts(computedAlerts);

          if (packetsData.stats?.usingSimulator !== undefined) {
            setIsDemoMode(packetsData.stats.usingSimulator);
            setCaptureMode(packetsData.stats.usingSimulator ? 'SIMULATED' : 'REAL');
          }

          setStats(prev => {
            const serverCapturing = packetsData.stats?.isCapturing ?? prev.isCapturing;
            return {
              ...prev,
              isCapturing: serverCapturing,
              interfaceStatus: serverCapturing ? 'ACTIVE' : 'IDLE',
              totalPackets:    packetsData.stats?.totalPacketsCaptured ?? packetsData.packets.length,
              packetsPerSec:   serverCapturing ? (packetsData.stats?.packetsPerSec || 0) : 0,
              incomingBytes:   packetsData.stats?.incomingBytes || 0,
              outgoingBytes:   packetsData.stats?.outgoingBytes || 0,
              cpuUsage:        statsData.cpuUsage        || prev.cpuUsage,
              memoryUsage:     statsData.memoryUsage     || prev.memoryUsage,
              diskUsage:       statsData.diskUsage       || prev.diskUsage,
              activeConnections: connsData.total         || prev.activeConnections,
              threatCounter:   computedAlerts.length,
              alertCounter:    computedAlerts.length,
              networkHealthScore: Math.max(25, 100 - computedAlerts.length * 15)
            };
          });

          setSelectedPacket(prev => prev || packetsData.packets[0] || null);
        }
        if (connsData.connections) setLiveConnections(connsData.connections);
        if (dnsData.entries)       setDnsEntries(dnsData.entries);
        if (sitesData.sites)       setTopSites(sitesData.sites);
      } catch (err) {
        console.error('Error fetching live data:', err);
      }
    };

    fetchAll();
    const interval = setInterval(fetchAll, 1500);
    return () => clearInterval(interval);
  }, []);

  // Demo Mode Switcher
  const handleToggleDemoMode = async () => {
    try {
      const res = await fetch('/api/demo-mode/toggle', { method: 'POST' });
      const data = await res.json();
      setIsDemoMode(data.demoMode);
      setCaptureMode(data.demoMode ? 'SIMULATED' : 'REAL');
      if (data.demoMode) {
        setPackets(DEMO_PACKETS);
        setSelectedPacket(DEMO_PACKETS[0] || null);
        const demoAlerts = runSecurityAnalysis(DEMO_PACKETS);
        setAlerts(demoAlerts);
        setStats(prev => ({
          ...prev,
          totalPackets: DEMO_PACKETS.length,
          packetsPerSec: 6,
          threatCounter: demoAlerts.length,
          alertCounter: demoAlerts.length,
          networkHealthScore: 85
        }));
      } else {
        setPackets([]);
        setAlerts([]);
        setLiveConnections([]);
        setDnsEntries([]);
        setTopSites([]);
        setSelectedPacket(null);
        setStats(prev => ({
          ...prev,
          totalPackets: 0,
          packetsPerSec: 0,
          incomingBytes: 0,
          outgoingBytes: 0,
          activeConnections: 0,
          threatCounter: 0,
          alertCounter: 0,
          networkHealthScore: 100
        }));
        // Request immediate live packet pull
        const pRes = await fetch('/api/packets');
        const pData = await pRes.json();
        if (pData.packets && pData.packets.length > 0) {
          setPackets(pData.packets);
          setSelectedPacket(pData.packets[0] || null);
          const liveAlerts = runSecurityAnalysis(pData.packets);
          setAlerts(liveAlerts);
        }
      }
    } catch (err) {
      console.error("Failed to toggle demo mode:", err);
    }
  };


  // Start / Stop sniffer action
  const toggleCapture = async () => {
    const nextCapturing = !stats.isCapturing;
    setStats(prev => ({
      ...prev,
      isCapturing: nextCapturing,
      interfaceStatus: nextCapturing ? 'ACTIVE' : 'IDLE',
      packetsPerSec: nextCapturing ? prev.packetsPerSec : 0
    }));

    try {
      if (nextCapturing) {
        await fetch('/api/start-sniffing', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ interfaceName: selectedInterfaceId || captureInterface || 'any' })
        });
        if (selectedAgentId && selectedAgentId !== 'agent-local') {
          await fetch(`/api/agents/${selectedAgentId}/start-sniffing`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ interfaceId: selectedInterfaceId })
          });
        }
      } else {
        await fetch('/api/stop-sniffing', {
          method: 'POST'
        });
        if (selectedAgentId && selectedAgentId !== 'agent-local') {
          await fetch(`/api/agents/${selectedAgentId}/stop-sniffing`, {
            method: 'POST'
          });
        }
      }
      fetchAgents();
    } catch (err) {
      console.error("Failed to sync capture toggle with backend:", err);
    }
  };

  // Clear packet logs
  const clearLogs = async () => {
    setPackets([]);
    setSelectedPacket(null);
    setStats(prev => ({
      ...prev,
      totalPackets: 0,
      incomingBytes: 0,
      outgoingBytes: 0,
      threatCounter: 0,
      alertCounter: 0
    }));
    setAlerts([]);
    try {
      await fetch('/api/clear-all', { method: 'POST' });
    } catch (err) {
      console.error("Failed to clear logs on backend:", err);
    }
  };

  // Add individual simulated custom packet
  const handleAddPacket = (newP: Packet) => {
    setPackets(prev => [newP, ...prev]);
    setStats(prev => ({
      ...prev,
      totalPackets: prev.totalPackets + 1
    }));
  };

  // Add alert to security log
  const handleAddAlert = (newA: SecurityAlert) => {
    setAlerts(prev => [newA, ...prev]);
    setStats(prev => ({
      ...prev,
      threatCounter: prev.threatCounter + 1,
      alertCounter: prev.alertCounter + 1,
      networkHealthScore: Math.max(prev.networkHealthScore - 12, 10)
    }));
  };

  // Toggle bookmark on selected packet
  const toggleBookmark = (id: number) => {
    setPackets(prev =>
      prev.map(p => (p.id === id ? { ...p, bookmarked: !p.bookmarked } : p))
    );
    if (selectedPacket && selectedPacket.id === id) {
      setSelectedPacket(prev => (prev ? { ...prev, bookmarked: !prev.bookmarked } : null));
    }
  };

  // Report download files
  const downloadReport = (format: 'CSV' | 'JSON' | 'HTML') => {
    let filename = `packet_report_${Date.now()}`;
    let blob: Blob;

    if (format === 'CSV') {
      const csvStr = exportToCSV(packets);
      blob = new Blob([csvStr], { type: 'text/csv' });
      filename += '.csv';
    } else if (format === 'JSON') {
      const jsonStr = exportToJSON(packets);
      blob = new Blob([jsonStr], { type: 'application/json' });
      filename += '.json';
    } else {
      const htmlStr = generateHTMLReport(packets, alerts, stats);
      blob = new Blob([htmlStr], { type: 'text/html' });
      filename += '.html';
    }

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Upload custom fake/sample pcap simulator
  const handlePcapUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setSelectedFileForUpload(file.name);
      // Populate custom pcap simulation packets
      const mockPcapPackets: Packet[] = [
        {
          id: 501,
          timestamp: new Date().toISOString(),
          protocol: 'TCP',
          srcIp: '10.0.0.8',
          dstIp: '192.168.1.15',
          srcPort: 80,
          dstPort: 49102,
          macSrc: '00:11:22:33:44:55',
          macDst: '00:0a:95:9d:68:16',
          size: 1450,
          ttl: 128,
          checksum: '0x1bc3 (Valid)',
          payloadSize: 1396,
          direction: 'INCOMING',
          summary: 'Simulated PCAP stream payload chunk',
          interface: 'eth0',
          payloadHex: 'a1 b2 c3 d4 e5',
          payloadAscii: '.....'
        },
        {
          id: 502,
          timestamp: new Date().toISOString(),
          protocol: 'UDP',
          srcIp: '192.168.1.15',
          dstIp: '8.8.4.4',
          srcPort: 49102,
          dstPort: 53,
          macSrc: '00:0a:95:9d:68:16',
          macDst: '00:11:22:33:44:55',
          size: 80,
          ttl: 64,
          checksum: '0x028e (Valid)',
          payloadSize: 26,
          direction: 'OUTGOING',
          summary: 'Simulated PCAP DNS resolver query',
          interface: 'eth0'
        }
      ];

      setPackets(prev => {
        const maxCurrentId = prev.reduce((max, p) => p.id > max ? p.id : max, 0);
        const mappedPcapPackets = mockPcapPackets.map((p, idx) => ({
          ...p,
          id: maxCurrentId + idx + 1
        }));
        return [...mappedPcapPackets, ...prev];
      });
      setStats(prev => ({
        ...prev,
        totalPackets: prev.totalPackets + 2,
        networkHealthScore: 100
      }));
    }
  };

  // AI Copilot prompt sender using real network telemetry
  const handleGeminiQuery = async (userPrompt: string): Promise<string> => {
    const protoList = Array.from(new Set(packets.map(p => p.protocol))).join(', ') || 'No traffic captured yet';
    const alertList = alerts.map(a => `${a.type} (${a.source} -> ${a.destination})`).join('; ') || 'No active security incidents detected';
    const topSitesList = topSites.slice(0, 5).map(s => s.host).join(', ') || 'None';

    const contextStr = `
CURRENT LIVE NETWORK TELEMETRY:
- Interface Status: ${stats.interfaceStatus} (${captureInterface})
- Total Packets Captured: ${stats.totalPackets} (Flow rate: ${stats.packetsPerSec} pkts/sec)
- Active 4-Tuple Connections: ${liveConnections.length}
- Observed Protocols: ${protoList}
- Active Security Alerts / Anomalies: ${alertList}
- Top Visited Sites / Domains: ${topSitesList}

RECENT CAPTURED PACKETS (Sample of ${Math.min(packets.length, 8)}):
${packets.slice(0, 8).map(p => `[#${p.id} ${p.timestamp}] ${p.protocol} ${p.srcIp}:${p.srcPort || ''} -> ${p.dstIp}:${p.dstPort || ''} (${p.size} bytes, ${p.direction}) Summary: ${p.summary}`).join('\n') || 'None'}
`.trim();

    const systemRule = `You are Sentinel AI — a friendly, expert network security assistant built into the Sentinel Analytica real-time packet sniffer dashboard.

Your job is to explain real network traffic, packets, threats, and protocols in a way that ANYONE can understand using the actual observed network telemetry provided.

## RULES FOR EVERY RESPONSE:
1. **Plain English first** — Start with a simple, jargon-free explanation. Imagine you're explaining to a curious beginner.
2. **Use Actual Telemetry** — Refer to the real connections, observed protocols, and alert counts from the live network context. DO NOT invent fake packet numbers or imaginary attacks if none exist in the telemetry.
3. **Real-world analogy** — Include a relatable real-world example or analogy.
4. **Actionable advice** — If there is an anomaly or concern, give clear steps to address it.
5. **Next Prompt Suggestions** — At the end of every response, add suggested next questions.

## FORMAT EVERY RESPONSE LIKE THIS:

### 🟢 Simple Explanation
(2-3 sentences in plain English that anyone can understand)

### 🔬 Technical Breakdown
(Deeper technical details using observed protocols, ports, and connection patterns)

### 📦 Real-World Example
(A relatable analogy or scenario from everyday life)

### 🛡️ What Should You Do?
(Clear, actionable recommendations if applicable)

---
💡 **You might also want to ask:**
1. ...
2. ...
3. ...`;

    try {
      const res = await fetch('/api/gemini-ask', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: userPrompt, packetContext: contextStr, systemRule })
      });
      const data = await res.json();
      if (data.error) {
        return `AI assistant error: ${data.error}`;
      }
      return data.text || "No insights could be formulated by the AI model at this moment.";
    } catch (err: any) {
      return `Telemetry audit model analysis error: ${err.message || err}`;
    }
  };

  // Apply filters logic
  const filteredList = filterPackets(packets, filters);

  // Compute stats graphs structures
  const protocolCounts: { [key: string]: number } = {};
  filteredList.forEach(p => {
    protocolCounts[p.protocol] = (protocolCounts[p.protocol] || 0) + p.size;
  });

  const chartData = Object.keys(protocolCounts).map(proto => ({
    name: proto,
    value: protocolCounts[proto]
  }));

  const COLORS = ['#38bdf8', '#818cf8', '#34d399', '#f87171', '#fbbf24', '#a78bfa'];

  // Trend graph data points
  const bandwidthTrend = packets.slice(0, 8).map((p, idx) => ({
    time: new Date(p.timestamp).toLocaleTimeString(),
    Incoming: Math.floor(Math.random() * 3000) + p.size,
    Outgoing: Math.floor(Math.random() * 1500) + (p.protocol === 'TCP' ? 1200 : 300)
  })).reverse();

  return (
    <div className="min-h-screen bg-brand-bg text-brand-text font-sans flex flex-col selection:bg-brand-accent/20 selection:text-white">
      {/* Top Professional Header Navigation */}
      <header className="bg-brand-card/80 border-b border-brand-border sticky top-0 z-40 backdrop-blur-md px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-brand-accent to-brand-accent-blue flex items-center justify-center shadow-[0_0_15px_rgba(0,242,255,0.4)]">
            <Shield className="w-5 h-5 text-white animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-sm font-bold tracking-tight text-white uppercase font-mono">
                Sentinel <span className="text-brand-accent font-light">Analytica</span>
              </h1>
              <span className="text-[9px] bg-brand-panel text-brand-accent font-mono font-bold px-1.5 py-0.5 rounded border border-brand-border-light">
                v2.5 PRO
              </span>
            </div>
            <p className="text-[10px] text-brand-muted font-medium">
              Enterprise Network Monitoring & Cybersecurity Analysis Platform
            </p>
          </div>
        </div>

        {/* Interface Info Panel */}
        <div className="hidden lg:flex items-center gap-6 text-[11px] font-mono border-l border-brand-border pl-6">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]"></div>
            <span className="text-brand-muted">INTERFACE:</span>
            <span className="text-brand-text font-bold bg-brand-panel px-1.5 py-0.5 rounded border border-brand-border-light">
              {captureInterface}
            </span>
          </div>

          {/* Machine identity chip */}
          {localInfo && (
            <div className="flex items-center gap-2">
              <span className="text-brand-muted">HOST:</span>
              <span className="text-cyan-400 font-bold">{localInfo.hostname}</span>
              <span className="text-brand-muted">·</span>
              <span className="text-emerald-400 font-bold">{localInfo.localIp}</span>
            </div>
          )}

          <div className="flex items-center gap-2">
            <span className="text-brand-muted">HEALTH INDEX:</span>
            <span className={`font-bold ${stats.networkHealthScore > 75 ? 'text-emerald-400' : 'text-brand-danger'}`}>
              {stats.networkHealthScore}/100
            </span>
          </div>
        </div>

        {/* Command Launcher Controls */}
        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsDownloadModalOpen(true)}
            className="text-[10px] bg-gradient-to-r from-cyan-500/20 to-brand-accent/20 hover:from-cyan-500/30 hover:to-brand-accent/30 text-cyan-300 border border-cyan-500/40 hover:border-cyan-400 rounded px-3.5 py-2 font-bold uppercase tracking-wider flex items-center gap-2 transition shadow-[0_0_12px_rgba(6,182,212,0.25)] cursor-pointer"
            title="Download Desktop Application or Connect Local Agent to analyze your hardware network cards"
          >
            <Laptop className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            <span>Desktop App & Agent</span>
          </button>

          <button
            onClick={toggleCapture}
            className={`text-[10px] px-4 py-2 rounded font-bold uppercase tracking-widest flex items-center gap-2 border transition duration-200 cursor-pointer ${
              stats.isCapturing
                ? 'bg-brand-danger/10 text-brand-danger border-brand-danger/30 hover:bg-brand-danger/20'
                : 'bg-brand-accent/10 text-brand-accent border-brand-accent/30 hover:bg-brand-accent/20'
            }`}
          >
            {stats.isCapturing ? (
              <>
                <Square className="w-3.5 h-3.5 fill-current" />
                Stop Capture
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                Start Sniffing
              </>
            )}
          </button>

          <button
            onClick={clearLogs}
            className="text-[10px] bg-brand-panel border border-brand-border hover:bg-brand-card text-brand-muted hover:text-brand-text rounded px-3.5 py-2 uppercase tracking-wider font-bold transition cursor-pointer"
            title="Clear current stream buffer"
          >
            Clear Data
          </button>
        </div>
      </header>

      {/* Monitoring Source & Agent Selector Bar */}
      <MonitoringSourceBar
        agents={agents}
        selectedAgentId={selectedAgentId}
        selectedInterfaceId={selectedInterfaceId}
        onSelectAgent={handleSelectAgent}
        onSelectInterface={handleSelectInterface}
        onRefreshInterfaces={handleRefreshInterfaces}
        onStartMonitoring={handleStartMonitoring}
        onStopMonitoring={handleStopMonitoring}
        onOpenAddAgentModal={() => setIsAddAgentModalOpen(true)}
        isCapturing={stats.isCapturing}
        captureMode={captureMode}
        packetsPerSec={stats.packetsPerSec}
        totalPackets={stats.totalPackets}
        totalBytes={totalBytes}
        isRefreshing={isRefreshingAgents}
        isDemoMode={isDemoMode}
        onToggleDemoMode={handleToggleDemoMode}
      />


      {/* Main Body Layout Container with Vertical Left Sidebar */}
      <div className="flex-1 flex overflow-hidden">
        
        {/* Left Vertical Navigation Panel */}
        <aside className="w-64 bg-brand-card/90 border-r border-brand-border flex flex-col shrink-0 py-4 px-3 font-mono text-xs select-none shadow-xl">
          <div className="px-3 py-2 text-[10px] text-brand-muted uppercase font-bold tracking-widest border-b border-brand-border/60 mb-2 flex items-center justify-between">
            <span>PLATFORM MODULES</span>
            <span className="w-2 h-2 rounded-full bg-brand-accent animate-pulse"></span>
          </div>

          <div className="flex-1 space-y-1 overflow-y-auto pr-1">
            {[
              { id: 'DASHBOARD', label: 'Monitor Dashboard', icon: Activity, badge: 'LIVE' },
              { id: 'TRAFFIC',   label: 'Live Traffic Intel', icon: TrendingUp },
              { id: 'PACKETS',   label: 'Packet Inspector',  icon: Search },
              { id: 'SECURITY',  label: 'Threat Analyzer',   icon: Shield, badge: stats.threatCounter > 0 ? `${stats.threatCounter}` : undefined },
              { id: 'PCAP',      label: 'PCAP Deep Analyzer', icon: FileCode, badge: 'PRO' },
              { id: 'SOURCE',    label: 'Enterprise Python Code', icon: Code },
              { id: 'COPILOT',   label: 'AI Copilot Intel',  icon: Terminal },
              { id: 'TOOLS',     label: 'Sniffing Tools',    icon: Wrench },
              { id: 'DOCS',      label: 'Portfolio Guide',   icon: BookOpen }
            ].map(tab => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg font-semibold text-xs transition-all duration-200 cursor-pointer ${
                    isActive
                      ? 'bg-brand-accent/15 text-brand-accent border-l-4 border-brand-accent shadow-[0_0_15px_rgba(0,242,255,0.15)] font-bold'
                      : 'text-brand-muted hover:text-brand-text hover:bg-brand-panel/60 border-l-4 border-transparent'
                  }`}
                >
                  <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-brand-accent animate-pulse' : 'text-brand-muted'}`} />
                  <span className="truncate">{tab.label}</span>
                  {tab.badge && (
                    <span className={`ml-auto text-[9px] px-1.5 py-0.5 rounded font-bold border shrink-0 ${
                      tab.id === 'SECURITY' && stats.threatCounter > 0
                        ? 'bg-rose-500/20 text-rose-400 border-rose-500/40 animate-bounce'
                        : 'bg-brand-panel text-brand-accent border-brand-border'
                    }`}>
                      {tab.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          {/* Quick Export Audit Section in Sidebar Footer */}
          <div className="pt-3 border-t border-brand-border/60 space-y-2 mt-2 shrink-0">
            <span className="px-3 text-[10px] text-brand-muted uppercase font-bold tracking-wider block">Export Audit Logs</span>
            <div className="grid grid-cols-3 gap-1 px-1">
              {['CSV', 'JSON', 'HTML'].map(fmt => (
                <button
                  key={fmt}
                  onClick={() => downloadReport(fmt as any)}
                  className="px-2 py-1.5 bg-brand-panel hover:bg-brand-card text-brand-muted hover:text-brand-accent font-mono text-[10px] rounded border border-brand-border hover:border-brand-border-light text-center transition cursor-pointer font-bold"
                >
                  {fmt}
                </button>
              ))}
            </div>
          </div>
        </aside>

        {/* Right Main Content Area */}
        <main className="flex-1 overflow-y-auto p-6 space-y-6">
          
          {/* Always-on live capture banner */}
          <div className="bg-brand-panel border border-brand-border rounded px-5 py-3 flex items-center justify-between text-xs">
            <div className="flex items-center gap-2 text-brand-accent">
              <span className="w-2 h-2 rounded-full bg-brand-accent animate-ping"></span>
              <span className="font-bold tracking-wide font-mono uppercase">LIVE CAPTURE ENGINE ACTIVE</span>
            </div>
            <div className="flex items-center gap-4 font-mono text-brand-muted">
              {localInfo && <span className="text-cyan-400 font-bold">{localInfo.hostname} ({localInfo.localIp})</span>}
              <span>{stats.totalPackets.toLocaleString()} packets</span>
              <span className="text-emerald-400">↑ {(stats.incomingBytes / 1024).toFixed(1)} KB in</span>
              <span className="text-amber-400">↓ {(stats.outgoingBytes / 1024).toFixed(1)} KB out</span>
              <span className="text-purple-400">{stats.packetsPerSec} p/s</span>
            </div>
          </div>




        {/* Tab 1: Monitor Dashboard */}
        {activeTab === 'DASHBOARD' && (
          <div className="space-y-6">
            
            {/* Live Stats Counters Grid */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">


              {[
                { title: 'Total Ingested', value: stats.totalPackets.toLocaleString(), color: 'text-white', icon: Network, label: 'TOTAL CAPTURED' },
                { title: 'Throughput', value: `${stats.packetsPerSec} P/s`, color: 'text-brand-accent', icon: Activity, label: 'FLOW RATE' },
                { title: 'Data Exchanged', value: `${stats.incomingBytes + stats.outgoingBytes} B`, color: 'text-brand-accent-blue', icon: HardDrive, label: 'SESSION DATA' },
                { title: 'Active Anomalies', value: stats.threatCounter.toString().padStart(2, '0'), color: 'text-brand-danger', icon: AlertTriangle, label: 'ACTIVE THREATS' }
              ].map((card, idx) => {
                const Icon = card.icon;
                return (
                  <div key={idx} className="bg-brand-card border border-brand-border rounded p-4 flex flex-col justify-between relative overflow-hidden">
                    <div className="absolute top-0 right-0 w-16 h-16 bg-brand-accent/5 rounded-bl-full"></div>
                    <div className="flex justify-between items-center mb-2">
                      <span className="text-[10px] text-brand-muted uppercase font-bold tracking-wider">{card.label}</span>
                      <Icon className="w-3.5 h-3.5 text-brand-dim" />
                    </div>
                    <div className={`text-2xl font-bold font-mono ${card.color}`}>
                      {card.value}
                    </div>
                    <div className="text-[11px] text-brand-muted mt-1">{card.title}</div>
                  </div>
                );
              })}
            </div>

            {/* Visual Charts Row */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              
              {/* Dynamic Line Graph for traffic rates */}
              <div className="bg-brand-card border border-brand-border rounded p-4 lg:col-span-2 space-y-3">
                <div className="flex items-center justify-between border-b border-brand-border pb-3">
                  <h3 className="text-xs font-bold text-brand-muted uppercase tracking-wider flex items-center gap-2">
                    <TrendingUp className="w-4 h-4 text-brand-accent" />
                    Ingress &amp; Egress Bandwidth Trend
                  </h3>
                  <span className="text-[10px] text-brand-dim font-mono">Live telemetry</span>
                </div>

                <div className="h-64 w-full">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={bandwidthTrend}>
                      <defs>
                        <linearGradient id="colorInc" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#00f2ff" stopOpacity={0.4}/>
                          <stop offset="95%" stopColor="#00f2ff" stopOpacity={0}/>
                        </linearGradient>
                        <linearGradient id="colorOut" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#0066ff" stopOpacity={0.4}/>
                          <stop offset="95%" stopColor="#0066ff" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e1e24" />
                      <XAxis dataKey="time" stroke="#4a4a5e" fontSize={10} />
                      <YAxis stroke="#4a4a5e" fontSize={10} />
                      <Tooltip contentStyle={{ backgroundColor: '#0a0a0e', borderColor: '#1e1e24', color: '#e0e0e0', fontSize: 11 }} />
                      <Legend wrapperStyle={{ fontSize: 11 }} />
                      <Area type="monotone" dataKey="Incoming" stroke="#00f2ff" fillOpacity={1} fill="url(#colorInc)" />
                      <Area type="monotone" dataKey="Outgoing" stroke="#0066ff" fillOpacity={1} fill="url(#colorOut)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Protocol share breakdown chart */}
              <div className="bg-brand-card border border-brand-border rounded p-4 space-y-3">
                <div className="flex items-center justify-between border-b border-brand-border pb-3">
                  <h3 className="text-xs font-bold text-brand-muted uppercase tracking-wider flex items-center gap-2">
                    <Tag className="w-4 h-4 text-brand-accent" />
                    Protocol Distribution
                  </h3>
                </div>

                <div className="h-64 w-full flex items-center justify-center relative">
                  {chartData.length === 0 ? (
                    <span className="text-xs text-brand-muted font-mono">No telemetry data inside buffer.</span>
                  ) : (
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={chartData}
                          cx="50%"
                          cy="50%"
                          innerRadius={60}
                          outerRadius={85}
                          paddingAngle={3}
                          dataKey="value"
                        >
                          {chartData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={{ backgroundColor: '#0a0a0e', borderColor: '#1e1e24', color: '#e0e0e0', fontSize: 11 }} />
                      </PieChart>
                    </ResponsiveContainer>
                  )}
                  {/* Legend Overlay */}
                  <div className="absolute inset-0 flex flex-col justify-center items-center pointer-events-none">
                    <span className="text-[10px] text-brand-dim font-bold uppercase tracking-wider">TOP PROTOCOL</span>
                    <span className="text-sm font-extrabold text-brand-accent font-mono">{stats.topProtocol}</span>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-2 text-center text-[10px] font-mono">
                  {chartData.slice(0, 3).map((d, i) => (
                    <div key={i} className="bg-brand-panel p-1.5 rounded border border-brand-border-light">
                      <div className="text-brand-muted truncate">{d.name}</div>
                      <div className="font-bold text-brand-accent mt-0.5">{d.value} B</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Fast overview stream */}
            <div className="bg-brand-card border border-brand-border rounded p-4 space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-brand-muted uppercase tracking-wider font-mono">
                  Live Traffic Feed
                </span>
                <button
                  onClick={() => setActiveTab('PACKETS')}
                  className="text-xs text-brand-accent hover:underline cursor-pointer"
                >
                  View full inspector &rarr;
                </button>
              </div>

              <div className="overflow-x-auto border border-brand-border rounded">
                <table className="w-full text-left border-collapse font-mono text-[11px]">
                  <thead>
                    <tr className="bg-brand-panel border-b border-brand-border text-brand-muted">
                      <th className="p-3">ID</th>
                      <th className="p-3">TIMESTAMP</th>
                      <th className="p-3">PROTOCOL</th>
                      <th className="p-3">SOURCE IP</th>
                      <th className="p-3">DESTINATION IP</th>
                      <th className="p-3">SIZE</th>
                      <th className="p-3">SUMMARY</th>
                    </tr>
                  </thead>
                  <tbody>
                    {packets.slice(0, 5).map(p => (
                      <tr
                        key={p.id}
                        onContextMenu={(e) => {
                          e.preventDefault();
                          setContextMenu({ x: e.clientX, y: e.clientY, packet: p });
                        }}
                        className={`border-b border-brand-border/40 hover:bg-brand-accent/5 transition duration-150 cursor-pointer ${
                          p.blocked
                            ? 'bg-brand-danger/5 text-brand-danger'
                            : 'text-brand-text'
                        }`}
                      >
                        <td className="p-3 font-bold flex items-center gap-1.5 text-brand-dim">
                          {p.blocked && <AlertCircle className="w-3 h-3 text-brand-danger shrink-0 animate-pulse" />}
                          #{p.id}
                        </td>
                        <td className="p-3 text-brand-muted">{new Date(p.timestamp).toLocaleTimeString()}</td>
                        <td className="p-3">
                          <span className="px-1.5 py-0.5 bg-brand-accent-blue/10 text-brand-accent rounded border border-brand-accent/20 text-[10px] font-bold">
                            {p.protocol}
                          </span>
                        </td>
                        <td className="p-3 text-brand-text">{p.srcIp}</td>
                        <td className="p-3 text-brand-text">{p.dstIp}</td>
                        <td className="p-3 text-brand-muted">{p.size} B</td>
                        <td className="p-3 text-brand-muted truncate max-w-[200px]" title={p.summary}>{p.summary}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ═══ TRAFFIC TAB: Live Traffic Intelligence ═══ */}
        {activeTab === 'TRAFFIC' && (
          <div className="space-y-6">

            {/* Summary strip */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              {[
                { label: 'Live Connections', value: liveConnections.length, color: 'text-cyan-400' },
                { label: 'DNS Queries Seen', value: dnsEntries.length, color: 'text-emerald-400' },
                { label: 'Sites Visited', value: topSites.length, color: 'text-purple-400' },
                { label: 'Total Bytes', value: `${(totalBytes / 1024).toFixed(1)} KB`, color: 'text-amber-400' },
              ].map(s => (
                <div key={s.label} className="bg-brand-card border border-brand-border rounded p-4">
                  <p className="text-[10px] text-brand-muted font-mono uppercase tracking-wider mb-1">{s.label}</p>
                  <p className={`text-2xl font-bold font-mono ${s.color}`}>{s.value}</p>
                </div>
              ))}
            </div>

            {/* Live Connections Table */}
            <div className="bg-brand-card border border-brand-border rounded p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
                  <span className="text-xs font-bold text-brand-muted uppercase tracking-wider font-mono">Live Connections</span>
                  <span className="text-[10px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 px-2 py-0.5 rounded font-mono">{liveConnections.length} active</span>
                </div>
                <span className="text-[10px] text-brand-muted font-mono">Grouped by 4-tuple · sorted by last activity</span>
              </div>
              <div className="overflow-x-auto border border-brand-border rounded max-h-72 overflow-y-auto">
                <table className="w-full text-left border-collapse font-mono text-[11px]">
                  <thead className="sticky top-0">
                    <tr className="bg-brand-panel border-b border-brand-border text-brand-muted">
                      <th className="p-2 px-3">HOSTNAME / DEST IP</th>
                      <th className="p-2 px-3">PROTOCOL</th>
                      <th className="p-2 px-3">SRC → DST PORT</th>
                      <th className="p-2 px-3">DIR</th>
                      <th className="p-2 px-3">BYTES</th>
                      <th className="p-2 px-3">PKTS</th>
                      <th className="p-2 px-3">LAST SEEN</th>
                    </tr>
                  </thead>
                  <tbody>
                    {liveConnections.length === 0 ? (
                      <tr><td colSpan={7} className="p-4 text-center text-brand-muted">Waiting for traffic... (connections appear after first packets)</td></tr>
                    ) : liveConnections.slice(0, 80).map((c, i) => (
                      <tr key={c.key || i} className="border-b border-brand-border hover:bg-brand-panel/40 transition">
                        <td className="p-2 px-3">
                          <div className="text-cyan-300 font-bold truncate max-w-[200px]">{c.hostname || c.dstIp}</div>
                          {c.tlsSni && <div className="text-[9px] text-purple-400">SNI: {c.tlsSni}</div>}
                          {c.httpHost && !c.tlsSni && <div className="text-[9px] text-amber-400">HTTP: {c.httpHost}</div>}
                        </td>
                        <td className="p-2 px-3">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            c.protocol === 'HTTPS' ? 'bg-emerald-500/20 text-emerald-400' :
                            c.protocol === 'DNS'   ? 'bg-blue-500/20 text-blue-400' :
                            c.protocol === 'HTTP'  ? 'bg-amber-500/20 text-amber-400' :
                            c.protocol === 'TCP'   ? 'bg-cyan-500/20 text-cyan-400' :
                            'bg-brand-panel text-brand-muted'
                          }`}>{c.protocol}</span>
                        </td>
                        <td className="p-2 px-3 text-brand-muted">{c.srcPort} → {c.dstPort}</td>
                        <td className="p-2 px-3">
                          <span className={`text-[10px] font-bold ${c.direction === 'OUTGOING' ? 'text-amber-400' : c.direction === 'INCOMING' ? 'text-emerald-400' : 'text-brand-muted'}`}>
                            {c.direction === 'OUTGOING' ? '↑ OUT' : c.direction === 'INCOMING' ? '↓ IN' : '⟲ LOOP'}
                          </span>
                        </td>
                        <td className="p-2 px-3 text-brand-text">{c.bytes > 1024 ? `${(c.bytes/1024).toFixed(1)}K` : c.bytes}</td>
                        <td className="p-2 px-3 text-brand-muted">{c.packets}</td>
                        <td className="p-2 px-3 text-brand-dim">{new Date(c.lastSeen).toLocaleTimeString()}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* DNS + Top Sites side-by-side */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

              {/* DNS Query Log */}
              <div className="bg-brand-card border border-brand-border rounded p-4 space-y-3">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-blue-400 animate-pulse"></span>
                  <span className="text-xs font-bold text-brand-muted uppercase tracking-wider font-mono">DNS Query Log</span>
                  <span className="text-[10px] bg-blue-500/10 text-blue-400 border border-blue-500/20 px-2 py-0.5 rounded font-mono">{dnsEntries.length} domains</span>
                </div>
                <div className="space-y-1 max-h-80 overflow-y-auto pr-1">
                  {dnsEntries.length === 0 ? (
                    <div className="text-[11px] text-brand-muted font-mono p-4 text-center">No DNS queries captured yet — browse a website to see queries appear</div>
                  ) : dnsEntries.map((d, i) => (
                    <div key={i} className="flex items-start justify-between py-1.5 border-b border-brand-border/40 last:border-0">
                      <div className="flex-1 min-w-0">
                        <div className="text-[11px] font-mono text-cyan-300 truncate font-bold">{d.name}</div>
                        {d.ip && <div className="text-[10px] text-emerald-400 font-mono">→ {d.ip}</div>}
                      </div>
                      <div className="flex items-center gap-3 shrink-0 ml-2">
                        <span className="text-[10px] text-brand-muted font-mono">{d.count}x</span>
                        <span className="text-[9px] text-brand-dim">{new Date(d.lastSeen).toLocaleTimeString()}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Top Sites Visited */}
              <div className="bg-brand-card border border-brand-border rounded p-4 space-y-3">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-purple-400 animate-pulse"></span>
                  <span className="text-xs font-bold text-brand-muted uppercase tracking-wider font-mono">Top Sites Visited</span>
                  <span className="text-[10px] bg-purple-500/10 text-purple-400 border border-purple-500/20 px-2 py-0.5 rounded font-mono">TLS SNI + HTTP</span>
                </div>
                <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
                  {topSites.length === 0 ? (
                    <div className="text-[11px] text-brand-muted font-mono p-4 text-center">Sites appear here as you browse — derived from TLS SNI handshakes</div>
                  ) : topSites.map((s, i) => {
                    const maxBytes = topSites[0]?.bytes || 1;
                    const pct = Math.round((s.bytes / maxBytes) * 100);
                    return (
                      <div key={i} className="space-y-1">
                        <div className="flex items-center justify-between text-[11px] font-mono">
                          <div className="flex items-center gap-2">
                            <span className="text-brand-muted text-[10px]">#{i+1}</span>
                            <span className="text-purple-300 font-bold truncate max-w-[180px]">{s.host}</span>
                          </div>
                          <div className="flex items-center gap-3 shrink-0">
                            <span className="text-brand-text">{s.bytes > 1024 ? `${(s.bytes/1024).toFixed(1)}K` : s.bytes} B</span>
                            <span className="text-brand-muted">{s.packets} pkts</span>
                          </div>
                        </div>
                        <div className="h-1 bg-brand-panel rounded-full overflow-hidden">
                          <div className="h-full bg-gradient-to-r from-purple-500 to-cyan-500 rounded-full transition-all duration-500" style={{ width: `${pct}%` }} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

          </div>
        )}

        {/* Tab 2: Packet Inspector split layout */}
        {activeTab === 'PACKETS' && (
          <div className="space-y-4">
            
            {/* Dedicated Live Stream vs. Demo Dataset Mode Switcher */}
            <div className="bg-brand-card border border-brand-border rounded p-3.5 flex flex-wrap items-center justify-between gap-4 shadow-lg">
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded border ${isDemoMode ? 'bg-amber-500/10 border-amber-500/30 text-amber-400' : 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'}`}>
                  <Search className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-xs font-bold text-white uppercase tracking-wider">PACKET INSPECTION ENGINE</h2>
                    <span className={`text-[10px] px-2.5 py-0.5 rounded font-bold uppercase tracking-wider flex items-center gap-1.5 ${
                      isDemoMode
                        ? 'bg-amber-950/80 text-amber-300 border border-amber-500/50'
                        : 'bg-emerald-950/80 text-emerald-400 border border-emerald-500/50'
                    }`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${isDemoMode ? 'bg-amber-400' : 'bg-emerald-400 animate-pulse'}`}></span>
                      {isDemoMode ? 'DEMO DATASET MODE' : 'LIVE NETWORK STREAM'}
                    </span>
                  </div>
                  <p className="text-[11px] text-brand-muted mt-0.5 font-mono">
                    {isDemoMode
                      ? '⚡ Inspecting offline scenario packets (SQL Injection, TLS Handshakes, DNS C2, Port Scans) for learning & testing.'
                      : '🔴 Inspecting real-time network packets captured live from your authorized network interfaces.'}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2 bg-brand-panel p-1 rounded-lg border border-brand-border">
                <button
                  onClick={() => isDemoMode && handleToggleDemoMode()}
                  className={`text-xs px-3.5 py-1.5 rounded font-bold uppercase tracking-wider flex items-center gap-1.5 transition cursor-pointer ${
                    !isDemoMode
                      ? 'bg-emerald-600 text-white shadow-md'
                      : 'text-brand-muted hover:text-white'
                  }`}
                  title="Switch to capturing authentic live network packets"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-white animate-ping"></span>
                  Live Stream
                </button>
                <button
                  onClick={() => !isDemoMode && handleToggleDemoMode()}
                  className={`text-xs px-3.5 py-1.5 rounded font-bold uppercase tracking-wider flex items-center gap-1.5 transition cursor-pointer ${
                    isDemoMode
                      ? 'bg-amber-600 text-white shadow-md'
                      : 'text-brand-muted hover:text-white'
                  }`}
                  title="Switch to inspecting rich offline demo scenarios"
                >
                  <AlertTriangle className="w-3.5 h-3.5" />
                  Demo Dataset
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
            
            {/* Filter sidebar & table column */}
            <div className="xl:col-span-8 space-y-4">
              
              {/* Dynamic Filter options toggler */}
              <div className="bg-brand-card border border-brand-border rounded p-4 flex flex-wrap items-center gap-4 justify-between">
                <div className="flex items-center gap-3 flex-1 min-w-[250px]">
                  <Search className="w-4 h-4 text-brand-dim shrink-0" />
                  <input
                    type="text"
                    value={filters.searchQuery}
                    onChange={(e) => setFilters(prev => ({ ...prev, searchQuery: e.target.value }))}
                    placeholder="Fast search IP, Port, protocol, Summary keyword..."
                    className="w-full text-xs bg-transparent text-brand-text outline-none placeholder:text-brand-dim"
                  />
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setShowFiltersModal(!showFiltersModal)}
                    className="text-xs bg-brand-panel hover:bg-brand-card text-brand-text rounded border border-brand-border hover:border-brand-border-light px-3 py-1.5 flex items-center gap-2 transition cursor-pointer"
                  >
                    <Filter className="w-3.5 h-3.5 text-brand-accent" />
                    Filters {showFiltersModal ? 'Open' : 'Configure'}
                  </button>

                  <button
                    onClick={() => setFilters({
                      protocol: 'ALL',
                      ip: '',
                      port: '',
                      mac: '',
                      sizeMin: '',
                      sizeMax: '',
                      country: 'ALL',
                      tcpFlag: 'ALL',
                      direction: 'ALL',
                      searchQuery: ''
                    })}
                    className="text-xs bg-brand-panel hover:bg-brand-card text-brand-muted rounded border border-brand-border px-3 py-1.5 transition cursor-pointer"
                  >
                    Reset
                  </button>
                </div>
              </div>

              {/* Filters expanded board */}
              {showFiltersModal && (
                <div className="bg-brand-card border border-brand-border rounded p-5 grid grid-cols-1 md:grid-cols-3 gap-4 animate-fadeIn">
                  <div>
                    <label className="block text-xs text-brand-muted mb-1 font-mono">PROTOCOL:</label>
                    <select
                      value={filters.protocol}
                      onChange={(e) => setFilters(prev => ({ ...prev, protocol: e.target.value }))}
                      className="w-full text-xs bg-brand-panel border border-brand-border text-brand-text rounded p-2 focus:border-brand-accent outline-none"
                    >
                      <option value="ALL">All Protocols</option>
                      <option value="TCP">TCP Only</option>
                      <option value="UDP">UDP Only</option>
                      <option value="HTTP">HTTP Only</option>
                      <option value="HTTPS">HTTPS Only</option>
                      <option value="ICMP">ICMP Only</option>
                      <option value="ARP">ARP Only</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs text-brand-muted mb-1 font-mono">IP ADDRESS (SRC/DST):</label>
                    <input
                      type="text"
                      value={filters.ip}
                      onChange={(e) => setFilters(prev => ({ ...prev, ip: e.target.value }))}
                      placeholder="e.g. 192.168.1.15"
                      className="w-full text-xs bg-brand-panel border border-brand-border text-brand-text rounded p-2 focus:border-brand-accent outline-none"
                    />
                  </div>

                  <div>
                    <label className="block text-xs text-brand-muted mb-1 font-mono">PORT (SRC/DST):</label>
                    <input
                      type="text"
                      value={filters.port}
                      onChange={(e) => setFilters(prev => ({ ...prev, port: e.target.value }))}
                      placeholder="e.g. 443"
                      className="w-full text-xs bg-brand-panel border border-brand-border text-brand-text rounded p-2 focus:border-brand-accent outline-none"
                    />
                  </div>

                  <div>
                    <label className="block text-xs text-brand-muted mb-1 font-mono">DIRECTION:</label>
                    <select
                      value={filters.direction}
                      onChange={(e) => setFilters(prev => ({ ...prev, direction: e.target.value }))}
                      className="w-full text-xs bg-brand-panel border border-brand-border text-brand-text rounded p-2 focus:border-brand-accent outline-none"
                    >
                      <option value="ALL">All Directions</option>
                      <option value="INCOMING">Incoming</option>
                      <option value="OUTGOING">Outgoing</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-xs text-brand-muted mb-1 font-mono">MIN SIZE (BYTES):</label>
                    <input
                      type="number"
                      value={filters.sizeMin}
                      onChange={(e) => setFilters(prev => ({ ...prev, sizeMin: e.target.value }))}
                      placeholder="e.g. 64"
                      className="w-full text-xs bg-brand-panel border border-brand-border text-brand-text rounded p-2 focus:border-brand-accent outline-none"
                    />
                  </div>

                  <div>
                    <label className="block text-xs text-brand-muted mb-1 font-mono">MAX SIZE (BYTES):</label>
                    <input
                      type="number"
                      value={filters.sizeMax}
                      onChange={(e) => setFilters(prev => ({ ...prev, sizeMax: e.target.value }))}
                      placeholder="e.g. 1500"
                      className="w-full text-xs bg-brand-panel border border-brand-border text-brand-text rounded p-2 focus:border-brand-accent outline-none"
                    />
                  </div>
                </div>
              )}

              {/* Packets Grid Table */}
              <div className="bg-brand-card border border-brand-border rounded overflow-hidden">
                <div className="overflow-x-auto max-h-[500px] overflow-y-auto">
                  <table className="w-full text-left border-collapse font-mono text-xs">
                    <thead>
                      <tr className="bg-brand-panel border-b border-brand-border text-brand-muted sticky top-0 z-10">
                        <th className="p-3">ID</th>
                        <th className="p-3">PROTOCOL</th>
                        <th className="p-3">SOURCE IP</th>
                        <th className="p-3">DESTINATION IP</th>
                        <th className="p-3">SIZE</th>
                        <th className="p-3">ACTIONS</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredList.map(p => (
                        <tr
                          key={p.id}
                          onClick={() => setSelectedPacket(p)}
                          onContextMenu={(e) => {
                            e.preventDefault();
                            setContextMenu({ x: e.clientX, y: e.clientY, packet: p });
                          }}
                          className={`cursor-pointer border-b border-brand-border/40 transition duration-150 ${
                            p.blocked
                              ? 'bg-brand-danger/10 border-brand-danger/20 text-brand-danger font-semibold'
                              : selectedPacket && selectedPacket.id === p.id
                              ? 'bg-brand-accent/5 border-brand-accent/20 text-brand-accent font-semibold'
                              : 'hover:bg-brand-accent/5 text-brand-text'
                          }`}
                        >
                          <td className="p-3 font-bold flex items-center gap-1.5 text-brand-dim">
                            {p.blocked && <AlertCircle className="w-3.5 h-3.5 text-brand-danger shrink-0 animate-pulse" />}
                            #{p.id}
                          </td>
                          <td className="p-3">
                            <span className={`px-2 py-0.5 rounded font-bold text-[10px] border ${
                              p.protocol === 'TCP' ? 'bg-brand-accent-blue/10 text-brand-accent border-brand-accent/20' :
                              p.protocol === 'UDP' ? 'bg-brand-panel text-brand-muted border-brand-border-light' :
                              p.protocol === 'ICMP' ? 'bg-brand-danger/10 text-brand-danger border-brand-danger/20' :
                              'bg-brand-panel text-brand-dim border-brand-border'
                            }`}>
                              {p.protocol}
                            </span>
                          </td>
                          <td className="p-3">{p.srcIp}{p.srcPort ? `:${p.srcPort}` : ''}</td>
                          <td className="p-3">{p.dstIp}{p.dstPort ? `:${p.dstPort}` : ''}</td>
                          <td className="p-3 text-brand-muted">{p.size} B</td>
                          <td className="p-3" onClick={(e) => e.stopPropagation()}>
                            <button
                              onClick={() => toggleBookmark(p.id)}
                              className="text-brand-dim hover:text-brand-accent transition cursor-pointer"
                              title="Toggle Bookmark"
                            >
                              <Bookmark className={`w-4 h-4 ${p.bookmarked ? 'fill-brand-accent text-brand-accent' : ''}`} />
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            {/* Packet Details Inspector column */}
            <div className="xl:col-span-4 space-y-4">
              <div className="bg-brand-card border border-brand-border rounded p-4 space-y-4 h-[580px] overflow-y-auto">
                <div className="border-b border-brand-border pb-3 flex items-center justify-between">
                  <h3 className="text-xs font-bold text-brand-muted uppercase tracking-wider flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-brand-accent" />
                    Deep Packet Inspector
                  </h3>
                  <span className={`text-[9px] px-2 py-0.5 rounded font-bold uppercase tracking-wider ${
                    isDemoMode
                      ? 'bg-amber-950/70 text-amber-300 border border-amber-500/40'
                      : 'bg-emerald-950/70 text-emerald-400 border border-emerald-500/40'
                  }`}>
                    {isDemoMode ? 'DEMO' : 'LIVE'}
                  </span>
                </div>

                {selectedPacket ? (
                  <div className="space-y-4 font-mono text-xs">
                    
                    {/* Raw Summary */}
                    <div className="bg-brand-panel border border-brand-border rounded p-3">
                      <span className="text-[10px] text-brand-dim font-bold block mb-1">PACKET SUMMARY</span>
                      <span className="text-brand-text">{selectedPacket.summary}</span>
                    </div>

                    {/* Meta Fields Grid */}
                    <div className="grid grid-cols-2 gap-3 text-[11px] bg-brand-panel/30 border border-brand-border/50 rounded p-3">
                      <div>
                        <span className="text-brand-dim block">MAC Source:</span>
                        <span className="text-brand-muted">{selectedPacket.macSrc}</span>
                      </div>
                      <div>
                        <span className="text-brand-dim block">MAC Destination:</span>
                        <span className="text-brand-muted">{selectedPacket.macDst}</span>
                      </div>
                      <div>
                        <span className="text-brand-dim block">Packet Size:</span>
                        <span className="text-brand-muted">{selectedPacket.size} Bytes</span>
                      </div>
                      <div>
                        <span className="text-brand-dim block">TTL / Hop Limit:</span>
                        <span className="text-brand-muted">{selectedPacket.ttl || 64}</span>
                      </div>
                    </div>

                    {/* Flags / Hex decoders */}
                    <div className="space-y-2">
                      <span className="text-[10px] text-brand-dim font-bold block">HEX DUMP REPRESENTATION</span>
                      <div className="bg-brand-panel border border-brand-border rounded p-2 text-[10px] text-brand-text font-mono h-24 overflow-y-auto leading-relaxed whitespace-pre-wrap">
                        {selectedPacket.payloadHex || "No data payload attached to packet structure."}
                      </div>
                    </div>

                    <div className="space-y-2">
                      <span className="text-[10px] text-brand-dim font-bold block">ASCII DECODED FIELD</span>
                      <div className="bg-brand-panel border border-brand-border rounded p-2 text-[10px] text-brand-text font-mono h-24 overflow-y-auto leading-relaxed whitespace-pre-wrap">
                        {selectedPacket.payloadAscii || "No readable data payload attached to packet."}
                      </div>
                    </div>

                    {/* Geolocation ASN representation */}
                    {selectedPacket.country && (
                      <div className="bg-brand-panel/40 border border-brand-border/40 rounded p-3 text-[11px]">
                        <span className="font-bold text-brand-accent">IP Intelligence Details</span>
                        <div className="mt-1 text-brand-muted">
                          Country: {selectedPacket.country} | ASN Code: {selectedPacket.asn || 'Private/Local'}
                        </div>
                      </div>
                    )}

                  </div>
                ) : (
                  <div className="h-full flex flex-col items-center justify-center text-center text-brand-muted text-xs">
                    <AlertCircle className="w-8 h-8 text-brand-dim mb-2" />
                    <span>Select a packet from the buffer table list to run OSI layer deep-inspection.</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

        {/* Tab 3: Security analysis simulator */}
        {activeTab === 'SECURITY' && (
          <SecurityPanel
            alerts={alerts}
            packets={packets}
            onAddPacket={handleAddPacket}
            onAddAlert={handleAddAlert}
            onSwitchTab={setActiveTab}
          />
        )}

        {/* Tab PCAP: Dedicated PCAP Deep Analyzer */}
        {activeTab === 'PCAP' && (
          <PcapAnalyzerPanel />
        )}

        {/* Tab 4: Desktop Python source code views */}
        {activeTab === 'SOURCE' && (
          <DesktopCodePanel />
        )}


        {/* Tab 5: AI Copilot analysis */}
        {activeTab === 'COPILOT' && (
          <AICopilotPanel onSendMessage={handleGeminiQuery} />
        )}

        {/* Tab 6: Portfolio and Docs panels */}
        {activeTab === 'DOCS' && (
          <DocsPanel />
        )}

        {/* Tab 7: Network Sniffing Tools reference */}
        {activeTab === 'TOOLS' && (
          <ToolsPanel />
        )}

      </main>
      </div>

      {/* Persistent platform status footer */}

      <footer className="bg-brand-card border-t border-brand-border px-6 py-4 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs font-mono shrink-0">
        <div className="flex items-center gap-2 text-brand-muted">
          <Cpu className="w-3.5 h-3.5 text-brand-accent" />
          SYSTEM: CPU {stats.cpuUsage}% | MEM {stats.memoryUsage}% | DISK {stats.diskUsage}%
        </div>
        <div className="text-brand-dim">
           Sentinel Analytica Network Sniffer Core • Developed under IEEE Clean-Architecture Framework
        </div>
      </footer>

      {/* Right-Click Context Menu Overlay */}
      {contextMenu && (
        <div
          id="packet-context-menu"
          className="fixed z-50 bg-brand-card border border-brand-border rounded shadow-2xl py-1 font-mono text-xs w-56 divide-y divide-brand-border/40"
          style={{ top: contextMenu.y, left: contextMenu.x }}
          onClick={(e) => e.stopPropagation()}
        >
          {/* Quick Stats Header */}
          <div className="px-3 py-2 text-[10px] text-brand-muted bg-brand-panel font-bold flex items-center justify-between">
            <span>PACKET ACTIONS #{contextMenu.packet.id}</span>
            <span className="text-brand-accent">{contextMenu.packet.protocol}</span>
          </div>

          {/* Firewall Rules Block/Unblock */}
          <div className="py-1">
            {blockedIpsList.includes(contextMenu.packet.srcIp) ? (
              <button
                onClick={() => {
                  handleFirewallUnblock(contextMenu.packet.srcIp);
                  setContextMenu(null);
                }}
                className="w-full text-left px-3 py-2 text-brand-accent hover:bg-brand-panel transition flex items-center gap-2 cursor-pointer"
              >
                <Shield className="w-3.5 h-3.5 text-brand-accent" />
                Unblock Src IP Firewall
              </button>
            ) : (
              <button
                onClick={() => {
                  handleFirewallBlock(contextMenu.packet.srcIp);
                  setContextMenu(null);
                }}
                className="w-full text-left px-3 py-2 text-brand-danger hover:bg-brand-panel transition flex items-center gap-2 cursor-pointer"
              >
                <Shield className="w-3.5 h-3.5 text-brand-danger" />
                Block Src IP in Firewall
              </button>
            )}

            {blockedIpsList.includes(contextMenu.packet.dstIp) ? (
              <button
                onClick={() => {
                  handleFirewallUnblock(contextMenu.packet.dstIp);
                  setContextMenu(null);
                }}
                className="w-full text-left px-3 py-2 text-brand-accent hover:bg-brand-panel transition flex items-center gap-2 cursor-pointer"
              >
                <Shield className="w-3.5 h-3.5 text-brand-accent" />
                Unblock Dst IP Firewall
              </button>
            ) : (
              <button
                onClick={() => {
                  handleFirewallBlock(contextMenu.packet.dstIp);
                  setContextMenu(null);
                }}
                className="w-full text-left px-3 py-2 text-brand-danger hover:bg-brand-panel transition flex items-center gap-2 cursor-pointer"
              >
                <Shield className="w-3.5 h-3.5 text-brand-danger" />
                Block Dst IP in Firewall
              </button>
            )}
          </div>

          {/* Whois Lookup Option */}
          <div className="py-1">
            <button
              onClick={() => {
                handleWhoisLookup(contextMenu.packet.srcIp);
                setContextMenu(null);
              }}
              className="w-full text-left px-3 py-2 text-brand-text hover:bg-brand-panel transition flex items-center gap-2 cursor-pointer"
            >
              <Search className="w-3.5 h-3.5 text-brand-accent" />
              Whois Lookup: Src IP
            </button>
            <button
              onClick={() => {
                handleWhoisLookup(contextMenu.packet.dstIp);
                setContextMenu(null);
              }}
              className="w-full text-left px-3 py-2 text-brand-text hover:bg-brand-panel transition flex items-center gap-2 cursor-pointer"
            >
              <Search className="w-3.5 h-3.5 text-brand-accent" />
              Whois Lookup: Dst IP
            </button>
          </div>

          {/* Extract / Download payload options */}
          <div className="py-1">
            <button
              onClick={() => {
                downloadPayload(contextMenu.packet.id, 'hex');
                setContextMenu(null);
              }}
              className="w-full text-left px-3 py-1.5 text-brand-text hover:bg-brand-panel transition flex items-center gap-2 cursor-pointer text-[11px]"
            >
              <Download className="w-3.5 h-3.5 text-brand-muted" />
              Extract Payload to Hex
            </button>
            <button
              onClick={() => {
                downloadPayload(contextMenu.packet.id, 'ascii');
                setContextMenu(null);
              }}
              className="w-full text-left px-3 py-1.5 text-brand-text hover:bg-brand-panel transition flex items-center gap-2 cursor-pointer text-[11px]"
            >
              <Download className="w-3.5 h-3.5 text-brand-muted" />
              Extract Payload to ASCII
            </button>
            <button
              onClick={() => {
                downloadPayload(contextMenu.packet.id, 'raw');
                setContextMenu(null);
              }}
              className="w-full text-left px-3 py-1.5 text-brand-text hover:bg-brand-panel transition flex items-center gap-2 cursor-pointer text-[11px]"
            >
              <Download className="w-3.5 h-3.5 text-brand-accent" />
              Extract Binary Payload (.bin)
            </button>
          </div>
        </div>
      )}

      {/* WHOIS Information Modal */}
      {whoisModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div
            className="w-full max-w-2xl bg-brand-card border border-brand-border rounded shadow-2xl flex flex-col overflow-hidden max-h-[85vh] animate-fade-in"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="px-5 py-4 bg-brand-panel border-b border-brand-border flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Search className="w-4 h-4 text-brand-accent" />
                <h3 className="font-mono font-bold text-sm text-brand-text">
                  WHOIS IP Intelligence Registry: <span className="text-brand-accent">{whoisModal.ip}</span>
                </h3>
              </div>
              <button
                onClick={() => setWhoisModal(null)}
                className="text-brand-dim hover:text-brand-text font-mono text-sm cursor-pointer"
              >
                [CLOSE]
              </button>
            </div>

            {/* Content Area */}
            <div className="p-5 overflow-y-auto space-y-4 text-xs font-mono">
              {whoisModal.loading ? (
                <div className="flex flex-col items-center justify-center py-12 gap-3 text-brand-muted">
                  <RefreshCw className="w-8 h-8 text-brand-accent animate-spin" />
                  <span>Querying IANA & RDAP root database registries...</span>
                </div>
              ) : whoisModal.error ? (
                <div className="p-4 bg-brand-danger/10 border border-brand-danger/20 text-brand-danger rounded">
                  <strong>Query Registry Failure:</strong> {whoisModal.error}
                </div>
              ) : whoisModal.data ? (
                <>
                  {/* Summary Grid */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-3 bg-brand-panel/40 border border-brand-border rounded text-[11px]">
                    <div>
                      <span className="text-brand-muted block">Allocation Range</span>
                      <span className="font-semibold text-brand-text">{whoisModal.data.range}</span>
                    </div>
                    <div>
                      <span className="text-brand-muted block">Network Handle</span>
                      <span className="font-semibold text-brand-text">{whoisModal.data.netName}</span>
                    </div>
                    <div>
                      <span className="text-brand-muted block">Registered Host Organization</span>
                      <span className="font-semibold text-brand-accent">{whoisModal.data.org}</span>
                    </div>
                    <div>
                      <span className="text-brand-muted block">Country ISO Code</span>
                      <span className="font-semibold text-brand-text">{whoisModal.data.country}</span>
                    </div>
                  </div>

                  {/* Raw output database content */}
                  <div>
                    <span className="text-brand-muted font-bold block mb-1">RAW RECONNAISSANCE TELEMETRY LOGS</span>
                    <pre className="p-4 bg-brand-panel rounded text-[10px] text-brand-text overflow-x-auto border border-brand-border max-h-[250px] leading-relaxed select-text">
                      {whoisModal.data.raw}
                    </pre>
                  </div>
                </>
              ) : null}
            </div>

            {/* Footer */}
            <div className="px-5 py-3 bg-brand-panel border-t border-brand-border flex justify-end gap-3">
              <button
                onClick={() => setWhoisModal(null)}
                className="px-4 py-1.5 bg-brand-border hover:bg-brand-border-light text-brand-text rounded font-mono text-xs cursor-pointer transition"
              >
                Dismiss Intel Reports
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Download Desktop App & Local Agent Modal */}
      <DownloadDesktopModal
        isOpen={isDownloadModalOpen}
        onClose={() => setIsDownloadModalOpen(false)}
        isLocalAgentConnected={agents.some(a => !a.isLocal && a.status === 'connected')}
      />

      {/* Add Monitoring Device & Agent Auth Management Modal */}
      <AddAgentModal
        isOpen={isAddAgentModalOpen}
        onClose={() => setIsAddAgentModalOpen(false)}
        agents={agents}
        onSelectAgent={handleSelectAgent}
      />
    </div>
  );
}
