import React, { useState, useEffect } from 'react';
import { AgentInfo, AgentRecord, AgentRegistrationResponse } from '../types';
import {
  Server,
  Plus,
  Copy,
  Check,
  Shield,
  Clock,
  Laptop,
  CheckCircle2,
  AlertTriangle,
  Trash2,
  RefreshCw,
  Terminal,
  X,
  ExternalLink,
  Wifi,
  Radio
} from 'lucide-react';

interface AddAgentModalProps {
  isOpen: boolean;
  onClose: () => void;
  agents: AgentInfo[];
  onSelectAgent?: (agentId: string) => void;
}

export const AddAgentModal: React.FC<AddAgentModalProps> = ({
  isOpen,
  onClose,
  agents,
  onSelectAgent
}) => {
  const [activeTab, setActiveTab] = useState<'ADD' | 'MANAGE'>('ADD');
  const [deviceName, setDeviceName] = useState('My Remote Laptop');
  const [loading, setLoading] = useState(false);
  const [tokenData, setTokenData] = useState<AgentRegistrationResponse | null>(null);
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);
  const [remainingSeconds, setRemainingSeconds] = useState<number>(0);
  const [connectedAgent, setConnectedAgent] = useState<AgentInfo | null>(null);
  const [registeredList, setRegisteredList] = useState<AgentRecord[]>([]);
  const [fetchingList, setFetchingList] = useState(false);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [initialAgentIds, setInitialAgentIds] = useState<Set<string>>(new Set());

  // Initialize and track existing agents to detect newly linked agent
  useEffect(() => {
    if (isOpen) {
      setInitialAgentIds(new Set(agents.map(a => a.id)));
      fetchRegisteredDevices();
    } else {
      setTokenData(null);
      setConnectedAgent(null);
    }
  }, [isOpen]);

  // Check if a new agent appeared in the agents list since token generation
  useEffect(() => {
    if (tokenData && !connectedAgent) {
      const newAgent = agents.find(a => !a.isLocal && !initialAgentIds.has(a.id) && a.status === 'connected');
      if (newAgent) {
        setConnectedAgent(newAgent);
        fetchRegisteredDevices();
      }
    }
  }, [agents, tokenData, connectedAgent, initialAgentIds]);

  // Countdown timer for 15-minute token TTL
  useEffect(() => {
    if (!tokenData || remainingSeconds <= 0) return;
    const interval = setInterval(() => {
      setRemainingSeconds(prev => {
        if (prev <= 1) {
          clearInterval(interval);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [tokenData, remainingSeconds]);

  const fetchRegisteredDevices = async () => {
    setFetchingList(true);
    try {
      const res = await fetch('/api/agents');
      const data = await res.json();
      if (data.registeredDevices) {
        setRegisteredList(data.registeredDevices);
      }
    } catch (e) {
      console.error('Error fetching registered agents:', e);
    } finally {
      setFetchingList(false);
    }
  };

  const generateToken = async () => {
    setLoading(true);
    setConnectedAgent(null);
    try {
      const res = await fetch('/api/agents/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: deviceName.trim() || 'Sentinel Capture Device' })
      });
      const data: AgentRegistrationResponse = await res.json();
      if (data.success) {
        setTokenData(data);
        setRemainingSeconds(data.expiresInSeconds || 900);
        // Refresh base snapshot of agents
        setInitialAgentIds(new Set(agents.map(a => a.id)));
      }
    } catch (e) {
      console.error('Error creating registration token:', e);
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(id);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  const handleRevokeAgent = async (agentId: string) => {
    if (!confirm('Are you sure you want to permanently revoke this device? Its active connection will be immediately terminated and it will no longer be able to capture packets.')) {
      return;
    }

    setRevokingId(agentId);
    try {
      const res = await fetch(`/api/agents/${agentId}`, {
        method: 'DELETE'
      });
      const data = await res.json();
      if (data.success) {
        await fetchRegisteredDevices();
      } else {
        alert(`Error revoking agent: ${data.error || 'Unknown error'}`);
      }
    } catch (e: any) {
      alert(`Failed to revoke agent: ${e.message || e}`);
    } finally {
      setRevokingId(null);
    }
  };

  const formatTimer = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-brand-card border border-brand-border rounded-2xl w-full max-w-2xl overflow-hidden shadow-2xl animate-fade-in flex flex-col max-h-[90vh]">
        
        {/* Modal Header */}
        <div className="bg-brand-panel border-b border-brand-border px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
              <Server className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
                Sentinel Capture Agent Management
              </h3>
              <p className="text-[11px] text-brand-muted">
                Connect and authenticate remote devices securely with one-time tokens
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="text-brand-muted hover:text-white p-1.5 rounded-lg hover:bg-brand-card transition cursor-pointer"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-brand-border bg-brand-card/40 px-6 pt-2">
          <button
            onClick={() => setActiveTab('ADD')}
            className={`px-4 py-2.5 text-xs font-bold font-mono transition border-b-2 flex items-center gap-2 cursor-pointer ${
              activeTab === 'ADD'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-brand-muted hover:text-brand-text'
            }`}
          >
            <Plus className="w-3.5 h-3.5" />
            Add Monitoring Device
          </button>
          <button
            onClick={() => {
              setActiveTab('MANAGE');
              fetchRegisteredDevices();
            }}
            className={`px-4 py-2.5 text-xs font-bold font-mono transition border-b-2 flex items-center gap-2 cursor-pointer ${
              activeTab === 'MANAGE'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-brand-muted hover:text-brand-text'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            Authorized Devices ({registeredList.filter(a => !a.revokedAt).length})
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 font-mono">
          
          {/* TAB 1: ADD NEW MONITORING DEVICE */}
          {activeTab === 'ADD' && (
            <div className="space-y-6">

              {/* Step 1: Device Name Input */}
              {!tokenData && (
                <div className="space-y-4 bg-brand-panel border border-brand-border rounded-xl p-5">
                  <div className="space-y-1">
                    <label className="text-xs font-bold text-slate-200 uppercase tracking-wider block">
                      1. Name This Capture Device
                    </label>
                    <p className="text-[11px] text-brand-muted">
                      Give your device an identifiable name (e.g., Office MacBook, Linux Web Server, Home Lab).
                    </p>
                  </div>

                  <div className="flex gap-3">
                    <input
                      type="text"
                      value={deviceName}
                      onChange={(e) => setDeviceName(e.target.value)}
                      placeholder="e.g. My Laptop"
                      className="flex-1 text-xs bg-brand-card border border-brand-border text-brand-text rounded-lg px-3.5 py-2.5 outline-none focus:border-cyan-400"
                    />
                    <button
                      onClick={generateToken}
                      disabled={loading || !deviceName.trim()}
                      className="bg-cyan-500 hover:bg-cyan-400 text-black font-bold text-xs px-5 py-2.5 rounded-lg transition flex items-center gap-2 shrink-0 cursor-pointer disabled:opacity-50 shadow-[0_0_12px_rgba(6,182,212,0.3)]"
                    >
                      {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Shield className="w-3.5 h-3.5" />}
                      <span>Generate Setup Token</span>
                    </button>
                  </div>
                </div>
              )}

              {/* Step 2: One-Time Token & Setup Command */}
              {tokenData && !connectedAgent && (
                <div className="space-y-5 animate-fade-in">
                  
                  {/* Status Banner */}
                  <div className="bg-cyan-950/40 border border-cyan-500/40 rounded-xl p-4 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping"></div>
                      <div>
                        <span className="text-xs font-bold text-cyan-300 block">
                          Waiting for device: "{deviceName}"
                        </span>
                        <span className="text-[11px] text-brand-muted">
                          Run the command below on your remote computer.
                        </span>
                      </div>
                    </div>

                    <div className="flex items-center gap-1.5 text-xs bg-brand-panel border border-brand-border px-3 py-1.5 rounded-lg text-amber-400">
                      <Clock className="w-3.5 h-3.5" />
                      <span>Expires in {formatTimer(remainingSeconds)}</span>
                    </div>
                  </div>

                  {/* Option A: NPM Run Start Command (Recommended) */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-slate-200 font-bold flex items-center gap-1.5">
                        <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                        Run on Target Machine (Option 1):
                      </span>
                      <span className="text-[10px] text-emerald-400 font-bold bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
                        ONE-TIME TOKEN
                      </span>
                    </div>

                    <div className="bg-black/90 border border-brand-border rounded-xl p-3.5 flex items-center justify-between gap-3 shadow-inner">
                      <code className="text-xs text-emerald-400 font-mono break-all select-all">
                        {tokenData.setupCommand}
                      </code>
                      <button
                        onClick={() => handleCopy(tokenData.setupCommand, 'npm-cmd')}
                        className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded text-xs transition flex items-center gap-1.5 shrink-0 cursor-pointer"
                        title="Copy command"
                      >
                        {copiedCmd === 'npm-cmd' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-cyan-400" />}
                        <span className="text-[11px] font-bold">{copiedCmd === 'npm-cmd' ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                  </div>

                  {/* Option B: Direct NPX Command */}
                  <div className="space-y-2">
                    <span className="text-xs text-slate-300 font-bold flex items-center gap-1.5">
                      <Terminal className="w-3.5 h-3.5 text-slate-400" />
                      Or via NPX Global Command (Option 2):
                    </span>

                    <div className="bg-black/90 border border-brand-border rounded-xl p-3.5 flex items-center justify-between gap-3 shadow-inner">
                      <code className="text-xs text-cyan-300 font-mono break-all select-all">
                        {tokenData.npxCommand}
                      </code>
                      <button
                        onClick={() => handleCopy(tokenData.npxCommand, 'npx-cmd')}
                        className="bg-slate-800 hover:bg-slate-700 text-slate-200 px-3 py-1.5 rounded text-xs transition flex items-center gap-1.5 shrink-0 cursor-pointer"
                        title="Copy command"
                      >
                        {copiedCmd === 'npx-cmd' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-cyan-400" />}
                        <span className="text-[11px] font-bold">{copiedCmd === 'npx-cmd' ? 'Copied' : 'Copy'}</span>
                      </button>
                    </div>
                  </div>

                  {/* Security Explainer */}
                  <div className="p-3 bg-brand-panel border border-brand-border rounded-lg text-[11px] text-brand-muted space-y-1">
                    <p className="text-slate-300 font-bold">🔒 Zero-Trust Security Guarantee:</p>
                    <p>
                      This temporary token is single-use and valid for 15 minutes. Once your agent connects, the backend automatically generates an individual long-term secret key and invalidates this setup token.
                    </p>
                  </div>

                  <div className="flex justify-between items-center pt-2 border-t border-brand-border">
                    <button
                      onClick={() => setTokenData(null)}
                      className="text-xs text-brand-muted hover:text-white transition cursor-pointer"
                    >
                      ← Cancel & Generate New Token
                    </button>
                  </div>

                </div>
              )}

              {/* Step 3: Success Confirmation (Agent Connected!) */}
              {connectedAgent && (
                <div className="p-6 bg-gradient-to-br from-emerald-950/40 to-slate-900 border border-emerald-500/50 rounded-2xl space-y-5 animate-fade-in text-center">
                  <div className="w-12 h-12 rounded-full bg-emerald-500/20 border border-emerald-500/40 mx-auto flex items-center justify-center">
                    <CheckCircle2 className="w-7 h-7 text-emerald-400 animate-bounce" />
                  </div>

                  <div className="space-y-1">
                    <h4 className="text-sm font-bold text-white uppercase tracking-wider">
                      Device Successfully Linked & Authenticated!
                    </h4>
                    <p className="text-xs text-emerald-300">
                      ● Connected: <strong className="text-white">{connectedAgent.name}</strong> ({connectedAgent.platform})
                    </p>
                  </div>

                  <div className="grid grid-cols-2 gap-3 bg-black/60 p-3.5 rounded-xl border border-emerald-900 text-left text-xs">
                    <div>
                      <span className="text-brand-muted block text-[10px]">AGENT ID:</span>
                      <strong className="text-cyan-400 font-mono">{connectedAgent.id}</strong>
                    </div>
                    <div>
                      <span className="text-brand-muted block text-[10px]">HOST IP:</span>
                      <strong className="text-slate-200 font-mono">{connectedAgent.ip}</strong>
                    </div>
                    <div>
                      <span className="text-brand-muted block text-[10px]">INTERFACES DETECTED:</span>
                      <strong className="text-emerald-400">{connectedAgent.interfaces?.length || 0} Network Adapters</strong>
                    </div>
                    <div>
                      <span className="text-brand-muted block text-[10px]">STATUS:</span>
                      <span className="text-emerald-400 font-bold">ONLINE & STREAMING</span>
                    </div>
                  </div>

                  <div className="flex gap-3 justify-center pt-2">
                    <button
                      onClick={() => {
                        if (onSelectAgent) onSelectAgent(connectedAgent.id);
                        onClose();
                      }}
                      className="bg-emerald-500 hover:bg-emerald-400 text-black font-bold text-xs px-6 py-2.5 rounded-lg transition cursor-pointer shadow-[0_0_15px_rgba(16,185,129,0.3)]"
                    >
                      Start Capturing on {connectedAgent.name}
                    </button>
                    <button
                      onClick={onClose}
                      className="bg-brand-panel hover:bg-slate-800 text-slate-300 text-xs px-4 py-2.5 rounded-lg border border-brand-border transition cursor-pointer"
                    >
                      Close Window
                    </button>
                  </div>
                </div>
              )}

            </div>
          )}

          {/* TAB 2: MANAGE AUTHORIZED DEVICES */}
          {activeTab === 'MANAGE' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between text-xs">
                <span className="text-brand-muted">
                  Registered Capture Nodes ({registeredList.length})
                </span>
                <button
                  onClick={fetchRegisteredDevices}
                  disabled={fetchingList}
                  className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 cursor-pointer disabled:opacity-50"
                >
                  <RefreshCw className={`w-3 h-3 ${fetchingList ? 'animate-spin' : ''}`} />
                  Refresh
                </button>
              </div>

              {/* Local Agent Card (Always available) */}
              <div className="p-4 bg-brand-panel border border-brand-border rounded-xl flex items-center justify-between text-xs">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center">
                    <Laptop className="w-4 h-4 text-emerald-400" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <strong className="text-white">Local Backend Agent (agent-local)</strong>
                      <span className="text-[9px] bg-emerald-500/20 text-emerald-300 px-2 py-0.5 rounded font-bold">
                        HOST MACHINE
                      </span>
                    </div>
                    <p className="text-[10px] text-brand-muted">
                      Built-in local capture interface for local development and direct packet inspection.
                    </p>
                  </div>
                </div>
                <span className="text-[10px] text-slate-400 font-bold bg-brand-card px-2.5 py-1 rounded border border-brand-border">
                  PERMANENT
                </span>
              </div>

              {/* Registered Remote Devices List */}
              {registeredList.filter(a => a.id !== 'agent-local').length > 0 ? (
                <div className="space-y-2">
                  {registeredList.map((device) => {
                    const isOnline = agents.some(a => a.id === device.id && a.status === 'connected');
                    const isRevoked = !!device.revokedAt;

                    return (
                      <div
                        key={device.id}
                        className={`p-4 rounded-xl border flex items-center justify-between text-xs transition ${
                          isRevoked
                            ? 'bg-rose-950/10 border-rose-900/40 opacity-60'
                            : isOnline
                            ? 'bg-cyan-950/20 border-cyan-500/30'
                            : 'bg-brand-panel border-brand-border'
                        }`}
                      >
                        <div className="flex items-center gap-3">
                          <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
                            isRevoked
                              ? 'bg-rose-500/10 border border-rose-500/30 text-rose-400'
                              : isOnline
                              ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-400'
                              : 'bg-slate-800 text-slate-400'
                          }`}>
                            <Server className="w-4 h-4" />
                          </div>

                          <div className="space-y-0.5">
                            <div className="flex items-center gap-2">
                              <strong className="text-white">{device.name}</strong>
                              {isRevoked ? (
                                <span className="text-[9px] bg-rose-500/20 text-rose-300 px-1.5 py-0.5 rounded font-bold">
                                  REVOKED
                                </span>
                              ) : isOnline ? (
                                <span className="text-[9px] bg-emerald-500/20 text-emerald-300 px-1.5 py-0.5 rounded font-bold flex items-center gap-1">
                                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping"></span>
                                  ONLINE
                                </span>
                              ) : (
                                <span className="text-[9px] bg-slate-800 text-slate-400 px-1.5 py-0.5 rounded">
                                  OFFLINE
                                </span>
                              )}
                            </div>
                            <div className="text-[10px] text-brand-muted flex items-center gap-3">
                              <span>ID: <code className="text-cyan-400">{device.id}</code></span>
                              <span>Platform: <strong className="text-slate-300">{device.platform}</strong></span>
                              <span>Registered: {new Date(device.createdAt).toLocaleDateString()}</span>
                            </div>
                          </div>
                        </div>

                        <div>
                          {!isRevoked && (
                            <button
                              onClick={() => handleRevokeAgent(device.id)}
                              disabled={revokingId === device.id}
                              className="text-xs text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 border border-rose-500/30 px-3 py-1.5 rounded-lg transition flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
                              title="Permanently invalidate credentials and disconnect this agent"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                              <span>{revokingId === device.id ? 'Revoking...' : 'Revoke'}</span>
                            </button>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="p-6 bg-brand-panel border border-brand-border rounded-xl text-center text-xs text-brand-muted space-y-2">
                  <Server className="w-6 h-6 mx-auto text-slate-500" />
                  <p>No remote capture agents registered yet.</p>
                  <button
                    onClick={() => setActiveTab('ADD')}
                    className="text-cyan-400 hover:underline font-bold text-xs cursor-pointer"
                  >
                    + Click here to add your first device
                  </button>
                </div>
              )}
            </div>
          )}

        </div>

      </div>
    </div>
  );
};
