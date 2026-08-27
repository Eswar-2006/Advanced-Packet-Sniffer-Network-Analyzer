import React, { useState } from 'react';
import { AgentInfo, NetworkInterface, AgentStatus, CaptureMode } from '../types';
import {
  Server,
  Wifi,
  Network,
  Shield,
  Activity,
  RefreshCw,
  Play,
  Square,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Radio,
  Sliders,
  Info
} from 'lucide-react';

interface MonitoringSourceBarProps {
  agents: AgentInfo[];
  selectedAgentId: string;
  selectedInterfaceId: string;
  onSelectAgent: (agentId: string) => void;
  onSelectInterface: (interfaceId: string) => void;
  onRefreshInterfaces: (agentId: string) => void;
  onStartMonitoring: (agentId: string, interfaceId: string) => void;
  onStopMonitoring: (agentId: string) => void;
  onOpenAddAgentModal?: () => void;
  isCapturing: boolean;
  captureMode: CaptureMode;
  packetsPerSec: number;
  totalPackets: number;
  totalBytes: number;
  isRefreshing?: boolean;
}

export const MonitoringSourceBar: React.FC<MonitoringSourceBarProps> = ({
  agents,
  selectedAgentId,
  selectedInterfaceId,
  onSelectAgent,
  onSelectInterface,
  onRefreshInterfaces,
  onStartMonitoring,
  onStopMonitoring,
  onOpenAddAgentModal,
  isCapturing,
  captureMode,
  packetsPerSec,
  totalPackets,
  totalBytes,
  isRefreshing = false
}) => {
  const currentAgent = agents.find(a => a.id === selectedAgentId) || agents[0];
  const interfaces = currentAgent?.interfaces || [];
  const currentInterface = interfaces.find(i => i.id === selectedInterfaceId) || interfaces[0];

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const getInterfaceIcon = (type: string) => {
    switch (type) {
      case 'wireless': return <Wifi className="w-3.5 h-3.5 text-cyan-400" />;
      case 'ethernet': return <Network className="w-3.5 h-3.5 text-emerald-400" />;
      case 'vpn': return <Shield className="w-3.5 h-3.5 text-purple-400" />;
      case 'loopback': return <Radio className="w-3.5 h-3.5 text-amber-400" />;
      default: return <Sliders className="w-3.5 h-3.5 text-slate-400" />;
    }
  };

  const getStatusBadge = (status?: AgentStatus) => {
    switch (status) {
      case 'monitoring':
        return (
          <span className="flex items-center gap-1.5 text-[10px] bg-emerald-500/10 text-emerald-400 font-mono px-2 py-0.5 rounded border border-emerald-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-ping"></span>
            MONITORING
          </span>
        );
      case 'connected':
        return (
          <span className="flex items-center gap-1.5 text-[10px] bg-cyan-500/10 text-cyan-400 font-mono px-2 py-0.5 rounded border border-cyan-500/30">
            <CheckCircle2 className="w-3 h-3" />
            CONNECTED
          </span>
        );
      case 'disconnected':
        return (
          <span className="flex items-center gap-1.5 text-[10px] bg-rose-500/10 text-rose-400 font-mono px-2 py-0.5 rounded border border-rose-500/30">
            <XCircle className="w-3 h-3" />
            OFFLINE
          </span>
        );
      case 'error':
        return (
          <span className="flex items-center gap-1.5 text-[10px] bg-amber-500/10 text-amber-400 font-mono px-2 py-0.5 rounded border border-amber-500/30">
            <AlertTriangle className="w-3 h-3" />
            ERROR
          </span>
        );
      default:
        return (
          <span className="text-[10px] bg-slate-800 text-slate-400 font-mono px-2 py-0.5 rounded">
            STOPPED
          </span>
        );
    }
  };

  return (
    <div className="bg-brand-card/90 border-b border-brand-border px-6 py-3 font-mono text-xs shadow-md">
      <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4">
        
        {/* Left Section: Monitoring Target & Source Selectors */}
        <div className="flex flex-wrap items-center gap-4">
          
          {/* Agent Selector */}
          <div className="flex items-center gap-2">
            <label className="text-[11px] text-brand-muted uppercase font-bold flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-brand-accent" />
              Agent:
            </label>
            <select
              value={selectedAgentId}
              onChange={(e) => onSelectAgent(e.target.value)}
              className="bg-brand-panel border border-brand-border rounded px-2.5 py-1.5 text-brand-text font-mono text-xs focus:border-brand-accent focus:outline-none cursor-pointer"
            >
              {agents.map(agent => (
                <option key={agent.id} value={agent.id}>
                  {agent.isLocal ? '💻 ' : '🌐 '}{agent.name} [{agent.ip}]
                </option>
              ))}
            </select>
            {getStatusBadge(currentAgent?.status)}

            {/* Add Monitoring Device Modal Trigger Button */}
            {onOpenAddAgentModal && (
              <button
                onClick={onOpenAddAgentModal}
                className="bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 hover:border-cyan-400 px-2.5 py-1.5 rounded text-[11px] font-bold flex items-center gap-1.5 transition cursor-pointer shadow-sm"
                title="Add a new remote device via one-time secure registration token"
              >
                <span>+ Add Device</span>
              </button>
            )}
          </div>

          {/* Interface Selector */}
          <div className="flex items-center gap-2">
            <label className="text-[11px] text-brand-muted uppercase font-bold flex items-center gap-1.5">
              <Wifi className="w-3.5 h-3.5 text-brand-accent" />
              Interface:
            </label>
            <div className="flex items-center gap-1 bg-brand-panel border border-brand-border rounded px-2 py-1">
              {currentInterface && getInterfaceIcon(currentInterface.type)}
              <select
                value={selectedInterfaceId || (currentInterface?.id || '')}
                onChange={(e) => onSelectInterface(e.target.value)}
                className="bg-transparent text-brand-text font-mono text-xs focus:outline-none cursor-pointer pr-1 max-w-[260px]"
              >
                {interfaces.map(iface => (
                  <option key={iface.id} value={iface.id} className="bg-brand-card text-brand-text">
                    {iface.name} ({iface.type.toUpperCase()}) — {iface.ip}
                  </option>
                ))}
              </select>
            </div>

            {/* Refresh Interfaces Button */}
            <button
              onClick={() => currentAgent && onRefreshInterfaces(currentAgent.id)}
              disabled={isRefreshing || currentAgent?.status === 'disconnected'}
              className="p-1.5 bg-brand-panel border border-brand-border hover:bg-brand-card text-brand-muted hover:text-brand-accent rounded transition cursor-pointer disabled:opacity-50"
              title="Rescan network adapters"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-brand-accent' : ''}`} />
            </button>
          </div>

          {/* Capture Mode Indicator (Constraint 2: Explicit REAL vs SIMULATED badge!) */}
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] text-brand-muted">ENGINE:</span>
            {captureMode === 'REAL' ? (
              <span className="text-[10px] bg-emerald-950/60 text-emerald-400 font-bold px-2 py-0.5 rounded border border-emerald-600/40 flex items-center gap-1">
                <Shield className="w-3 h-3 text-emerald-400" />
                REAL TSHARK CAPTURE
              </span>
            ) : (
              <span className="text-[10px] bg-amber-950/60 text-amber-300 font-bold px-2 py-0.5 rounded border border-amber-600/40 flex items-center gap-1" title="tshark binary not detected or active on target adapter. Demonstrating telemetry via high-fidelity packet simulator.">
                <AlertTriangle className="w-3 h-3 text-amber-400" />
                SIMULATED DEMO TRAFFIC
              </span>
            )}
          </div>
        </div>

        {/* Right Section: Telemetry Counters & Action Controls */}
        <div className="flex flex-wrap items-center gap-4 border-t xl:border-t-0 pt-2 xl:pt-0 border-brand-border">
          
          {/* Live Telemetry Chips */}
          <div className="flex items-center gap-4 text-[11px] font-mono">
            <div className="flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              <span className="text-brand-muted">PKTS/SEC:</span>
              <span className="text-brand-accent font-bold">{packetsPerSec}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-brand-muted">TOTAL PKTS:</span>
              <span className="text-white font-bold">{totalPackets.toLocaleString()}</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-brand-muted">TRAFFIC:</span>
              <span className="text-emerald-400 font-bold">{formatBytes(totalBytes)}</span>
            </div>
          </div>

          {/* Start / Stop Toggle Button */}
          <div className="flex items-center gap-2">
            {isCapturing ? (
              <button
                onClick={() => currentAgent && onStopMonitoring(currentAgent.id)}
                className="bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 px-3.5 py-1.5 rounded font-bold uppercase tracking-wider text-[11px] flex items-center gap-1.5 transition cursor-pointer"
              >
                <Square className="w-3 h-3 fill-current" />
                Stop Capture
              </button>
            ) : (
              <button
                onClick={() => currentAgent && currentInterface && onStartMonitoring(currentAgent.id, currentInterface.id)}
                disabled={currentAgent?.status === 'disconnected'}
                className="bg-brand-accent/10 hover:bg-brand-accent/20 text-brand-accent border border-brand-accent/30 px-3.5 py-1.5 rounded font-bold uppercase tracking-wider text-[11px] flex items-center gap-1.5 transition cursor-pointer disabled:opacity-50"
              >
                <Play className="w-3 h-3 fill-current" />
                Start Monitoring
              </button>
            )}
          </div>
        </div>

      </div>
    </div>
  );
};
