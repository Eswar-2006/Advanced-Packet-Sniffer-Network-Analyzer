import React, { useState } from 'react';
import { PcapAnalysisReport, PcapFinding, Packet, CtfArtifact, ReconstructedFile } from '../types';
import { filterPackets } from '../utils';
import {
  FileCode,
  Upload,
  AlertTriangle,
  Shield,
  CheckCircle2,
  AlertCircle,
  Search,
  Filter,
  FileDown,
  Activity,
  Terminal,
  Server,
  Layers,
  Database,
  Lock,
  Eye,
  RefreshCw,
  Key,
  Copy,
  Check,
  FileText,
  Flag
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer
} from 'recharts';

interface PcapAnalyzerPanelProps {
  onAnalyzeSample?: () => void;
}

export const PcapAnalyzerPanel: React.FC<PcapAnalyzerPanelProps> = () => {
  const [report, setReport] = useState<PcapAnalysisReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const [selectedPacket, setSelectedPacket] = useState<Packet | null>(null);
  const [activeSubTab, setActiveSubTab] = useState<'CTF' | 'FINDINGS' | 'PACKETS' | 'TALKERS'>('CTF');
  const [copiedArtifactId, setCopiedArtifactId] = useState<string | null>(null);

  const copyArtifact = (val: string, id: string) => {
    navigator.clipboard.writeText(val);
    setCopiedArtifactId(id);
    setTimeout(() => setCopiedArtifactId(null), 2000);
  };

  // Packet Filter state
  const [searchQuery, setSearchQuery] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');

  const handleFileUpload = async (file: File) => {
    setLoading(true);
    try {
      const reader = new FileReader();
      reader.onload = async (e) => {
        const arrayBuffer = e.target?.result as ArrayBuffer;
        const base64 = btoa(
          new Uint8Array(arrayBuffer).reduce((data, byte) => data + String.fromCharCode(byte), '')
        );

        const res = await fetch('/api/pcap/analyze', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ filename: file.name, base64 })
        });

        const data = await res.json();
        if (data.success && data.report) {
          setReport(data.report);
          if (data.report.packets && data.report.packets.length > 0) {
            setSelectedPacket(data.report.packets[0]);
          }
        } else {
          alert(`Analysis Error: ${data.error || 'Failed to analyze PCAP file'}`);
        }
        setLoading(false);
      };
      reader.readAsArrayBuffer(file);
    } catch (err: any) {
      console.error("PCAP upload failed:", err);
      alert(`Upload failed: ${err.message || err}`);
      setLoading(false);
    }
  };

  const handleSamplePcap = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/pcap/sample');
      const data = await res.json();
      if (data.success && data.report) {
        setReport(data.report);
        if (data.report.packets && data.report.packets.length > 0) {
          setSelectedPacket(data.report.packets[0]);
        }
      }
    } catch (err) {
      console.error("Sample PCAP fetch error:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const getRiskBadge = (level?: string) => {
    switch (level) {
      case 'CRITICAL':
        return <span className="bg-rose-500/20 text-rose-400 border border-rose-500/40 px-3 py-1 rounded font-bold text-xs">CRITICAL RISK</span>;
      case 'HIGH':
        return <span className="bg-orange-500/20 text-orange-400 border border-orange-500/40 px-3 py-1 rounded font-bold text-xs">HIGH THREAT LEVEL</span>;
      case 'MEDIUM':
        return <span className="bg-amber-500/20 text-amber-300 border border-amber-500/40 px-3 py-1 rounded font-bold text-xs">MODERATE RISK</span>;
      case 'LOW':
        return <span className="bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 px-3 py-1 rounded font-bold text-xs">LOW ANOMALY</span>;
      default:
        return <span className="bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 px-3 py-1 rounded font-bold text-xs">CLEAN PCAP AUDIT</span>;
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return <span className="bg-rose-500/20 text-rose-400 px-2 py-0.5 rounded text-[10px] font-bold border border-rose-500/40">CRITICAL</span>;
      case 'HIGH':
        return <span className="bg-orange-500/20 text-orange-400 px-2 py-0.5 rounded text-[10px] font-bold border border-orange-500/40">HIGH</span>;
      case 'MEDIUM':
        return <span className="bg-amber-500/20 text-amber-300 px-2 py-0.5 rounded text-[10px] font-bold border border-amber-500/40">MEDIUM</span>;
      default:
        return <span className="bg-cyan-500/20 text-cyan-400 px-2 py-0.5 rounded text-[10px] font-bold border border-cyan-500/40">INFO</span>;
    }
  };

  const filteredFindings = report?.findings.filter(f => {
    if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return f.title.toLowerCase().includes(q) || f.description.toLowerCase().includes(q) || f.sourceIp.includes(q) || f.destinationIp.includes(q);
    }
    return true;
  }) || [];

  const filteredPcapPackets = report?.packets.filter(p => {
    if (protocolFilter !== 'ALL' && p.protocol !== protocolFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return p.summary.toLowerCase().includes(q) || p.srcIp.includes(q) || p.dstIp.includes(q) || p.protocol.toLowerCase().includes(q);
    }
    return true;
  }) || [];

  const COLORS = ['#38bdf8', '#818cf8', '#34d399', '#f87171', '#fbbf24', '#a78bfa'];

  return (
    <div className="flex-1 p-6 space-y-6 font-sans bg-brand-bg text-brand-text">
      
      {/* Title & Section Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-brand-border pb-4">
        <div>
          <div className="flex items-center gap-2">
            <FileCode className="w-6 h-6 text-brand-accent animate-pulse" />
            <h2 className="text-xl font-bold uppercase tracking-wider font-mono text-white">
              PCAP Deep Forensic Analyzer
            </h2>
            <span className="text-[10px] bg-brand-accent/20 text-brand-accent font-mono font-bold px-2 py-0.5 rounded border border-brand-accent/40">
              OFFLINE / FILE AUDIT
            </span>
          </div>
          <p className="text-xs text-brand-muted mt-1 font-mono">
            Upload `.pcap` or `.pcapng` capture files for deep protocol inspection, threat categorization, cleartext credential detection, and forensic risk reporting.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleSamplePcap}
            disabled={loading}
            className="px-4 py-2 bg-brand-panel border border-brand-accent/40 hover:bg-brand-card text-brand-accent font-mono text-xs rounded font-bold uppercase tracking-wider flex items-center gap-2 transition cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Load Sample Forensic PCAP
          </button>
        </div>
      </div>

      {/* Drag & Drop Upload Zone */}
      {!report && (
        <div
          onDragEnter={handleDrag}
          onDragOver={handleDrag}
          onDragLeave={handleDrag}
          onDrop={handleDrop}
          className={`border-2 border-dashed rounded-xl p-10 text-center transition-all ${
            dragActive
              ? 'border-brand-accent bg-brand-accent/10 shadow-[0_0_30px_rgba(0,242,255,0.2)]'
              : 'border-brand-border hover:border-brand-border-light bg-brand-card/60'
          }`}
        >
          <div className="w-16 h-16 rounded-full bg-brand-panel border border-brand-border flex items-center justify-center mx-auto mb-4 text-brand-accent">
            <Upload className="w-8 h-8" />
          </div>
          <h3 className="text-base font-bold text-white font-mono uppercase tracking-wider">
            Drop Your `.pcap` or `.pcapng` Packet Capture File Here
          </h3>
          <p className="text-xs text-brand-muted font-mono mt-1 max-w-lg mx-auto">
            Deeply inspect network traces for cleartext credentials, port scanning probes, DNS C2 exfiltration, legacy unencrypted protocols, and security anomalies.
          </p>

          <div className="mt-6 flex flex-col sm:flex-row items-center justify-center gap-4">
            <label className="px-6 py-2.5 bg-brand-accent hover:bg-brand-accent-blue text-brand-bg font-bold font-mono text-xs uppercase tracking-wider rounded cursor-pointer transition shadow-md">
              Browse PCAP File
              <input
                type="file"
                accept=".pcap,.pcapng,.cap"
                onChange={(e) => e.target.files?.[0] && handleFileUpload(e.target.files[0])}
                className="hidden"
              />
            </label>
            <button
              onClick={handleSamplePcap}
              className="px-6 py-2.5 bg-brand-panel border border-brand-border hover:bg-brand-card text-brand-text font-mono text-xs uppercase font-bold rounded transition cursor-pointer"
            >
              Analyze Demo Threat Trace
            </button>
          </div>
        </div>
      )}

      {/* Loading Spinner State */}
      {loading && (
        <div className="bg-brand-card/80 border border-brand-border rounded-xl p-12 text-center font-mono">
          <RefreshCw className="w-10 h-10 text-brand-accent animate-spin mx-auto mb-3" />
          <h4 className="text-sm font-bold text-white uppercase tracking-wider">
            Performing Deep PCAP Protocol & Threat Analysis...
          </h4>
          <p className="text-xs text-brand-muted mt-1">
            Extracting frame fields, testing heuristic rules, checking cleartext credentials, and auditing DNS queries.
          </p>
        </div>
      )}

      {/* Analysis Report Results */}
      {report && !loading && (
        <div className="space-y-6">
          
          {/* Executive Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 font-mono">
            
            {/* Risk Score Card */}
            <div className="bg-brand-card/90 border border-brand-border p-5 rounded-xl flex flex-col justify-between">
              <div className="flex items-center justify-between">
                <span className="text-[11px] text-brand-muted uppercase font-bold">Threat Risk Score</span>
                <Shield className="w-4 h-4 text-brand-accent" />
              </div>
              <div className="mt-3 flex items-baseline gap-3">
                <span className={`text-4xl font-extrabold ${report.riskScore > 50 ? 'text-rose-400' : 'text-emerald-400'}`}>
                  {report.riskScore}<span className="text-xs text-brand-muted">/100</span>
                </span>
                {getRiskBadge(report.riskLevel)}
              </div>
              <div className="w-full bg-brand-panel h-1.5 rounded-full mt-3 overflow-hidden">
                <div
                  className={`h-full ${report.riskScore > 50 ? 'bg-rose-500' : 'bg-emerald-500'}`}
                  style={{ width: `${report.riskScore}%` }}
                ></div>
              </div>
            </div>

            {/* Total Packets */}
            <div className="bg-brand-card/90 border border-brand-border p-5 rounded-xl flex flex-col justify-between">
              <div className="flex items-center justify-between">
                <span className="text-[11px] text-brand-muted uppercase font-bold">Packets Processed</span>
                <Activity className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="mt-3 text-3xl font-extrabold text-white">
                {report.totalPackets.toLocaleString()}
              </div>
              <p className="text-[10px] text-brand-muted mt-1">File: {report.filename}</p>
            </div>

            {/* Total Data Volume */}
            <div className="bg-brand-card/90 border border-brand-border p-5 rounded-xl flex flex-col justify-between">
              <div className="flex items-center justify-between">
                <span className="text-[11px] text-brand-muted uppercase font-bold">Total Traffic Size</span>
                <Database className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="mt-3 text-3xl font-extrabold text-emerald-400">
                {(report.totalBytes / (1024 * 1024)).toFixed(2)} <span className="text-xs font-normal">MB</span>
              </div>
              <p className="text-[10px] text-brand-muted mt-1">Duration: ~{report.durationSeconds}s</p>
            </div>

            {/* Threat Findings Count */}
            <div className="bg-brand-card/90 border border-brand-border p-5 rounded-xl flex flex-col justify-between">
              <div className="flex items-center justify-between">
                <span className="text-[11px] text-brand-muted uppercase font-bold">Suspicious Anomalies</span>
                <AlertTriangle className="w-4 h-4 text-amber-400" />
              </div>
              <div className="mt-3 text-3xl font-extrabold text-amber-400">
                {report.findings.filter(f => f.severity !== 'INFO').length}
              </div>
              <p className="text-[10px] text-brand-muted mt-1">Found across protocol streams</p>
            </div>
          </div>

          {/* Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 font-mono">
            
            {/* Protocol Distribution */}
            <div className="bg-brand-card/90 border border-brand-border rounded-xl p-5">
              <h4 className="text-xs font-bold uppercase text-white tracking-wider mb-4 flex items-center gap-2">
                <Layers className="w-4 h-4 text-brand-accent" />
                PCAP Protocol Distribution
              </h4>
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={report.protocolDistribution}
                      dataKey="bytes"
                      nameKey="protocol"
                      cx="50%"
                      cy="50%"
                      outerRadius={75}
                      label={({ name, percent }) => `${name} (${((percent || 0) * 100).toFixed(0)}%)`}
                    >
                      {report.protocolDistribution.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0d131d', borderColor: '#1e293b', color: '#fff', fontSize: '11px' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* Top Communicating Endpoints */}
            <div className="bg-brand-card/90 border border-brand-border rounded-xl p-5">
              <h4 className="text-xs font-bold uppercase text-white tracking-wider mb-4 flex items-center gap-2">
                <Server className="w-4 h-4 text-cyan-400" />
                Top Communicate Host Volume
              </h4>
              <div className="h-56">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={report.topTalkers.slice(0, 6)}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="ip" stroke="#64748b" tick={{ fontSize: 10 }} />
                    <YAxis stroke="#64748b" tick={{ fontSize: 10 }} />
                    <Tooltip contentStyle={{ backgroundColor: '#0d131d', borderColor: '#1e293b', color: '#fff', fontSize: '11px' }} />
                    <Bar dataKey="bytes" fill="#38bdf8" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

          </div>

          {/* Sub Navigation Tabs inside PCAP Deep Analyzer */}
          <div className="bg-brand-card/60 border border-brand-border rounded-xl overflow-hidden">
            <div className="bg-brand-panel border-b border-brand-border px-4 py-2 flex items-center justify-between font-mono">
              <div className="flex items-center gap-2">
                {[
                  { id: 'CTF',      label: `🚩 CTF & Forensics Intel (${(report.ctfArtifacts || []).length})`, icon: Flag },
                  { id: 'FINDINGS', label: `Security & Threat Findings (${report.findings.length})`,           icon: AlertTriangle },
                  { id: 'PACKETS',  label: `PCAP Packet Inspector (${report.packets.length})`,                icon: Search },
                  { id: 'TALKERS',  label: `Top Host Conversations (${report.topTalkers.length})`,             icon: Server }
                ].map(t => {
                  const Icon = t.icon;
                  return (
                    <button
                      key={t.id}
                      onClick={() => setActiveSubTab(t.id as any)}
                      className={`px-3 py-1.5 text-xs font-bold rounded flex items-center gap-2 transition cursor-pointer ${
                        activeSubTab === t.id
                          ? 'bg-brand-card text-cyan-400 border border-cyan-500/40 shadow-[0_0_10px_rgba(6,182,212,0.2)]'
                          : 'text-brand-muted hover:text-brand-text'
                      }`}
                    >
                      <Icon className="w-3.5 h-3.5 text-cyan-400" />
                      {t.label}
                    </button>
                  );
                })}
              </div>

              {/* Upload New PCAP Button */}
              <label className="text-[10px] bg-brand-accent/10 hover:bg-brand-accent/20 text-brand-accent border border-brand-accent/30 px-3 py-1.5 rounded font-bold uppercase cursor-pointer transition">
                Upload Another PCAP
                <input
                  type="file"
                  accept=".pcap,.pcapng,.cap"
                  onChange={(e) => e.target.files?.[0] && handleFileUpload(e.target.files[0])}
                  className="hidden"
                />
              </label>
            </div>

            {/* Content Area */}
            <div className="p-4 font-mono">

              {/* TAB 0: CTF & FORENSICS INTEL */}
              {activeSubTab === 'CTF' && (
                <div className="space-y-6 animate-fade-in">
                  
                  {/* Discovered CTF Flags Section */}
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Flag className="w-4 h-4 text-cyan-400" />
                        <h4 className="text-xs font-bold text-slate-100 uppercase tracking-wider">
                          Extracted CTF Flags & High-Value Secrets ({ (report.ctfArtifacts || []).filter(a => a.type === 'CTF_FLAG').length })
                        </h4>
                      </div>
                      <span className="text-[10px] bg-cyan-500/10 text-cyan-300 px-2 py-0.5 rounded border border-cyan-500/30">
                        AUTOMATIC PATTERN MATCH & BASE64 DECODER
                      </span>
                    </div>

                    {(report.ctfArtifacts || []).filter(a => a.type === 'CTF_FLAG').length > 0 ? (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {(report.ctfArtifacts || []).filter(a => a.type === 'CTF_FLAG').map((art) => (
                          <div
                            key={art.id}
                            className="p-4 rounded-xl bg-gradient-to-br from-cyan-950/40 to-slate-900 border border-cyan-500/50 shadow-[0_0_15px_rgba(6,182,212,0.15)] flex flex-col justify-between space-y-3"
                          >
                            <div className="space-y-2">
                              <div className="flex items-center justify-between">
                                <span className="text-xs font-bold text-cyan-300 flex items-center gap-1.5">
                                  🚩 {art.title}
                                </span>
                                <span className="text-[10px] bg-emerald-500/20 text-emerald-300 px-2 py-0.5 rounded border border-emerald-500/40 font-bold">
                                  {art.confidence} CONFIDENCE
                                </span>
                              </div>
                              
                              <div className="bg-black/80 p-3 rounded-lg border border-cyan-900 font-mono text-xs text-emerald-400 break-all select-all flex items-center justify-between">
                                <code>{art.value}</code>
                                <button
                                  onClick={() => copyArtifact(art.value, art.id)}
                                  className="ml-2 p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs transition-colors shrink-0 flex items-center gap-1"
                                  title="Copy Flag value to clipboard"
                                >
                                  {copiedArtifactId === art.id ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-cyan-400" />}
                                  <span className="text-[10px] font-bold">{copiedArtifactId === art.id ? 'Copied!' : 'Copy'}</span>
                                </button>
                              </div>
                            </div>

                            <div className="flex items-center justify-between text-[10px] text-brand-muted border-t border-brand-border/60 pt-2">
                              <span>Protocol: <strong className="text-slate-200">{art.protocol}</strong></span>
                              <span>Source: <strong className="text-cyan-400">{art.srcIp}</strong> → <strong className="text-emerald-400">{art.dstIp}</strong></span>
                              {art.packetId && <span>Packet #{art.packetId}</span>}
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="p-5 rounded-lg bg-brand-panel border border-brand-border text-xs text-brand-muted flex items-center gap-3">
                        <Flag className="w-5 h-5 text-slate-500" />
                        <span>No explicit flag format string matching baseline rules found in raw payloads. Check Harvested Credentials and Protocol Streams below.</span>
                      </div>
                    )}
                  </div>

                  {/* Harvested Cleartext Credentials Section */}
                  <div className="space-y-3 pt-4">
                    <div className="flex items-center gap-2">
                      <Key className="w-4 h-4 text-amber-400" />
                      <h4 className="text-xs font-bold text-slate-100 uppercase tracking-wider">
                        Harvested Cleartext Credentials & Auth Tokens ({ (report.ctfArtifacts || []).filter(a => a.type === 'CREDENTIAL').length })
                      </h4>
                    </div>

                    {(report.ctfArtifacts || []).filter(a => a.type === 'CREDENTIAL').length > 0 ? (
                      <div className="space-y-2">
                        {(report.ctfArtifacts || []).filter(a => a.type === 'CREDENTIAL').map((cred) => (
                          <div key={cred.id} className="p-3 bg-amber-950/20 border border-amber-500/30 rounded-lg flex items-center justify-between text-xs">
                            <div className="space-y-1">
                              <span className="font-bold text-amber-300 flex items-center gap-2">
                                🔑 {cred.title}
                              </span>
                              <p className="text-slate-200 font-mono text-xs">{cred.value}</p>
                            </div>
                            <div className="text-right text-[10px] text-brand-muted">
                              <p className="text-cyan-400">{cred.srcIp} → {cred.dstIp}</p>
                              <button
                                onClick={() => copyArtifact(cred.value, cred.id)}
                                className="mt-1 px-2 py-0.5 bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 rounded border border-amber-500/40 text-[10px] font-bold"
                              >
                                {copiedArtifactId === cred.id ? 'Copied' : 'Copy Credential'}
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="p-4 rounded-lg bg-brand-panel border border-brand-border text-xs text-brand-muted">
                        No cleartext HTTP/FTP password authentication exchanges detected in this PCAP trace.
                      </div>
                    )}
                  </div>

                  {/* Reconstructed Files Section */}
                  <div className="space-y-3 pt-4">
                    <div className="flex items-center gap-2">
                      <FileCode className="w-4 h-4 text-emerald-400" />
                      <h4 className="text-xs font-bold text-slate-100 uppercase tracking-wider">
                        Reconstructed Transferred File Streams ({ (report.reconstructedFiles || []).length })
                      </h4>
                    </div>

                    {(report.reconstructedFiles || []).length > 0 ? (
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                        {report.reconstructedFiles?.map((file) => (
                          <div key={file.id} className="p-3 bg-slate-900 border border-brand-border rounded-lg space-y-2">
                            <div className="flex items-center justify-between">
                              <span className="text-xs font-bold text-slate-200">{file.filename}</span>
                              <span className="text-[9px] bg-slate-800 text-emerald-400 px-2 py-0.5 rounded">{file.mimeType}</span>
                            </div>
                            <p className="text-[10px] text-brand-muted">Frame Packet #{file.packetId} · {file.sizeBytes} Bytes</p>
                            <div className="bg-black p-2 rounded text-[9px] text-slate-400 font-mono overflow-x-auto">
                              Sample: {file.sampleHex}
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="p-4 rounded-lg bg-brand-panel border border-brand-border text-xs text-brand-muted">
                        No image, ZIP archive, or executable file signatures were detected in application streams.
                      </div>
                    )}
                  </div>

                </div>
              )}

              {/* TAB 1: FINDINGS & SECURITY ALERTS */}
              {activeSubTab === 'FINDINGS' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-brand-muted">Filter by severity:</span>
                    <select
                      value={severityFilter}
                      onChange={(e) => setSeverityFilter(e.target.value)}
                      className="bg-brand-panel border border-brand-border rounded px-2.5 py-1 text-brand-text text-xs focus:outline-none"
                    >
                      <option value="ALL">ALL SEVERITIES</option>
                      <option value="CRITICAL">CRITICAL ONLY</option>
                      <option value="HIGH">HIGH ONLY</option>
                      <option value="MEDIUM">MEDIUM ONLY</option>
                      <option value="INFO">INFO / BASELINE</option>
                    </select>
                  </div>

                  <div className="space-y-3">
                    {filteredFindings.map((finding) => (
                      <div
                        key={finding.id}
                        className={`p-4 rounded-lg border transition ${
                          finding.severity === 'CRITICAL'
                            ? 'bg-rose-950/20 border-rose-500/40'
                            : finding.severity === 'HIGH'
                            ? 'bg-orange-950/20 border-orange-500/40'
                            : finding.severity === 'MEDIUM'
                            ? 'bg-amber-950/20 border-amber-500/40'
                            : 'bg-brand-panel/60 border-brand-border'
                        }`}
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            {getSeverityBadge(finding.severity)}
                            <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                              {finding.title}
                            </h4>
                          </div>
                          <span className="text-[10px] text-brand-muted bg-brand-panel px-2 py-0.5 rounded border border-brand-border">
                            CATEGORY: {finding.category}
                          </span>
                        </div>

                        <p className="text-xs text-brand-text mt-2 leading-relaxed">
                          {finding.description}
                        </p>

                        <div className="mt-3 pt-2 border-t border-brand-border/60 flex flex-wrap items-center justify-between text-[11px] gap-2">
                          <div className="flex items-center gap-3 text-brand-muted">
                            <span>Source: <strong className="text-cyan-400">{finding.sourceIp}</strong></span>
                            <span>Destination: <strong className="text-emerald-400">{finding.destinationIp}</strong></span>
                            <span>Protocol: <strong className="text-amber-400">{finding.protocol}</strong></span>
                          </div>
                          <div className="text-emerald-400 font-semibold flex items-center gap-1 text-[10px]">
                            <Shield className="w-3 h-3" />
                            Rec: {finding.recommendation}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* TAB 2: PACKET INSPECTOR */}
              {activeSubTab === 'PACKETS' && (
                <div className="space-y-4">
                  {/* Search Bar */}
                  <div className="flex flex-wrap items-center gap-3">
                    <div className="flex-1 relative">
                      <Search className="w-3.5 h-3.5 text-brand-muted absolute left-3 top-2.5" />
                      <input
                        type="text"
                        placeholder="Search packets in uploaded PCAP..."
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        className="w-full bg-brand-panel border border-brand-border rounded pl-9 pr-3 py-1.5 text-xs text-brand-text focus:border-brand-accent focus:outline-none"
                      />
                    </div>
                    <select
                      value={protocolFilter}
                      onChange={(e) => setProtocolFilter(e.target.value)}
                      className="bg-brand-panel border border-brand-border rounded px-2.5 py-1.5 text-xs text-brand-text focus:outline-none"
                    >
                      <option value="ALL">ALL PROTOCOLS</option>
                      <option value="TCP">TCP</option>
                      <option value="UDP">UDP</option>
                      <option value="HTTP">HTTP</option>
                      <option value="DNS">DNS</option>
                      <option value="TLS/HTTPS">TLS/HTTPS</option>
                    </select>
                  </div>

                  {/* Packets Table */}
                  <div className="border border-brand-border rounded-lg overflow-x-auto max-h-96">
                    <table className="w-full text-left border-collapse text-xs">
                      <thead className="bg-brand-panel sticky top-0 border-b border-brand-border text-brand-muted text-[10px] uppercase font-bold">
                        <tr>
                          <th className="p-2">#</th>
                          <th className="p-2">Time</th>
                          <th className="p-2">Protocol</th>
                          <th className="p-2">Source</th>
                          <th className="p-2">Destination</th>
                          <th className="p-2">Size</th>
                          <th className="p-2">Summary Info</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-brand-border/40 font-mono text-[11px]">
                        {filteredPcapPackets.map(p => (
                          <tr
                            key={p.id}
                            onClick={() => setSelectedPacket(p)}
                            className={`cursor-pointer transition hover:bg-brand-panel/80 ${
                              selectedPacket?.id === p.id ? 'bg-brand-accent/10 border-l-2 border-brand-accent' : ''
                            }`}
                          >
                            <td className="p-2 font-bold text-brand-muted">{p.id}</td>
                            <td className="p-2 text-brand-muted">{new Date(p.timestamp).toLocaleTimeString()}</td>
                            <td className="p-2 font-bold text-brand-accent">{p.protocol}</td>
                            <td className="p-2 text-cyan-400">{p.srcIp}:{p.srcPort || ''}</td>
                            <td className="p-2 text-emerald-400">{p.dstIp}:{p.dstPort || ''}</td>
                            <td className="p-2 text-brand-muted">{p.size} B</td>
                            <td className="p-2 text-slate-300 truncate max-w-md">{p.summary}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {/* Selected Packet Deep Forensic Inspector */}
                  {selectedPacket && (
                    <div className="bg-brand-card border border-brand-border rounded-xl p-5 font-mono text-xs space-y-4 shadow-xl">
                      
                      {/* Header Title Bar */}
                      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-brand-border/60 pb-3">
                        <div className="flex items-center gap-2">
                          <Layers className="w-4 h-4 text-brand-accent animate-pulse" />
                          <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                            Packet #{selectedPacket.id} Deep Forensic Dissection
                          </h4>
                        </div>
                        <div className="flex items-center gap-2 text-[10px]">
                          <span className="text-brand-accent bg-brand-panel px-2.5 py-1 rounded font-bold border border-brand-border">
                            {selectedPacket.protocol}
                          </span>
                          <span className="text-cyan-400 bg-brand-panel px-2.5 py-1 rounded font-bold border border-brand-border">
                            {selectedPacket.size} Bytes
                          </span>
                          {selectedPacket.tagged && (
                            <span className="text-rose-400 bg-rose-500/10 border border-rose-500/30 px-2.5 py-1 rounded font-bold uppercase">
                              {selectedPacket.tagged}
                            </span>
                          )}
                        </div>
                      </div>

                      {/* AI Natural Language Packet Explanation Box */}
                      <div className="bg-brand-accent/10 border border-brand-accent/30 rounded-lg p-3.5 space-y-1">
                        <div className="flex items-center gap-2 text-brand-accent text-[11px] font-bold uppercase tracking-wider">
                          <Eye className="w-3.5 h-3.5" />
                          Automated Packet Analysis & Forensic Explanation
                        </div>
                        <p className="text-xs text-slate-200 leading-relaxed font-sans">
                          {selectedPacket.packetExplanation || `${selectedPacket.direction === 'INCOMING' ? 'Inbound' : 'Outbound'} ${selectedPacket.protocol} packet between ${selectedPacket.srcIp}:${selectedPacket.srcPort || 0} and ${selectedPacket.dstIp}:${selectedPacket.dstPort || 0}. Wire length: ${selectedPacket.size} bytes.`}
                        </p>
                      </div>

                      {/* 4-Tuple Endpoint Summary */}
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 bg-brand-panel p-3 rounded-lg border border-brand-border text-[11px]">
                        <div>Source Host: <strong className="text-cyan-400 block">{selectedPacket.srcIp}:{selectedPacket.srcPort || 0}</strong></div>
                        <div>Destination Target: <strong className="text-emerald-400 block">{selectedPacket.dstIp}:{selectedPacket.dstPort || 0}</strong></div>
                        <div>Ethernet Src MAC: <strong className="text-slate-300 block">{selectedPacket.macSrc}</strong></div>
                        <div>Ethernet Dst MAC: <strong className="text-slate-300 block">{selectedPacket.macDst}</strong></div>
                      </div>

                      {/* Expandable Protocol Layer Tree (Wireshark-style) */}
                      <div className="space-y-2">
                        <span className="text-[10px] text-brand-muted uppercase font-bold tracking-wider block">
                          Wireshark Protocol Tree Dissection ({selectedPacket.layerDetails?.length || 4} Layers)
                        </span>

                        <div className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
                          {(selectedPacket.layerDetails || [
                            {
                              layer: 'FRAME',
                              title: `Frame ${selectedPacket.id}: ${selectedPacket.size} bytes on wire, ${selectedPacket.size} bytes captured`,
                              fields: [
                                { name: 'Arrival Time', value: selectedPacket.timestamp },
                                { name: 'Frame Length', value: `${selectedPacket.size} bytes` },
                                { name: 'Capture Length', value: `${selectedPacket.size} bytes` }
                              ]
                            },
                            {
                              layer: 'ETHERNET',
                              title: `Ethernet II, Src: ${selectedPacket.macSrc}, Dst: ${selectedPacket.macDst}`,
                              fields: [
                                { name: 'Destination MAC', value: selectedPacket.macDst },
                                { name: 'Source MAC', value: selectedPacket.macSrc },
                                { name: 'Type', value: 'IPv4 (0x0800)' }
                              ]
                            },
                            {
                              layer: 'IP',
                              title: `Internet Protocol Version 4, Src: ${selectedPacket.srcIp}, Dst: ${selectedPacket.dstIp}`,
                              fields: [
                                { name: 'Version', value: '4' },
                                { name: 'Header Length', value: '20 bytes' },
                                { name: 'Total Length', value: `${selectedPacket.size} bytes` },
                                { name: 'TTL', value: `${selectedPacket.ttl || 64}` },
                                { name: 'Protocol', value: selectedPacket.protocol },
                                { name: 'Checksum', value: selectedPacket.checksum }
                              ]
                            },
                            {
                              layer: 'TRANSPORT',
                              title: `${selectedPacket.protocol} Transport Layer, Src Port: ${selectedPacket.srcPort || 0}, Dst Port: ${selectedPacket.dstPort || 0}`,
                              fields: [
                                { name: 'Source Port', value: `${selectedPacket.srcPort || 0}` },
                                { name: 'Destination Port', value: `${selectedPacket.dstPort || 0}` },
                                ...(selectedPacket.tcpFlags ? [{ name: 'TCP Flags', value: selectedPacket.tcpFlags }] : [])
                              ]
                            }
                          ]).map((layer, idx) => (
                            <details key={idx} open className="bg-brand-panel border border-brand-border/80 rounded p-2.5 text-[11px] group">
                              <summary className="font-bold text-slate-200 cursor-pointer hover:text-brand-accent transition flex items-center justify-between">
                                <span>▶ {layer.title}</span>
                                <span className="text-[9px] bg-brand-card text-brand-muted px-1.5 py-0.5 rounded border border-brand-border">{layer.layer}</span>
                              </summary>
                              <div className="mt-2 pl-4 space-y-1 border-l border-brand-border/60 text-brand-muted">
                                {layer.fields.map((f: any, fIdx: number) => (
                                  <div key={fIdx} className="flex items-center justify-between py-0.5">
                                    <span>{f.name}:</span>
                                    <span className="text-white font-mono">{f.value} {f.note ? `<${f.note}>` : ''}</span>
                                  </div>
                                ))}
                              </div>
                            </details>
                          ))}
                        </div>
                      </div>

                      {/* Raw Hex & ASCII Payload Dissection Viewer */}
                      <div className="space-y-1.5 pt-2">
                        <div className="flex items-center justify-between text-[10px] text-brand-muted uppercase font-bold">
                          <span>Raw Application Payload (Hex & ASCII Dump)</span>
                          <span>{selectedPacket.payloadSize || Math.max(0, selectedPacket.size - 54)} Bytes Payload</span>
                        </div>
                        <div className="bg-black border border-brand-border rounded p-3 text-[10px] text-emerald-400 font-mono overflow-x-auto whitespace-pre leading-relaxed shadow-inner">
                          {selectedPacket.payloadHex ? (
                            <div>
                              <div className="text-slate-500 pb-1 border-b border-slate-800 mb-1">
                                OFFSET  00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   ASCII DECODE
                              </div>
                              {selectedPacket.payloadHex.split(' ').reduce((acc: string[][], byte: string, idx: number) => {
                                const lineIdx = Math.floor(idx / 16);
                                if (!acc[lineIdx]) acc[lineIdx] = [];
                                acc[lineIdx].push(byte);
                                return acc;
                              }, []).map((chunk: string[], chunkIdx: number) => {
                                const offset = (chunkIdx * 16).toString(16).padStart(4, '0');
                                const hexPart = chunk.join(' ').padEnd(47, ' ');
                                const asciiPart = chunk.map(h => {
                                  const code = parseInt(h, 16);
                                  return (code >= 32 && code <= 126) ? String.fromCharCode(code) : '.';
                                }).join('');
                                return (
                                  <div key={chunkIdx}>
                                    <span className="text-cyan-600">{offset}</span>  {hexPart}  <span className="text-amber-300">{asciiPart}</span>
                                  </div>
                                );
                              })}
                            </div>
                          ) : (
                            <div className="text-slate-400">
                              [PAYLOAD SUMMARY]: {selectedPacket.summary}
                            </div>
                          )}
                        </div>
                      </div>

                    </div>
                  )}


                </div>
              )}

              {/* TAB 3: TOP HOST TALKERS */}
              {activeSubTab === 'TALKERS' && (
                <div className="border border-brand-border rounded-lg overflow-x-auto">
                  <table className="w-full text-left border-collapse text-xs font-mono">
                    <thead className="bg-brand-panel border-b border-brand-border text-brand-muted text-[10px] uppercase font-bold">
                      <tr>
                        <th className="p-3">Host IP Address</th>
                        <th className="p-3">Role</th>
                        <th className="p-3">Total Packets</th>
                        <th className="p-3">Traffic Volume</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-brand-border/40 text-[11px]">
                      {report.topTalkers.map((t, idx) => (
                        <tr key={idx} className="hover:bg-brand-panel/60">
                          <td className="p-3 font-bold text-cyan-400">{t.ip}</td>
                          <td className="p-3">
                            <span className="text-[10px] px-2 py-0.5 bg-brand-panel border border-brand-border rounded font-bold">
                              {t.role}
                            </span>
                          </td>
                          <td className="p-3 text-white font-bold">{t.packets.toLocaleString()}</td>
                          <td className="p-3 text-emerald-400 font-bold">{(t.bytes / 1024).toFixed(1)} KB</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

            </div>
          </div>

        </div>
      )}

    </div>
  );
};
