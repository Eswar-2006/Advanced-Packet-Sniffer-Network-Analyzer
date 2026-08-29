import React, { useState } from 'react';
import { Packet, SecurityAlert, SnifferStats } from '../types';
import { INITIAL_PACKETS } from '../mockData';
import { Activity, ShieldAlert, FileText, CheckCircle, AlertTriangle, Play, HelpCircle, Terminal, Copy, Check, Download, Trash2, Globe, RefreshCw, Cpu } from 'lucide-react';

interface SecurityPanelProps {
  alerts: SecurityAlert[];
  packets: Packet[];
  onAddPacket: (p: Packet) => void;
  onAddAlert: (a: SecurityAlert) => void;
  onSwitchTab?: (tab: 'DASHBOARD' | 'PACKETS' | 'TRAFFIC' | 'SECURITY' | 'SOURCE' | 'COPILOT' | 'DOCS' | 'TOOLS') => void;
}

export const SecurityPanel: React.FC<SecurityPanelProps> = ({ alerts, packets, onAddPacket, onAddAlert, onSwitchTab }) => {
  const [analyzing, setAnalyzing] = useState(false);
  const [selectedThreatType, setSelectedThreatType] = useState('Port Scan');
  const [customSrcIp, setCustomSrcIp] = useState('192.168.1.109');
  const [customDstIp, setCustomDstIp] = useState('192.168.1.15');

  const [activeSubTab, setActiveSubTab] = useState<'IDS' | 'NMAP' | 'SCAPY'>('IDS');

  // Nmap Scan State
  const [nmapTarget, setNmapTarget] = useState('127.0.0.1');
  const [nmapFlags, setNmapFlags] = useState('-F');
  const [nmapOutput, setNmapOutput] = useState('');
  const [nmapRunning, setNmapRunning] = useState(false);
  const [nmapCopied, setNmapCopied] = useState(false);
  const [nmapMeta, setNmapMeta] = useState<{ command?: string; durationMs?: number; binary?: string; success?: boolean } | null>(null);
  const [nmapElapsed, setNmapElapsed] = useState(0);

  // Scapy Craft State
  const [scapyProto, setScapyProto] = useState('TCP');
  const [scapySrcIp, setScapySrcIp] = useState('127.0.0.1');
  const [scapyDstIp, setScapyDstIp] = useState('127.0.0.1');
  const [scapySrcPort, setScapySrcPort] = useState('4444');
  const [scapyDstPort, setScapyDstPort] = useState('80');
  const [scapyPayload, setScapyPayload] = useState('Hello from real Scapy!');
  const [scapySuccessMsg, setScapySuccessMsg] = useState('');
  const [scapyErrorMsg, setScapyErrorMsg] = useState('');
  const [scapySending, setScapySending] = useState(false);

  // Triggering real backend simulation attacks
  const simulateAttack = async () => {
    setAnalyzing(true);
    let mappedType = 'PORT_SCAN';
    if (selectedThreatType === 'SQL Injection') mappedType = 'SQL_INJECTION';
    else if (selectedThreatType === 'XSS Script Injection') mappedType = 'XSS_ATTACK';
    else if (selectedThreatType === 'TCP SYN Flood') mappedType = 'SYN_FLOOD';
    else if (selectedThreatType === 'SSH Brute Force') mappedType = 'SSH_BRUTE_FORCE';
    else if (selectedThreatType === 'DNS Tunneling') mappedType = 'DNS_C2_EXFIL';

    try {
      const res = await fetch('/api/simulate-attack', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          attackType: mappedType,
          targetIp: customDstIp,
          attackerIp: customSrcIp
        })
      });
      const data = await res.json();
      if (data.success && data.result) {
        if (data.result.packets) {
          data.result.packets.forEach((p: Packet) => onAddPacket(p));
        }
        if (data.result.alert) {
          onAddAlert(data.result.alert);
        }
      }
    } catch (err) {
      console.error("Failed to execute live attack simulation:", err);
    } finally {
      setAnalyzing(false);
    }
  };


  // Run Real Nmap Scan
  const handleNmapScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setNmapRunning(true);
    setNmapElapsed(0);
    setNmapMeta(null);
    setNmapOutput(`[+] Initializing Kali Nmap Audit on target: ${nmapTarget}\n[+] Parameters: ${nmapFlags}\n[+] Probe packets dispatched in real-time... Stand by.\n\n`);

    const timer = setInterval(() => {
      setNmapElapsed((prev) => +(prev + 0.1).toFixed(1));
    }, 100);

    try {
      const res = await fetch('/api/run-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: nmapTarget, flags: nmapFlags })
      });
      const data = await res.json();
      setNmapMeta({
        command: data.command,
        durationMs: data.durationMs,
        binary: data.binary,
        success: data.success
      });

      if (data.success) {
        setNmapOutput(data.stdout || '[!] Scan completed with no terminal output.');
      } else {
        setNmapOutput(`[-] Error executing scan:\n${data.stderr || data.stdout || 'Scan failed or binary unavailable.'}`);
      }
    } catch (err: any) {
      setNmapOutput(`[-] Connection error communicating with backend:\n${err.message || err}`);
    } finally {
      clearInterval(timer);
      setNmapRunning(false);
    }
  };

  const copyNmapOutput = () => {
    if (!nmapOutput) return;
    navigator.clipboard.writeText(nmapOutput);
    setNmapCopied(true);
    setTimeout(() => setNmapCopied(false), 2000);
  };

  const clearNmapOutput = () => {
    setNmapOutput('');
    setNmapMeta(null);
  };

  const downloadNmapOutput = () => {
    if (!nmapOutput) return;
    const blob = new Blob([nmapOutput], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `nmap_scan_${nmapTarget.replace(/[^a-zA-Z0-9.-]/g, '_')}_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Craft packet via Real Scapy
  const handleScapySend = async (e: React.FormEvent) => {
    e.preventDefault();
    setScapySending(true);
    setScapySuccessMsg('');
    setScapyErrorMsg('');
    try {
      const res = await fetch('/api/scapy-craft', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          srcIp: scapySrcIp,
          dstIp: scapyDstIp,
          protocol: scapyProto,
          payload: scapyPayload,
          srcPort: parseInt(scapySrcPort),
          dstPort: parseInt(scapyDstPort)
        })
      });
      const data = await res.json();
      if (data.success) {
        setScapySuccessMsg(data.stdout || 'Packet successfully crafted and injected!');
        // Inject a localized trigger alert if crafted from non-standard IP
        if (scapySrcIp !== '127.0.0.1') {
          onAddAlert({
            id: `alert_scapy_${Date.now()}`,
            timestamp: new Date().toISOString(),
            severity: 'MEDIUM',
            type: 'Injected Packet Vector',
            source: scapySrcIp,
            destination: scapyDstIp,
            message: `Scapy security suite injected customized ${scapyProto} payload: "${scapyPayload}" into target subnet. Heuristics logging active.`,
            resolved: false
          });
        }
      } else {
        setScapyErrorMsg(data.stderr || data.stdout || 'Error crafting packet via Scapy.');
      }
    } catch (err: any) {
      setScapyErrorMsg(`Connection error: ${err.message || err}`);
    } finally {
      setScapySending(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Sub tabs selector */}
      <div className="flex border-b border-brand-border">
        <button
          onClick={() => setActiveSubTab('IDS')}
          className={`px-4 py-2 text-xs font-mono font-bold tracking-wider cursor-pointer border-b-2 transition ${
            activeSubTab === 'IDS' ? 'border-brand-accent text-brand-accent' : 'border-transparent text-brand-muted hover:text-white'
          }`}
        >
          IDS ATTACK SIMULATOR
        </button>
        <button
          onClick={() => setActiveSubTab('NMAP')}
          className={`px-4 py-2 text-xs font-mono font-bold tracking-wider cursor-pointer border-b-2 transition ${
            activeSubTab === 'NMAP' ? 'border-brand-accent text-brand-accent' : 'border-transparent text-brand-muted hover:text-white'
          }`}
        >
          REAL KALI NMAP SCANNER
        </button>
        <button
          onClick={() => setActiveSubTab('SCAPY')}
          className={`px-4 py-2 text-xs font-mono font-bold tracking-wider cursor-pointer border-b-2 transition ${
            activeSubTab === 'SCAPY' ? 'border-brand-accent text-brand-accent' : 'border-transparent text-brand-muted hover:text-white'
          }`}
        >
          SCAPY PACKET CRAFTER
        </button>
      </div>

      {activeSubTab === 'IDS' && (
        <div className="space-y-6">
          {/* Simulation Board */}
          <div className="bg-brand-card border border-brand-border rounded p-5 relative overflow-hidden">
            <div className="absolute top-0 right-0 w-20 h-20 bg-brand-danger/5 rounded-bl-full"></div>
            <h3 className="text-xs font-semibold tracking-wide text-brand-muted uppercase flex items-center gap-2 mb-3">
              <ShieldAlert className="w-4 h-4 text-brand-danger animate-pulse" />
              Cybersecurity Threat & Intrusion Simulator
            </h3>
            <p className="text-xs text-brand-muted mb-4 leading-relaxed">
              Trigger real-time advanced network attacks to validate the platform's multi-layered heuristic IDS, deep-packet parsing rule sets, and machine learning anomaly detection.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
              <div>
                <label className="block text-[10px] uppercase font-bold text-brand-dim mb-1 font-mono">Select Threat Vector</label>
                <select
                  value={selectedThreatType}
                  onChange={(e) => setSelectedThreatType(e.target.value)}
                  className="w-full text-xs bg-brand-panel border border-brand-border text-brand-text rounded p-2 focus:border-brand-accent outline-none"
                >
                  <option value="Port Scan">SYN Port Sweep / Scan Probe</option>
                  <option value="SQL Injection">Web App SQL Injection Vector</option>
                  <option value="XSS Script Injection">Reflected XSS Cookie Theft Exploit</option>
                  <option value="TCP SYN Flood">TCP SYN Flood DoS Attack</option>
                  <option value="SSH Brute Force">SSH Password Auth Brute Force</option>
                  <option value="DNS Tunneling">DNS Covert C2 Exfiltration Probe</option>
                </select>

              </div>

              <div>
                <label className="block text-[10px] uppercase font-bold text-brand-dim mb-1 font-mono">Source IP / Host Address</label>
                <input
                  type="text"
                  value={customSrcIp}
                  onChange={(e) => setCustomSrcIp(e.target.value)}
                  className="w-full text-xs bg-brand-panel border border-brand-border text-brand-text rounded p-2 focus:border-brand-accent outline-none"
                />
              </div>

              <div>
                <label className="block text-[10px] uppercase font-bold text-brand-dim mb-1 font-mono">Destination Target IP</label>
                <input
                  type="text"
                  value={customDstIp}
                  onChange={(e) => setCustomDstIp(e.target.value)}
                  className="w-full text-xs bg-brand-panel border border-brand-border text-brand-text rounded p-2 focus:border-brand-accent outline-none"
                />
              </div>

              <div>
                <button
                  onClick={simulateAttack}
                  disabled={analyzing}
                  className="w-full text-xs bg-brand-danger/10 hover:bg-brand-danger/20 text-brand-danger border border-brand-danger/30 rounded p-2 flex items-center justify-center gap-2 transition duration-200 disabled:opacity-50 font-bold uppercase tracking-wider cursor-pointer"
                >
                  {analyzing ? (
                    <div className="w-3.5 h-3.5 border-2 border-brand-danger border-t-transparent rounded-full animate-spin"></div>
                  ) : (
                    <Play className="w-3.5 h-3.5 fill-current" />
                  )}
                  Inject Intrusion Vector
                </button>
              </div>
            </div>
          </div>

          {/* Live Alerts List */}
          <div className="space-y-3">
            <h3 className="text-xs font-semibold text-brand-muted uppercase tracking-wider font-mono">
              Active Intrusion Incidents ({alerts.length})
            </h3>

            {alerts.length === 0 ? (
              <div className="bg-brand-card border border-brand-border rounded p-8 text-center text-brand-muted">
                <CheckCircle className="w-8 h-8 text-emerald-500 mx-auto mb-2" />
                <span className="text-xs">No cyber-threats or network anomalies actively registered.</span>
              </div>
            ) : (
              <div className="space-y-3 max-h-[380px] overflow-y-auto pr-1">
                {alerts.map((alert) => (
                  <div
                    key={alert.id}
                    className={`border rounded p-4 transition-all duration-200 ${
                      alert.severity === 'CRITICAL'
                        ? 'bg-brand-danger/10 border-brand-danger/30'
                        : alert.severity === 'HIGH'
                        ? 'bg-brand-danger/5 border-brand-danger/20'
                        : 'bg-brand-panel border-brand-border'
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex gap-2">
                        <AlertTriangle className={`w-4 h-4 mt-0.5 shrink-0 ${
                          alert.severity === 'CRITICAL' ? 'text-brand-danger' : 'text-amber-500'
                        }`} />
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-bold text-white">{alert.type}</span>
                            <span className={`text-[9px] px-1.5 py-0.5 rounded font-mono font-bold border ${
                              alert.severity === 'CRITICAL'
                                ? 'bg-brand-danger/20 text-brand-danger border-brand-danger/30'
                                : alert.severity === 'HIGH'
                                ? 'bg-amber-500/10 text-amber-500 border-amber-500/20'
                                : 'bg-brand-panel text-brand-muted border-brand-border'
                            }`}>
                              {alert.severity}
                            </span>
                          </div>
                          <div className="text-[10px] text-brand-muted font-mono mt-1">
                            Path: {alert.source} &rarr; {alert.destination}
                          </div>
                          <p className="text-xs text-brand-text mt-2 leading-relaxed">
                            {alert.message}
                          </p>
                        </div>
                      </div>

                      <span className="text-[10px] text-brand-dim font-mono">
                        {new Date(alert.timestamp).toLocaleTimeString()}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {activeSubTab === 'NMAP' && (
        <div className="bg-brand-card border border-brand-border rounded p-5 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-brand-border pb-3">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-wider text-brand-muted flex items-center gap-2">
                <Activity className="w-4 h-4 text-brand-accent" />
                Live Host & Port Audits via Real Kali Nmap Suite
              </h3>
              <p className="text-xs text-brand-muted mt-1">
                Executes native host and port audits directly via the local/container Nmap binary with complete protocol probing.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-mono text-[11px] font-semibold">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                Nmap Engine Active
              </span>
            </div>
          </div>

          {/* Quick Target Chips */}
          <div>
            <span className="block text-[10px] uppercase font-bold text-brand-dim mb-1.5 font-mono">Quick Target Selectors</span>
            <div className="flex flex-wrap gap-2">
              {[
                { label: '127.0.0.1 (Localhost)', value: '127.0.0.1' },
                { label: 'localhost', value: 'localhost' },
                { label: '192.168.1.1 (Gateway)', value: '192.168.1.1' },
                { label: 'scanme.nmap.org (Official Testbed)', value: 'scanme.nmap.org' }
              ].map(t => (
                <button
                  key={t.value}
                  type="button"
                  onClick={() => setNmapTarget(t.value)}
                  className={`text-[11px] font-mono px-2.5 py-1 rounded border transition cursor-pointer ${
                    nmapTarget === t.value
                      ? 'bg-brand-accent/20 border-brand-accent text-brand-accent font-bold'
                      : 'bg-brand-panel border-brand-border text-brand-muted hover:text-white hover:border-brand-accent/50'
                  }`}
                >
                  <Globe className="w-3 h-3 inline mr-1 opacity-70" />
                  {t.label}
                </button>
              ))}
            </div>
          </div>

          {/* Quick Preset Scan Strategies */}
          <div>
            <span className="block text-[10px] uppercase font-bold text-brand-dim mb-1.5 font-mono">Audit Presets & Strategies</span>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {[
                { name: 'Fast Port Scan', flags: '-F', desc: 'Top 100 ports' },
                { name: 'TCP Connect Audit', flags: '-sT -F', desc: 'Full 3-way handshake' },
                { name: 'Service Banners', flags: '-sV -p 80,443,3000,5432,8080', desc: 'Version identification' },
                { name: 'Top 100 Ports', flags: '--top-ports 100', desc: 'Top 100 common ports' },
                { name: 'Heuristic OS Scan', flags: '-O -F', desc: 'OS fingerprinting' },
                { name: 'Aggressive Audit', flags: '-A -T4 -F', desc: 'OS, version, traceroute' },
                { name: 'Host Discovery (Ping)', flags: '-sn', desc: 'ICMP/ARP ping sweep' },
                { name: 'Vulnerability Probes', flags: '--script vuln -F', desc: 'NSE vulnerability checks' }
              ].map(p => (
                <button
                  key={p.name}
                  type="button"
                  onClick={() => setNmapFlags(p.flags)}
                  className={`text-left p-2 rounded border transition text-xs cursor-pointer ${
                    nmapFlags === p.flags
                      ? 'bg-brand-accent/15 border-brand-accent text-white'
                      : 'bg-brand-panel border-brand-border text-brand-muted hover:text-white hover:border-brand-accent/40'
                  }`}
                >
                  <div className="font-bold font-mono text-[11px] text-brand-accent flex items-center justify-between">
                    {p.name}
                    {nmapFlags === p.flags && <Check className="w-3 h-3 text-brand-accent" />}
                  </div>
                  <div className="text-[10px] font-mono text-brand-dim mt-0.5 truncate">{p.flags}</div>
                </button>
              ))}
            </div>
          </div>

          <form onSubmit={handleNmapScan} className="grid grid-cols-1 md:grid-cols-12 gap-4 items-end bg-brand-panel p-4 rounded border border-brand-border">
            <div className="md:col-span-5">
              <label className="block text-[10px] uppercase font-bold text-brand-dim mb-1 font-mono">Target Host / IP / Subnet CIDR</label>
              <input
                type="text"
                required
                value={nmapTarget}
                onChange={(e) => setNmapTarget(e.target.value)}
                placeholder="e.g. 127.0.0.1, 192.168.1.0/24, scanme.nmap.org"
                className="w-full text-xs bg-brand-card border border-brand-border text-brand-text rounded p-2.5 focus:border-brand-accent outline-none font-mono"
              />
            </div>

            <div className="md:col-span-4">
              <label className="block text-[10px] uppercase font-bold text-brand-dim mb-1 font-mono">Nmap Scan Arguments & Flags</label>
              <input
                type="text"
                required
                value={nmapFlags}
                onChange={(e) => setNmapFlags(e.target.value)}
                placeholder="e.g. -F, -sV -p 80,443, -sT, -O"
                className="w-full text-xs bg-brand-card border border-brand-border text-brand-text rounded p-2.5 focus:border-brand-accent outline-none font-mono"
              />
            </div>

            <div className="md:col-span-3">
              <button
                type="submit"
                disabled={nmapRunning}
                className="w-full text-xs bg-brand-accent hover:bg-brand-accent-hover text-brand-panel font-bold rounded p-2.5 flex items-center justify-center gap-2 transition duration-200 disabled:opacity-50 cursor-pointer uppercase font-mono shadow-md shadow-brand-accent/20"
              >
                {nmapRunning ? (
                  <>
                    <div className="w-3.5 h-3.5 border-2 border-brand-panel border-t-transparent rounded-full animate-spin"></div>
                    <span>Auditing ({nmapElapsed}s)...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5" />
                    <span>Launch Nmap Scan</span>
                  </>
                )}
              </button>
            </div>
          </form>

          {/* Live Command Preview */}
          <div className="flex items-center gap-2 px-3 py-2 bg-black/60 rounded border border-brand-border/80 font-mono text-[11px]">
            <Terminal className="w-3.5 h-3.5 text-brand-accent flex-shrink-0" />
            <span className="text-brand-dim select-none">$</span>
            <span className="text-emerald-400 font-semibold">nmap {nmapFlags} {nmapTarget}</span>
          </div>

          {/* Terminal Console */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-[10px] uppercase font-bold text-brand-dim font-mono flex items-center gap-1.5">
                  <Terminal className="w-3 h-3 text-brand-accent" />
                  Nmap Interactive Terminal Console
                </span>
                {nmapRunning && (
                  <span className="text-[10px] text-brand-accent font-mono animate-pulse">
                    ● Audit in progress ({nmapElapsed}s)
                  </span>
                )}
              </div>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={copyNmapOutput}
                  disabled={!nmapOutput}
                  className="text-[10px] font-mono px-2 py-1 bg-brand-panel hover:bg-brand-border text-brand-muted hover:text-white rounded border border-brand-border flex items-center gap-1 disabled:opacity-30 cursor-pointer"
                >
                  {nmapCopied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  {nmapCopied ? 'Copied' : 'Copy'}
                </button>
                <button
                  type="button"
                  onClick={downloadNmapOutput}
                  disabled={!nmapOutput}
                  className="text-[10px] font-mono px-2 py-1 bg-brand-panel hover:bg-brand-border text-brand-muted hover:text-white rounded border border-brand-border flex items-center gap-1 disabled:opacity-30 cursor-pointer"
                >
                  <Download className="w-3 h-3" />
                  Export Log
                </button>
                <button
                  type="button"
                  onClick={clearNmapOutput}
                  disabled={!nmapOutput}
                  className="text-[10px] font-mono px-2 py-1 bg-brand-panel hover:bg-brand-border text-brand-muted hover:text-red-400 rounded border border-brand-border flex items-center gap-1 disabled:opacity-30 cursor-pointer"
                >
                  <Trash2 className="w-3 h-3" />
                  Clear
                </button>
              </div>
            </div>

            <pre className="w-full h-80 bg-black border border-brand-border rounded p-4 text-[11px] text-emerald-400 font-mono overflow-auto whitespace-pre leading-relaxed shadow-inner selection:bg-emerald-800 selection:text-white">
              {nmapOutput || "# Kali Nmap Engine Ready.\n# Select a strategy above or enter custom parameters, then click 'Launch Nmap Scan'."}
            </pre>

            {nmapMeta && (
              <div className="flex flex-wrap items-center justify-between gap-2 px-3 py-1.5 bg-brand-panel border border-brand-border rounded text-[10px] font-mono text-brand-muted">
                <div className="flex items-center gap-3">
                  <span>Status: <strong className={nmapMeta.success ? "text-emerald-400" : "text-amber-400"}>{nmapMeta.success ? "Execution Finished" : "Completed with notice"}</strong></span>
                  {nmapMeta.durationMs !== undefined && (
                    <span>Duration: <strong className="text-white">{(nmapMeta.durationMs / 1000).toFixed(2)}s</strong></span>
                  )}
                </div>
                {nmapMeta.command && (
                  <div className="truncate text-brand-dim">
                    Cmd: <span className="text-brand-text">{nmapMeta.command}</span>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {activeSubTab === 'SCAPY' && (
        <div className="bg-brand-card border border-brand-border rounded p-5 space-y-4">
          <div className="border-b border-brand-border pb-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-brand-muted flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-brand-accent" />
              Low-Level Packet Crafting & Injection via Real Scapy Engine
            </h3>
            <p className="text-xs text-brand-muted mt-1">
              Assemble low-level protocol headers dynamically. Real Scapy engine compiles the parameters, generates standard sockets, and pushes the crafted segments to local loopback buffers.
            </p>
          </div>

          <form onSubmit={handleScapySend} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="block text-[10px] uppercase font-bold text-brand-dim mb-1 font-mono">Header Protocol</label>
                <select
                  value={scapyProto}
                  onChange={(e) => setScapyProto(e.target.value)}
                  className="w-full text-xs bg-brand-panel border border-brand-border text-brand-text rounded p-2 focus:border-brand-accent outline-none font-mono"
                >
                  <option value="TCP">TCP Segment Builder</option>
                  <option value="UDP">UDP Datagram Builder</option>
                  <option value="RAW">Raw IP Layer Payload</option>
                </select>
              </div>

              <div>
                <label className="block text-[10px] uppercase font-bold text-brand-dim mb-1 font-mono">Spoofed Source IP</label>
                <input
                  type="text"
                  required
                  value={scapySrcIp}
                  onChange={(e) => setScapySrcIp(e.target.value)}
                  className="w-full text-xs bg-brand-panel border border-brand-border text-brand-text rounded p-2 focus:border-brand-accent outline-none font-mono"
                />
              </div>

              <div>
                <label className="block text-[10px] uppercase font-bold text-brand-dim mb-1 font-mono">Target Destination IP</label>
                <input
                  type="text"
                  required
                  value={scapyDstIp}
                  onChange={(e) => setScapyDstIp(e.target.value)}
                  className="w-full text-xs bg-brand-panel border border-brand-border text-brand-text rounded p-2 focus:border-brand-accent outline-none font-mono"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="block text-[10px] uppercase font-bold text-brand-dim mb-1 font-mono">Source Port</label>
                <input
                  type="text"
                  required
                  value={scapySrcPort}
                  onChange={(e) => setScapySrcPort(e.target.value)}
                  className="w-full text-xs bg-brand-panel border border-brand-border text-brand-text rounded p-2 focus:border-brand-accent outline-none font-mono"
                />
              </div>

              <div>
                <label className="block text-[10px] uppercase font-bold text-brand-dim mb-1 font-mono">Destination Port</label>
                <input
                  type="text"
                  required
                  value={scapyDstPort}
                  onChange={(e) => setScapyDstPort(e.target.value)}
                  className="w-full text-xs bg-brand-panel border border-brand-border text-brand-text rounded p-2 focus:border-brand-accent outline-none font-mono"
                />
              </div>

              <div>
                <label className="block text-[10px] uppercase font-bold text-brand-dim mb-1 font-mono">Text Payload</label>
                <input
                  type="text"
                  required
                  value={scapyPayload}
                  onChange={(e) => setScapyPayload(e.target.value)}
                  className="w-full text-xs bg-brand-panel border border-brand-border text-brand-text rounded p-2 focus:border-brand-accent outline-none font-mono"
                />
              </div>
            </div>

            <div className="pt-2">
              <button
                type="submit"
                disabled={scapySending}
                className="w-full md:w-auto px-6 py-2.5 text-xs bg-brand-danger hover:bg-red-700 text-white font-bold rounded flex items-center justify-center gap-2 transition duration-200 disabled:opacity-50 cursor-pointer uppercase font-mono"
              >
                {scapySending ? (
                  <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                ) : (
                  <Play className="w-3.5 h-3.5" />
                )}
                Compile & Inject with Scapy
              </button>
            </div>
          </form>

          {scapySuccessMsg && (
            <div className="space-y-3 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 p-4 rounded text-[11px] font-mono whitespace-pre-line animate-fadeIn">
              <div>{scapySuccessMsg}</div>
              {onSwitchTab && (
                <button
                  type="button"
                  onClick={() => onSwitchTab('PACKETS')}
                  className="px-3 py-1.5 bg-emerald-500/20 hover:bg-emerald-500/30 border border-emerald-500/40 text-emerald-300 hover:text-emerald-200 text-[10px] font-bold rounded cursor-pointer uppercase transition"
                >
                  Go to Packet Inspector &rarr;
                </button>
              )}
            </div>
          )}

          {scapyErrorMsg && (
            <div className="bg-brand-danger/10 border border-brand-danger/30 text-brand-danger p-3 rounded text-[11px] font-mono whitespace-pre-line animate-fadeIn">
              {scapyErrorMsg}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
