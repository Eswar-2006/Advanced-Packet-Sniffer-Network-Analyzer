import React, { useState } from 'react';
import { Packet, SecurityAlert, SnifferStats } from '../types';
import { INITIAL_PACKETS } from '../mockData';
import { Activity, ShieldAlert, FileText, CheckCircle, AlertTriangle, Play, HelpCircle } from 'lucide-react';

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
    setNmapOutput('Scanning target host in real-time... please stand by.\n');
    try {
      const res = await fetch('/api/run-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: nmapTarget, flags: nmapFlags })
      });
      const data = await res.json();
      if (data.success) {
        setNmapOutput(data.stdout || 'Scan completed with no terminal output.');
      } else {
        setNmapOutput(`Error executing scan:\n${data.stderr || data.stdout}`);
      }
    } catch (err: any) {
      setNmapOutput(`Connection error: ${err.message || err}`);
    } finally {
      setNmapRunning(false);
    }
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
        <div className="bg-brand-card border border-brand-border rounded p-5 space-y-4">
          <div className="border-b border-brand-border pb-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-brand-muted flex items-center gap-2">
              <Activity className="w-4 h-4 text-brand-accent" />
              Live Host & Port Audits via Real Nmap Binary
            </h3>
            <p className="text-xs text-brand-muted mt-1">
              Initiate actual port audits against container networks or localhost target ports. The system makes direct shell executions of the Kali Nmap suite.
            </p>
          </div>

          <form onSubmit={handleNmapScan} className="grid grid-cols-1 md:grid-cols-3 gap-4 items-end">
            <div>
              <label className="block text-[10px] uppercase font-bold text-brand-dim mb-1 font-mono">Scan Target Address / Host</label>
              <input
                type="text"
                required
                value={nmapTarget}
                onChange={(e) => setNmapTarget(e.target.value)}
                placeholder="e.g. 127.0.0.1"
                className="w-full text-xs bg-brand-panel border border-brand-border text-brand-text rounded p-2 focus:border-brand-accent outline-none font-mono"
              />
            </div>

            <div>
              <label className="block text-[10px] uppercase font-bold text-brand-dim mb-1 font-mono">Scan Strategy / Flags</label>
              <select
                value={nmapFlags}
                onChange={(e) => setNmapFlags(e.target.value)}
                className="w-full text-xs bg-brand-panel border border-brand-border text-brand-text rounded p-2 focus:border-brand-accent outline-none font-mono"
              >
                <option value="-F">Fast TCP Port Scan (-F)</option>
                <option value="-sT -F">TCP Connect Port Audit (-sT -F)</option>
                <option value="-sV -p 80,3000">Service Banner Identification (-sV)</option>
                <option value="-O -F">Heuristic OS Identification (-O -F)</option>
              </select>
            </div>

            <div>
              <button
                type="submit"
                disabled={nmapRunning}
                className="w-full text-xs bg-brand-accent hover:bg-brand-accent-hover text-brand-panel font-bold rounded p-2 flex items-center justify-center gap-2 transition duration-200 disabled:opacity-50 cursor-pointer uppercase font-mono"
              >
                {nmapRunning ? (
                  <div className="w-3.5 h-3.5 border-2 border-brand-panel border-t-transparent rounded-full animate-spin"></div>
                ) : (
                  <Play className="w-3.5 h-3.5" />
                )}
                Trigger Nmap Audit
              </button>
            </div>
          </form>

          {/* Terminal Console */}
          <div className="space-y-2">
            <span className="text-[10px] uppercase font-bold text-brand-dim font-mono">Nmap Terminal Standard Output</span>
            <pre className="w-full h-80 bg-black border border-brand-border rounded p-4 text-[10px] text-emerald-400 font-mono overflow-auto whitespace-pre leading-relaxed shadow-inner">
              {nmapOutput || "# Ready. Initiate an audit to print standard Kali terminal output."}
            </pre>
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
