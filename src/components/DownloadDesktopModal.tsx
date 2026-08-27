import React, { useState } from 'react';
import {
  Download,
  Laptop,
  Terminal,
  Copy,
  Check,
  ShieldCheck,
  Wifi,
  Globe,
  Cpu,
  Layers,
  X,
  ExternalLink,
  Play,
  Server,
  ArrowRight,
  Monitor
} from 'lucide-react';

interface DownloadDesktopModalProps {
  isOpen: boolean;
  onClose: () => void;
  serverUrl?: string;
  isLocalAgentConnected?: boolean;
}

export const DownloadDesktopModal: React.FC<DownloadDesktopModalProps> = ({
  isOpen,
  onClose,
  serverUrl = typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000',
  isLocalAgentConnected = false
}) => {
  const [activeTab, setActiveTab] = useState<'desktop' | 'agent'>('desktop');
  const [copiedCmd, setCopiedCmd] = useState<string | null>(null);

  if (!isOpen) return null;

  const agentCommand = `npx tsx agent/index.ts --server ${serverUrl}`;
  const npmAgentCommand = `npm run start:agent`;

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCmd(label);
    setTimeout(() => setCopiedCmd(null), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-fade-in font-mono">
      <div 
        className="relative w-full max-w-4xl bg-brand-panel border border-brand-border rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]"
        onClick={(e) => e.stopPropagation()}
      >
        
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 bg-brand-card/90 border-b border-brand-border">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Laptop className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                Capture Your Own Local Hardware Packets
                <span className="text-[10px] bg-cyan-500/20 text-cyan-300 px-2 py-0.5 rounded-full border border-cyan-500/40">
                  DUAL-MODE CAPABLE
                </span>
              </h2>
              <p className="text-xs text-brand-muted">
                Run natively on your OS (Option A) or bridge your local Wi-Fi/Ethernet to this Web Dashboard (Option B)
              </p>
            </div>
          </div>
          
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Selector */}
        <div className="flex border-b border-brand-border bg-brand-card/40 px-6 pt-3 gap-2">
          <button
            onClick={() => setActiveTab('desktop')}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-t-lg text-xs font-bold transition-all border-t border-x ${
              activeTab === 'desktop'
                ? 'bg-brand-panel text-cyan-400 border-brand-border border-b-brand-panel -mb-px'
                : 'text-slate-400 border-transparent hover:text-slate-200 hover:bg-slate-800/40'
            }`}
          >
            <Monitor className="w-4 h-4 text-cyan-400" />
            Option A: Download Desktop App
            <span className="text-[9px] bg-emerald-500/10 text-emerald-400 px-1.5 py-0.5 rounded border border-emerald-500/20">
              RECOMMENDED
            </span>
          </button>

          <button
            onClick={() => setActiveTab('agent')}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-t-lg text-xs font-bold transition-all border-t border-x ${
              activeTab === 'agent'
                ? 'bg-brand-panel text-purple-400 border-brand-border border-b-brand-panel -mb-px'
                : 'text-slate-400 border-transparent hover:text-slate-200 hover:bg-slate-800/40'
            }`}
          >
            <Terminal className="w-4 h-4 text-purple-400" />
            Option B: Quick Local Agent Bridge
            {isLocalAgentConnected && (
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping"></span>
            )}
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6">

          {/* Explanation Alert */}
          <div className="p-4 rounded-lg bg-cyan-950/30 border border-cyan-500/30 flex items-start gap-3">
            <ShieldCheck className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
            <div className="text-xs space-y-1">
              <p className="text-cyan-200 font-bold">Why do I need the Desktop App or Agent?</p>
              <p className="text-slate-300 leading-relaxed">
                Standard web browsers block websites from silently sniffing your computer's local Wi-Fi or Ethernet card due to browser security rules.
                Running the **Desktop App** or **Local Agent** grants elevated raw packet capture capabilities (`tshark`/`Npcap`) directly on your machine.
              </p>
            </div>
          </div>

          {activeTab === 'desktop' ? (
            /* Option A Content */
            <div className="space-y-6 animate-fade-in">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                
                {/* Windows Package */}
                <div className="p-5 rounded-xl bg-slate-900/60 border border-brand-border hover:border-cyan-500/50 transition-all flex flex-col justify-between group">
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-bold text-slate-100 flex items-center gap-2">
                        🪟 Windows
                      </span>
                      <span className="text-[10px] bg-cyan-500/20 text-cyan-300 font-bold px-2 py-0.5 rounded border border-cyan-500/40">.EXE Executable</span>
                    </div>
                    <p className="text-xs text-brand-muted leading-relaxed">
                      Downloads standalone `.exe` Desktop App. Double-click to launch your full packet sniffer website natively on Windows.
                    </p>
                  </div>
                  <a
                    href="/api/download/desktop-windows"
                    download="Sentinel-Packet-Sniffer-Desktop.cmd"
                    className="mt-4 w-full py-2.5 px-3 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center justify-center gap-2 transition-all shadow-[0_0_15px_rgba(6,182,212,0.4)] group-hover:scale-[1.02]"
                  >
                    <Download className="w-4 h-4 text-slate-950" />
                    Download Windows (.exe)
                  </a>
                </div>

                {/* macOS Package */}
                <div className="p-5 rounded-xl bg-slate-900/60 border border-brand-border hover:border-cyan-500/50 transition-all flex flex-col justify-between group">
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-bold text-slate-100 flex items-center gap-2">
                        🍎 macOS
                      </span>
                      <span className="text-[10px] bg-purple-500/20 text-purple-300 font-bold px-2 py-0.5 rounded border border-purple-500/40">.DMG Package</span>
                    </div>
                    <p className="text-xs text-brand-muted leading-relaxed">
                      Standalone macOS application bundle for Apple Silicon and Intel macs with `libpcap` dissection engine.
                    </p>
                  </div>
                  <a
                    href="/api/download/desktop-mac"
                    download="Sentinel-Packet-Sniffer.dmg"
                    className="mt-4 w-full py-2.5 px-3 rounded-lg bg-purple-500/20 hover:bg-purple-500/30 text-purple-300 border border-purple-500/40 font-bold text-xs flex items-center justify-center gap-2 transition-all group-hover:scale-[1.02]"
                  >
                    <Download className="w-4 h-4" />
                    Download macOS (.dmg)
                  </a>
                </div>

                {/* Linux Package */}
                <div className="p-5 rounded-xl bg-slate-900/60 border border-brand-border hover:border-cyan-500/50 transition-all flex flex-col justify-between group">
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-bold text-slate-100 flex items-center gap-2">
                        🐧 Linux / Docker
                      </span>
                      <span className="text-[10px] bg-slate-800 text-slate-400 px-2 py-0.5 rounded">AppImage / CLI</span>
                    </div>
                    <p className="text-xs text-brand-muted leading-relaxed">
                      Native `tshark` capture support with root socket binding for Linux security distributions.
                    </p>
                  </div>
                  <a
                    href="/api/download/desktop-linux"
                    download="Sentinel-Packet-Sniffer.AppImage"
                    className="mt-4 w-full py-2.5 px-3 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 font-bold text-xs flex items-center justify-center gap-2 transition-all group-hover:scale-[1.02]"
                  >
                    <Download className="w-4 h-4" />
                    Download Linux AppImage
                  </a>
                </div>

              </div>

              {/* Developer / Run Local Instructions */}
              <div className="p-4 rounded-xl bg-slate-900/80 border border-brand-border space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-200 flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-emerald-400" />
                    Run Desktop App Immediately on Your PC (Developer / Terminal)
                  </span>
                </div>
                <div className="flex items-center justify-between bg-black/60 p-3 rounded-lg border border-slate-800">
                  <code className="text-xs text-emerald-400">npm run dev:electron</code>
                  <button
                    onClick={() => copyToClipboard('npm run dev:electron', 'dev-electron')}
                    className="flex items-center gap-1.5 px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs transition-colors"
                  >
                    {copiedCmd === 'dev-electron' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    {copiedCmd === 'dev-electron' ? 'Copied' : 'Copy'}
                  </button>
                </div>
              </div>
            </div>
          ) : (
            /* Option B Content */
            <div className="space-y-6 animate-fade-in">
              <div className="p-4 rounded-xl bg-purple-950/20 border border-purple-500/30 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-purple-400 animate-ping"></div>
                    <span className="text-xs font-bold text-purple-300 uppercase">
                      Option B: Quick Agent Bridge Command
                    </span>
                  </div>
                  <span className="text-[10px] bg-purple-500/20 text-purple-300 px-2 py-0.5 rounded border border-purple-500/40">
                    STAY ON THIS WEB DASHBOARD
                  </span>
                </div>
                <p className="text-xs text-slate-300">
                  Run this single command in your terminal. It detects your Wi-Fi/Ethernet cards and streams live traffic into **this exact browser window**:
                </p>

                <div className="space-y-2">
                  <div className="flex items-center justify-between bg-black/70 p-3 rounded-lg border border-purple-900/60 font-mono text-xs">
                    <code className="text-purple-300 overflow-x-auto">{npmAgentCommand}</code>
                    <button
                      onClick={() => copyToClipboard(npmAgentCommand, 'agent-npm')}
                      className="flex items-center gap-1.5 px-3 py-1 bg-purple-900/40 hover:bg-purple-800/60 text-purple-200 rounded text-xs transition-colors shrink-0 ml-2"
                    >
                      {copiedCmd === 'agent-npm' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      {copiedCmd === 'agent-npm' ? 'Copied!' : 'Copy'}
                    </button>
                  </div>

                  <div className="flex items-center justify-between bg-black/70 p-3 rounded-lg border border-purple-900/60 font-mono text-xs">
                    <code className="text-purple-300 overflow-x-auto">{agentCommand}</code>
                    <button
                      onClick={() => copyToClipboard(agentCommand, 'agent-cli')}
                      className="flex items-center gap-1.5 px-3 py-1 bg-purple-900/40 hover:bg-purple-800/60 text-purple-200 rounded text-xs transition-colors shrink-0 ml-2"
                    >
                      {copiedCmd === 'agent-cli' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      {copiedCmd === 'agent-cli' ? 'Copied!' : 'Copy NPX'}
                    </button>
                  </div>
                </div>
              </div>

              {/* Status Indicator */}
              <div className="p-4 rounded-xl bg-slate-900/60 border border-brand-border flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className={`w-3 h-3 rounded-full ${isLocalAgentConnected ? 'bg-emerald-500 animate-ping' : 'bg-amber-500'}`}></div>
                  <div>
                    <p className="text-xs font-bold text-slate-200">
                      {isLocalAgentConnected ? 'Local Agent Connected!' : 'Waiting for Local Agent Connection...'}
                    </p>
                    <p className="text-[11px] text-brand-muted">
                      {isLocalAgentConnected
                        ? 'Your local network cards are linked to this web dashboard session.'
                        : 'Run the command above in terminal to see your own Wi-Fi/Ethernet traffic.'}
                    </p>
                  </div>
                </div>
                {isLocalAgentConnected && (
                  <span className="text-xs bg-emerald-500/10 text-emerald-400 px-3 py-1 rounded-full border border-emerald-500/30 font-bold">
                    LIVE STREAMING
                  </span>
                )}
              </div>
            </div>
          )}

        </div>

        {/* Footer */}
        <div className="px-6 py-4 bg-brand-card/90 border-t border-brand-border flex items-center justify-between text-xs">
          <div className="flex items-center gap-2 text-brand-muted">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span>Built with Node.js, Express, WebSocket, Wireshark/tshark & Electron</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold transition-colors"
          >
            Close
          </button>
        </div>

      </div>
    </div>
  );
};
