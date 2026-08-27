import React, { useState } from 'react';
import { DESKTOP_SOURCE_FILES } from '../desktopSource';
import { Terminal, Copy, Check, FileCode } from 'lucide-react';

export const DesktopCodePanel: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState(DESKTOP_SOURCE_FILES[0]);
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(selectedFile.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="space-y-6">
      {/* Overview Banner */}
      <div className="bg-brand-card border border-brand-border rounded p-5 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-20 h-20 bg-brand-accent/5 rounded-bl-full"></div>
        <h3 className="text-xs font-semibold tracking-wide text-brand-muted uppercase flex items-center gap-2 mb-2">
          <Terminal className="w-4 h-4 text-brand-accent" />
          Production-Grade Python PySide6 Source Code
        </h3>
        <p className="text-xs text-brand-muted leading-relaxed">
          The following codes represent the actual enterprise modular Python core system, incorporating the Scapy asynchronous multi-threaded sniffing loop, Thread-safe sqlite pooled datastore managers, and heuristic anomaly hazard scoring.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* File Navigator */}
        <div className="space-y-2 lg:col-span-1">
          <span className="text-[10px] font-bold text-brand-dim uppercase tracking-wider block px-1 mb-2">
            Workspace Tree Structure
          </span>
          {DESKTOP_SOURCE_FILES.map((file) => (
            <button
              key={file.path}
              onClick={() => setSelectedFile(file)}
              className={`w-full text-left text-xs rounded px-3 py-2.5 flex items-center gap-2 border transition-all duration-200 cursor-pointer ${
                selectedFile.path === file.path
                  ? 'bg-brand-panel/60 text-brand-accent border-brand-border-light'
                  : 'bg-brand-card/40 text-brand-muted border-brand-border hover:bg-brand-panel hover:text-brand-text'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" />
              <div className="truncate font-mono">{file.filename}</div>
            </button>
          ))}
        </div>

        {/* Code Viewer */}
        <div className="lg:col-span-3 bg-brand-card border border-brand-border rounded overflow-hidden flex flex-col h-[520px]">
          {/* Header */}
          <div className="bg-brand-panel border-b border-brand-border px-4 py-3 flex items-center justify-between shrink-0">
            <div className="flex items-center gap-2">
              <div className="flex gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-brand-danger/80"></span>
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80"></span>
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80"></span>
              </div>
              <span className="text-[11px] text-brand-muted font-mono ml-2 truncate">
                project/{selectedFile.path}
              </span>
            </div>

            <button
              onClick={handleCopy}
              className="text-[11px] text-brand-muted hover:text-brand-text bg-brand-panel hover:bg-brand-card border border-brand-border hover:border-brand-border-light rounded px-2.5 py-1 flex items-center gap-1.5 transition cursor-pointer font-bold uppercase tracking-wider"
            >
              {copied ? (
                <>
                  <Check className="w-3 h-3 text-emerald-400" />
                  Copied
                </>
              ) : (
                <>
                  <Copy className="w-3 h-3 text-brand-accent" />
                  Copy Core
                </>
              )}
            </button>
          </div>

          {/* Editor Window */}
          <div className="flex-1 overflow-auto p-4 font-mono text-xs text-brand-text leading-relaxed bg-brand-card select-text">
            <pre className="whitespace-pre">{selectedFile.content}</pre>
          </div>
        </div>
      </div>
    </div>
  );
};
