import React from 'react';
import { BookOpen, AlertCircle, Code, Terminal } from 'lucide-react';

export const DocsPanel: React.FC = () => {
  return (
    <div className="space-y-6">
      {/* Intro */}
      <div className="bg-brand-card border border-brand-border rounded p-5 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-20 h-20 bg-brand-accent/5 rounded-bl-full"></div>
        <h3 className="text-xs font-semibold tracking-wide text-brand-muted uppercase flex items-center gap-2 mb-3">
          <BookOpen className="w-4 h-4 text-brand-accent" />
          Technical Design & Portfolio Manual
        </h3>
        <p className="text-xs text-brand-muted leading-relaxed">
          Detailed structural, database, and system interface documentation ready to be showcase on GitHub, university portfolios, or technical interview preparations.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Architecture */}
        <div className="bg-brand-card border border-brand-border rounded p-5 space-y-4">
          <h4 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2 border-b border-brand-border pb-2">
            <Code className="w-4 h-4 text-brand-accent" />
            1. Core System Architecture
          </h4>
          <p className="text-xs text-brand-muted leading-relaxed">
            The platform is structured adhering strictly to SOLID clean-architectural design guidelines. 
          </p>
          <div className="bg-brand-panel p-3.5 rounded border border-brand-border">
            <pre className="text-[10px] text-brand-accent font-mono leading-relaxed whitespace-pre-wrap">
{`+-------------------------------------------------------------+
|                     PYSIDE6 QT DASHBOARD                    |
+-------------------------------------------------------------+
                             |  (Observable / Event State)
                             v
+-------------------------------------------------------------+
|                    TRAFFIC ANALYSIS ENGINE                  |
+-------------------------------------------------------------+
      | (Packet queue stream)               | (Risk Scores)
      v                                     v
+------------------------+            +-----------------------+
|  BACKGROUND SNIFFER   |            |   SECURITY HEURISTICS |
| (Async Scapy Sniff)    |            |       ALERT engine    |
+------------------------+            +-----------------------+`}
            </pre>
          </div>
          <div className="text-xs text-brand-muted space-y-1.5 list-disc pl-4 font-mono">
            <div>• <b className="text-brand-text">Separation of Concerns:</b> Capturing, analysis, and rendering remain completely isolated.</div>
            <div>• <b className="text-brand-text">Observer Pattern:</b> Real-time packet parsing pushes updates directly to active UI models.</div>
          </div>
        </div>

        {/* Database Schema */}
        <div className="bg-brand-card border border-brand-border rounded p-5 space-y-4">
          <h4 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2 border-b border-brand-border pb-2">
            <Terminal className="w-4 h-4 text-brand-accent" />
            2. SQLite Database Schema
          </h4>
          <p className="text-xs text-brand-muted leading-relaxed">
            Enterprise database tables designed with SQLite database structures ensuring clean relations and fast indexed queries.
          </p>
          <div className="bg-brand-panel p-3.5 rounded border border-brand-border">
            <pre className="text-[10px] text-brand-accent font-mono leading-relaxed whitespace-pre-wrap">
{`CREATE TABLE sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  notes TEXT
);

CREATE TABLE packet_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER,
  timestamp REAL,
  protocol TEXT,
  src_ip TEXT,
  dst_ip TEXT,
  size INTEGER,
  summary TEXT,
  FOREIGN KEY(session_id) REFERENCES sessions(id)
);

CREATE TABLE threat_alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  severity TEXT,
  type TEXT,
  source TEXT,
  destination TEXT,
  message TEXT
);`}
            </pre>
          </div>
        </div>

        {/* Portfolio Interview Q&A */}
        <div className="bg-brand-card border border-brand-border rounded p-5 space-y-4 md:col-span-2">
          <h4 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2 border-b border-brand-border pb-2">
            <AlertCircle className="w-4 h-4 text-brand-accent" />
            3. Technical Viva & Recruiter Interview Guide
          </h4>
          
          <div className="space-y-4">
            <div className="bg-brand-panel p-4 rounded border border-brand-border">
              <span className="text-xs font-bold text-brand-accent font-mono">Q1: How does the Python background packet capture handle UI thread congestion?</span>
              <p className="text-xs text-brand-text mt-2 leading-relaxed font-sans">
                <b className="text-brand-accent">Answer:</b> The PySide6/Qt front-end maintains completely separate memory spaces. A specialized <code className="text-brand-accent bg-brand-card border border-brand-border px-1 py-0.5 rounded text-[10px]">PacketCaptureWorker</code> runs in a distinct thread inheriting <code className="text-brand-accent bg-brand-card border border-brand-border px-1 py-0.5 rounded text-[10px]">QThread</code> or standard Python <code className="text-brand-accent bg-brand-card border border-brand-border px-1 py-0.5 rounded text-[10px]">threading.Thread</code>, pushing decoded packets into a thread-safe <code className="text-brand-accent bg-brand-card border border-brand-border px-1 py-0.5 rounded text-[10px]">queue.Queue()</code>. Signals or poll updates periodically read from the queue, ensuring the GUI thread is never blocked.
              </p>
            </div>

            <div className="bg-brand-panel p-4 rounded border border-brand-border">
              <span className="text-xs font-bold text-brand-accent font-mono">Q2: Why did we choose Scapy for packet sniffing?</span>
              <p className="text-xs text-brand-text mt-2 leading-relaxed font-sans">
                <b className="text-brand-accent">Answer:</b> Scapy is an incredibly flexible interactive packet manipulation engine. Unlike socket interfaces which require manually decoding Raw IP/TCP headers, Scapy's dissection algorithms map standard fields across dozens of networking protocols (ARP, TCP, UDP, ICMP, DNS, DHCP) and allow painless custom rules.
              </p>
            </div>

            <div className="bg-brand-panel p-4 rounded border border-brand-border">
              <span className="text-xs font-bold text-brand-accent font-mono">Q3: How do you calculate Shannon Entropy in cyber threat intelligence?</span>
              <p className="text-xs text-brand-text mt-2 leading-relaxed font-sans">
                <b className="text-brand-accent">Answer:</b> Shannon entropy measures the amount of information or degree of randomness in a payload string. Encrypted malware communications or covert tunnels typically exhibit extremely high randomness (approaching 8.0), whereas standard ASCII headers are lower and more uniform. By calculating byte distribution patterns, the platform predicts covert activity without parsing encrypted keys.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
