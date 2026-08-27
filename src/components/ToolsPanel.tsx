import React, { useState } from 'react';
import { Terminal, Shield, Cpu, HelpCircle, Copy, Check, ExternalLink, Search } from 'lucide-react';

interface ToolCommand {
  cmd: string;
  desc: string;
}

interface SnifferTool {
  id: string;
  name: string;
  icon: React.ComponentType<any>;
  role: string;
  prerequisites: string;
  description: string;
  commands: ToolCommand[];
  steps?: string[];
  codeSnippet?: string;
  glowColor: string;
}

export const ToolsPanel: React.FC = () => {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [activeTool, setActiveTool] = useState<string>('tshark');

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 1500);
  };

  const tools: SnifferTool[] = [
    {
      id: 'tshark',
      name: 'tshark (Wireshark CLI)',
      icon: Terminal,
      role: 'Primary live packet dissection & streaming daemon used by backend server.',
      prerequisites: 'Wireshark installed & added to system environment PATH.',
      description: 'tshark is the terminal-based version of Wireshark. It is highly optimized for headless servers or automated scripts, allowing you to capture raw frames and filter specific network layer fields in real-time.',
      glowColor: 'from-[#00f2ff] to-[#0066ff]',
      commands: [
        {
          cmd: 'tshark -D',
          desc: 'Lists all network interfaces with their indexes and physical IDs. Used to find the interface to capture from.'
        },
        {
          cmd: 'tshark -i 1 -c 20',
          desc: 'Captures exactly 20 packets from interface index 1 and prints a one-line summary for each.'
        },
        {
          cmd: 'tshark -i 1 -w capture.pcap',
          desc: 'Sniffs traffic from interface 1 and writes the raw binary stream directly into a standard PCAP file.'
        },
        {
          cmd: 'tshark -r capture.pcap -Y "http.request.method == GET"',
          desc: 'Reads a PCAP file and filters out only packets containing HTTP GET requests.'
        },
        {
          cmd: 'tshark -i 1 -l -n -T fields -E separator=\\t -e frame.number -e frame.time_epoch -e ip.proto -e ip.src -e ip.dst -e frame.len -e tcp.srcport -e tcp.dstport',
          desc: 'Extracts customized protocol columns formatted in real-time tab-separated values. (Matches the backend sniffer engine).'
        }
      ]
    },
    {
      id: 'wireshark',
      name: 'Wireshark (GUI Tool)',
      icon: Shield,
      role: 'Comprehensive packet protocol analyzer and visual debugger.',
      prerequisites: 'Wireshark desktop application.',
      description: 'The industry-standard GUI sniffer. Best for debugging complex protocols, examining TCP handshakes, follow stream data, and verifying the authenticity/accuracy of the live captured packets.',
      glowColor: 'from-blue-500 to-indigo-600',
      commands: [],
      steps: [
        'Launch the Wireshark GUI application on your computer.',
        'Double-click your active connection interface (e.g., "Wi-Fi" or "Ethernet") showing spike indicators.',
        'Apply display filters in the top filter bar (e.g., type "dns" or "tcp.port == 443" and press Enter).',
        'Right-click any packet and select "Follow > TCP Stream" to view the reconstructed conversational payloads.',
        'Go to "File > Save As" and choose the ".pcap" format to store files for dashboard processing.'
      ]
    },
    {
      id: 'npcap',
      name: 'Npcap / WinPcap & libpcap',
      icon: Cpu,
      role: 'Low-level kernel-mode packet capture driver interface.',
      prerequisites: 'Npcap (Windows) / Native libpcap (Unix/Linux/macOS).',
      description: 'The driver engine that hooks into your network interface card (NIC), bypassing the standard OS network stack to intercept raw frames, Ethernet headers, and IP datagrams in promiscuous mode.',
      glowColor: 'from-emerald-500 to-teal-600',
      commands: [],
      steps: [
        'On Windows, install Npcap during the Wireshark installation wizard.',
        'Ensure the "Install Npcap in WinPcap API-compatible mode" checkbox is checked.',
        'Ensure the service is running (on Windows command line as admin: net start npcap).',
        'On Linux, ensure the user running tshark has permissions to the network socket (sudo dpkg-reconfigure wireshark-common).'
      ]
    },
    {
      id: 'scapy',
      name: 'Scapy (Python Engine)',
      icon: HelpCircle,
      role: 'Programmatic packet fabrication, sniffing, and subnet penetration.',
      prerequisites: 'Python 3.x and "pip install scapy" library.',
      description: 'A powerful interactive packet manipulation library. Unlike typical network APIs that restrict custom headers, Scapy lets you craft entirely arbitrary network packets layer-by-layer (Ethernet / IP / TCP / Payload).',
      glowColor: 'from-purple-500 to-pink-600',
      commands: [
        {
          cmd: 'pip install scapy',
          desc: 'Installs the Scapy library and standard binary dependencies.'
        }
      ],
      codeSnippet: `from scapy.all import sniff, IP, TCP, send

# 1. SNIFF: Sniff packets with a custom processing callback
def process_packet(pkt):
    if pkt.haslayer(IP):
        print(f"Captured: {pkt[IP].src} -> {pkt[IP].dst} | Proto: {pkt.proto}")

print("Sniffing 15 packets...")
sniff(prn=process_packet, count=15)

# 2. CRAFT & SEND: Send a customized TCP SYN handshake packet
print("Sending custom TCP SYN packet...")
custom_packet = IP(src="192.168.1.109", dst="192.168.1.15")/TCP(sport=4444, dport=80, flags="S")
send(custom_packet)`
    },
    {
      id: 'tcpdump',
      name: 'tcpdump (CLI Sniffer)',
      icon: Terminal,
      role: 'Standard lightweight command-line packet sniffer natively available on Linux/macOS.',
      prerequisites: 'Sudo/root terminal privileges.',
      description: 'The classic command-line packet analyzer. Known for being extremely low-resource and robust, making it the tool of choice for capturing packet dumps on remote Linux servers, embedded systems, and firewalls.',
      glowColor: 'from-orange-500 to-red-600',
      commands: [
        {
          cmd: 'sudo tcpdump -D',
          desc: 'Lists all available physical and virtual network interfaces for sniffing.'
        },
        {
          cmd: 'sudo tcpdump -i eth0 -c 10',
          desc: 'Captures exactly 10 packets on interface eth0 and prints the IP summary.'
        },
        {
          cmd: 'sudo tcpdump -i eth0 -w dump.pcap',
          desc: 'Sniffs packets and saves the raw stream as standard binary PCAP for Wireshark inspection.'
        },
        {
          cmd: 'sudo tcpdump -r dump.pcap',
          desc: 'Reads and displays the packet details stored in a saved pcap dump file.'
        },
        {
          cmd: 'sudo tcpdump -i eth0 src 192.168.1.109 and port 80',
          desc: 'Captures packets filtering by source address 192.168.1.109 on HTTP port 80.'
        }
      ]
    },
    {
      id: 'nmap',
      name: 'Nmap (Network Mapper)',
      icon: Search,
      role: 'Industry standard network scanner, host discovery tool, and security auditor.',
      prerequisites: 'Kali Linux pre-installed / Windows/macOS local installation.',
      description: 'An essential cybersecurity scanner that probes targets with custom packet payloads to determine active hosts, open ports, software services, operating system versions, and known vulnerabilities.',
      glowColor: 'from-yellow-500 to-amber-600',
      commands: [
        {
          cmd: 'nmap -F 192.168.1.15',
          desc: 'Quickly scans the top 100 most common ports of the target IP address.'
        },
        {
          cmd: 'nmap -sS -O 192.168.1.15',
          desc: 'Initiates a stealthy TCP SYN scan and attempts to fingerprint the operating system.'
        },
        {
          cmd: 'nmap -sV -p 22,80,443 192.168.1.0/24',
          desc: 'Queries ports 22, 80, and 443 across an entire class C subnet to log version details.'
        },
        {
          cmd: 'nmap --script vuln 192.168.1.15',
          desc: 'Runs the Nmap Scripting Engine (NSE) vulnerability detection suite against the target.'
        }
      ]
    },
    {
      id: 'bettercap',
      name: 'Bettercap (MITM Suite)',
      icon: Shield,
      role: 'All-in-one Man-In-The-Middle (MITM) framework and active sniffer.',
      prerequisites: 'Sudo privileges (pre-installed on Kali/Debian/Linux).',
      description: 'The security industry standard for active LAN auditing. Bettercap can discover devices, perform active ARP and DNS spoofing, inject JavaScript codes into HTTP streams, and harvest passwords on the fly.',
      glowColor: 'from-red-600 to-pink-700',
      commands: [
        {
          cmd: 'sudo bettercap',
          desc: 'Opens the interactive Bettercap CLI session console.'
        },
        {
          cmd: 'net.probe on',
          desc: 'Actively sends ARP probes to discover all hosts on the local network subnet.'
        },
        {
          cmd: 'net.sniff on',
          desc: 'Enables the live packet sniffing engine to capture credentials and network metadata.'
        },
        {
          cmd: 'set arp.spoof.targets 192.168.1.15; arp.spoof on',
          desc: 'Spoofs the ARP cache of the victim, intercepting all local internet traffic.'
        }
      ]
    },
    {
      id: 'snort',
      name: 'Snort (IDS/IPS Engine)',
      icon: Cpu,
      role: 'Signature-based Network Intrusion Detection System (IDS).',
      prerequisites: 'Rule-set configurations loaded (e.g. Community Rules).',
      description: 'Snort is a real-time packet analyzer that parses network datagrams and compares them against thousands of threat rules to log security alerts, detect SQL injection probes, and drop malicious traffic.',
      glowColor: 'from-teal-500 to-emerald-600',
      commands: [
        {
          cmd: 'sudo snort -V',
          desc: 'Verifies the installed Snort engine version and details.'
        },
        {
          cmd: 'sudo snort -v -i eth0',
          desc: 'Starts sniffing packets on interface eth0, showing header printouts in terminal.'
        },
        {
          cmd: 'sudo snort -c /etc/snort/snort.conf -i eth0',
          desc: 'Launches real-time network intrusion monitoring using the local snort rules database.'
        },
        {
          cmd: 'sudo snort -c /etc/snort/snort.conf -r dump.pcap',
          desc: 'Analyzes a PCAP file off-line to identify indicators of compromise (IoC).'
        }
      ]
    },
    {
      id: 'hping3',
      name: 'hping3 (Packet Assembler)',
      icon: Terminal,
      role: 'Custom TCP/IP packet crafter, scanner, and stress-test utility.',
      prerequisites: 'Kali Linux pre-installed / apt install hping3.',
      description: 'hping3 is a packet building tool that enables hackers and network admins to customize TCP/IP headers, perform custom traceroutes, test firewall rules, and stress-test target networks.',
      glowColor: 'from-indigo-500 to-blue-600',
      commands: [
        {
          cmd: 'hping3 -c 3 -S -p 80 192.168.1.15',
          desc: 'Sends 3 TCP SYN packets to port 80, behaving like ping but using raw TCP.'
        },
        {
          cmd: 'hping3 -1 192.168.1.15',
          desc: 'Sends an ICMP Echo Request (identical to a standard ping packet).'
        },
        {
          cmd: 'hping3 --scan 1-1024 -S 192.168.1.15',
          desc: 'Triggers a custom TCP SYN port scan of ports 1 to 1024 on the target IP.'
        },
        {
          cmd: 'hping3 --flood -S -p 80 192.168.1.15',
          desc: 'Stress-tests target by flooding it with TCP SYN packets at high speed.'
        }
      ]
    }
  ];

  // Filtering tools/commands based on search
  const filteredTools = tools.map(tool => {
    const matchesSearch = tool.name.toLowerCase().includes(searchQuery.toLowerCase()) || 
                          tool.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
                          tool.role.toLowerCase().includes(searchQuery.toLowerCase());
    
    const matchedCmds = tool.commands.filter(c => 
      c.cmd.toLowerCase().includes(searchQuery.toLowerCase()) || 
      c.desc.toLowerCase().includes(searchQuery.toLowerCase())
    );

    if (matchesSearch || matchedCmds.length > 0 || (tool.steps && tool.steps.some(s => s.toLowerCase().includes(searchQuery.toLowerCase())))) {
      return {
        ...tool,
        commands: matchesSearch ? tool.commands : matchedCmds
      };
    }
    return null;
  }).filter(Boolean) as SnifferTool[];

  const activeToolObj = tools.find(t => t.id === activeTool) || tools[0];

  return (
    <div className="space-y-6">
      {/* Intro Header */}
      <div className="bg-brand-card border border-brand-border rounded p-5 relative overflow-hidden">
        <div className={`absolute top-0 right-0 w-24 h-24 bg-brand-accent/5 rounded-bl-full`}></div>
        <h3 className="text-xs font-semibold tracking-wide text-brand-muted uppercase flex items-center gap-2 mb-3">
          <Terminal className="w-4 h-4 text-brand-accent" />
          Packet Sniffing Toolchain & Utility Reference
        </h3>
        <p className="text-xs text-brand-muted leading-relaxed max-w-3xl">
          Complete engineering manual detailing the software components, kernel drivers, and command-line scripts utilized to capture, parse, and analyze raw network packets in high-accuracy audits.
        </p>
      </div>

      {/* Main interface layout */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        
        {/* Left column: Sidebar list of tools */}
        <div className="lg:col-span-1 space-y-3">
          <div className="bg-brand-card border border-brand-border rounded p-3 space-y-3">
            <span className="text-[10px] text-brand-muted uppercase tracking-wider font-bold block mb-1">Search & Filter</span>
            <div className="relative">
              <Search className="absolute left-2.5 top-2.5 w-3.5 h-3.5 text-brand-dim" />
              <input
                type="text"
                placeholder="Search commands, steps..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-brand-panel border border-brand-border rounded pl-8 pr-3 py-1.5 text-xs text-brand-text placeholder-brand-dim focus:outline-none focus:border-brand-accent transition"
              />
            </div>
          </div>

          <div className="bg-brand-card border border-brand-border rounded p-3 space-y-2">
            <span className="text-[10px] text-brand-muted uppercase tracking-wider font-bold block mb-2">Available Software</span>
            <div className="flex flex-col gap-1">
              {filteredTools.map(t => {
                const Icon = t.icon;
                const isSelected = activeTool === t.id;
                return (
                  <button
                    key={t.id}
                    onClick={() => setActiveTool(t.id)}
                    className={`w-full text-left px-3 py-2.5 rounded text-xs transition duration-200 cursor-pointer flex items-center justify-between border ${
                      isSelected 
                        ? 'bg-brand-panel/60 text-brand-accent border-brand-border-light shadow-md' 
                        : 'border-transparent text-brand-muted hover:text-brand-text hover:bg-brand-panel/30'
                    }`}
                  >
                    <div className="flex items-center gap-2.5">
                      <Icon className={`w-4 h-4 ${isSelected ? 'text-brand-accent' : 'text-brand-dim'}`} />
                      <span className="font-semibold">{t.name.split(' ')[0]}</span>
                    </div>
                    {isSelected && <span className="w-1.5 h-1.5 rounded-full bg-brand-accent"></span>}
                  </button>
                );
              })}
              {filteredTools.length === 0 && (
                <div className="text-[11px] text-brand-muted text-center py-4 font-mono">No matching tools found.</div>
              )}
            </div>
          </div>
        </div>

        {/* Right column: Selected tool details */}
        <div className="lg:col-span-3">
          {activeToolObj && (
            <div className="bg-brand-card border border-brand-border rounded overflow-hidden flex flex-col min-h-[500px]">
              
              {/* Header banner with gradient glow */}
              <div className="p-5 border-b border-brand-border relative bg-brand-panel/40">
                <div className="flex items-start justify-between">
                  <div className="space-y-1">
                    <span className="text-[10px] text-brand-accent font-bold font-mono uppercase tracking-widest bg-brand-accent/5 border border-brand-accent/20 px-2 py-0.5 rounded">
                      TOOL SPECIFICATION
                    </span>
                    <h2 className="text-base font-bold text-white mt-2 flex items-center gap-2">
                      <activeToolObj.icon className="w-5 h-5 text-brand-accent" />
                      {activeToolObj.name}
                    </h2>
                  </div>
                  <span className="text-[11px] text-brand-muted font-mono">
                    ID: {activeToolObj.id}
                  </span>
                </div>
                
                <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                  <div className="bg-brand-card/60 p-3 rounded border border-brand-border/60">
                    <span className="text-[9px] text-brand-dim font-bold uppercase block mb-1">PROJECT ROLE</span>
                    <p className="text-brand-text text-[11px] leading-relaxed">{activeToolObj.role}</p>
                  </div>
                  <div className="bg-brand-card/60 p-3 rounded border border-brand-border/60">
                    <span className="text-[9px] text-brand-dim font-bold uppercase block mb-1">PREREQUISITES</span>
                    <p className="text-brand-text text-[11px] leading-relaxed">{activeToolObj.prerequisites}</p>
                  </div>
                </div>
              </div>

              {/* Body Content */}
              <div className="p-5 flex-1 space-y-6">
                
                {/* Description */}
                <div className="space-y-2">
                  <h4 className="text-xs font-bold text-white uppercase tracking-wider">Overview</h4>
                  <p className="text-xs text-brand-muted leading-relaxed font-sans">{activeToolObj.description}</p>
                </div>

                {/* Steps (If any) */}
                {activeToolObj.steps && activeToolObj.steps.length > 0 && (
                  <div className="space-y-3">
                    <h4 className="text-xs font-bold text-white uppercase tracking-wider">How to Perform Accurate Sniffing</h4>
                    <div className="space-y-2.5">
                      {activeToolObj.steps.map((step, idx) => (
                        <div key={idx} className="flex gap-3 text-xs leading-relaxed font-sans items-start">
                          <span className="w-5 h-5 rounded-full bg-brand-panel border border-brand-border flex items-center justify-center font-bold font-mono text-[10px] text-brand-accent shrink-0">
                            {idx + 1}
                          </span>
                          <span className="text-brand-muted pt-0.5">{step}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Commands table (If any) */}
                {activeToolObj.commands && activeToolObj.commands.length > 0 && (
                  <div className="space-y-3">
                    <h4 className="text-xs font-bold text-white uppercase tracking-wider">Essential Command Reference</h4>
                    <div className="overflow-hidden border border-brand-border rounded bg-brand-panel/30">
                      <table className="w-full text-left border-collapse text-[11px] font-mono">
                        <thead>
                          <tr className="bg-brand-panel border-b border-brand-border text-brand-muted">
                            <th className="p-3">COMMAND</th>
                            <th className="p-3">DESCRIPTION</th>
                            <th className="p-3 text-center">ACTION</th>
                          </tr>
                        </thead>
                        <tbody>
                          {activeToolObj.commands.map((cmd, idx) => (
                            <tr key={idx} className="border-b border-brand-border/40 hover:bg-brand-panel/20 transition">
                              <td className="p-3 text-brand-accent font-bold align-middle break-all max-w-[280px]">
                                <code>{cmd.cmd}</code>
                              </td>
                              <td className="p-3 text-brand-muted leading-relaxed align-middle font-sans text-xs">
                                {cmd.desc}
                              </td>
                              <td className="p-3 text-center align-middle">
                                <button
                                  onClick={() => copyToClipboard(cmd.cmd, `${activeToolObj.id}-cmd-${idx}`)}
                                  className="p-1.5 bg-brand-card hover:bg-brand-panel text-brand-muted hover:text-brand-accent border border-brand-border rounded cursor-pointer transition"
                                  title="Copy Command"
                                >
                                  {copiedId === `${activeToolObj.id}-cmd-${idx}` ? (
                                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                                  ) : (
                                    <Copy className="w-3.5 h-3.5" />
                                  )}
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* Code Snippet (If any) */}
                {activeToolObj.codeSnippet && (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <h4 className="text-xs font-bold text-white uppercase tracking-wider">Example Sniffing Script (Python)</h4>
                      <button
                        onClick={() => copyToClipboard(activeToolObj.codeSnippet || '', 'code-snippet')}
                        className="px-2.5 py-1 bg-brand-panel text-brand-muted hover:text-brand-accent border border-brand-border rounded cursor-pointer transition text-[10px] font-mono flex items-center gap-1.5"
                      >
                        {copiedId === 'code-snippet' ? (
                          <>
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                            Copied Script
                          </>
                        ) : (
                          <>
                            <Copy className="w-3.5 h-3.5" />
                            Copy Script
                          </>
                        )}
                      </button>
                    </div>
                    <div className="bg-brand-panel p-4 rounded border border-brand-border overflow-x-auto">
                      <pre className="text-[11px] text-brand-accent font-mono leading-relaxed whitespace-pre">
                        {activeToolObj.codeSnippet}
                      </pre>
                    </div>
                  </div>
                )}
              </div>

            </div>
          )}
        </div>

      </div>
    </div>
  );
};
