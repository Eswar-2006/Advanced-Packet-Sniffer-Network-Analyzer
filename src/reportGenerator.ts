import { Packet, SecurityAlert, SnifferStats } from './types';

// Convert a table array of packets to a CSV string
export function exportToCSV(packets: Packet[]): string {
  const headers = ['ID', 'Timestamp', 'Protocol', 'Source IP', 'Destination IP', 'Src Port', 'Dst Port', 'MAC Src', 'MAC Dst', 'Size', 'TTL', 'Summary'];
  const rows = packets.map(p => [
    p.id,
    p.timestamp,
    p.protocol,
    p.srcIp,
    p.dstIp,
    p.srcPort || '',
    p.dstPort || '',
    p.macSrc,
    p.macDst,
    p.size,
    p.ttl || '',
    p.summary.replace(/"/g, '""')
  ]);
  
  return [
    headers.join(','),
    ...rows.map(row => row.map(val => `"${val}"`).join(','))
  ].join('\n');
}

// Convert data to JSON string
export function exportToJSON(packets: Packet[]): string {
  return JSON.stringify(packets, null, 2);
}

// Generate highly stylized custom reports representation
export function generateHTMLReport(packets: Packet[], alerts: SecurityAlert[], stats: SnifferStats): string {
  const alertRows = alerts.map(a => `
    <tr style="border-bottom: 1px solid #ef4444; background: rgba(239, 68, 68, 0.05);">
      <td style="padding: 10px; font-weight: bold; color: #f87171;">[${a.severity}]</td>
      <td style="padding: 10px;">${a.type}</td>
      <td style="padding: 10px;">${a.source} &rarr; ${a.destination}</td>
      <td style="padding: 10px; font-size: 13px;">${a.message}</td>
    </tr>
  `).join('');

  const packetRows = packets.map(p => `
    <tr style="border-bottom: 1px solid #334155;">
      <td style="padding: 8px;">#${p.id}</td>
      <td style="padding: 8px; font-weight: bold; color: #38bdf8;">${p.protocol}</td>
      <td style="padding: 8px;">${p.srcIp}:${p.srcPort || ''}</td>
      <td style="padding: 8px;">${p.dstIp}:${p.dstPort || ''}</td>
      <td style="padding: 8px;">${p.size} B</td>
      <td style="padding: 8px; font-size: 13px; color: #94a3b8;">${p.summary}</td>
    </tr>
  `).join('');

  return `
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>Network Traffic & Security Analysis Report</title>
      <style>
        body { font-family: 'Consolas', 'Courier New', monospace; background: #0b0f19; color: #f1f5f9; padding: 25px; }
        .header { border-bottom: 2px solid #38bdf8; padding-bottom: 15px; margin-bottom: 30px; }
        .title { font-size: 24px; color: #38bdf8; font-weight: bold; }
        .subtitle { color: #94a3b8; font-size: 14px; }
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 30px; }
        .stat-card { background: #1e293b; border: 1px solid #334155; padding: 15px; border-radius: 8px; }
        .stat-val { font-size: 22px; font-weight: bold; color: #38bdf8; }
        .section-title { font-size: 18px; border-left: 4px solid #38bdf8; padding-left: 10px; margin-top: 40px; margin-bottom: 15px; }
        table { width: 100%; border-collapse: collapse; text-align: left; }
        th { background: #1e293b; padding: 10px; color: #38bdf8; }
      </style>
    </head>
    <body>
      <div class="header">
        <div class="title">Enterprise Traffic & Cybersecurity Audit Report</div>
        <div class="subtitle">Generated: ${new Date().toLocaleString()} | Security Health Index Score: ${stats.networkHealthScore}/100</div>
      </div>

      <div class="stats-grid">
        <div class="stat-card">
          <div style="font-size: 12px; color: #94a3b8;">TOTAL PACKETS AUDITED</div>
          <div class="stat-val">${stats.totalPackets}</div>
        </div>
        <div class="stat-card">
          <div style="font-size: 12px; color: #94a3b8;">TOTAL SYSTEM THREATS</div>
          <div class="stat-val" style="color: #ef4444;">${stats.threatCounter}</div>
        </div>
        <div class="stat-card">
          <div style="font-size: 12px; color: #94a3b8;">TOTAL DATA TRANSFERRED</div>
          <div class="stat-val">${stats.incomingBytes + stats.outgoingBytes} B</div>
        </div>
        <div class="stat-card">
          <div style="font-size: 12px; color: #94a3b8;">ACTIVE CONNECTIONS</div>
          <div class="stat-val" style="color: #10b981;">${stats.activeConnections}</div>
        </div>
      </div>

      ${alerts.length > 0 ? `
        <div class="section-title">CRITICAL SECURITY INCIDENTS</div>
        <table>
          <thead>
            <tr>
              <th>SEVERITY</th>
              <th>INCIDENT TYPE</th>
              <th>IP PATH</th>
              <th>DESCRIPTION</th>
            </tr>
          </thead>
          <tbody>
            ${alertRows}
          </tbody>
        </table>
      ` : '<p style="color: #10b981;">No security threats or suspicious activity detected during audit period.</p>'}

      <div class="section-title">CAPTURED NETWORK TRAFFIC LOG</div>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>PROTOCOL</th>
            <th>SOURCE ADDR</th>
            <th>DESTINATION ADDR</th>
            <th>SIZE</th>
            <th>SUMMARY DESCRIPTION</th>
          </tr>
        </thead>
        <tbody>
          ${packetRows}
        </tbody>
      </table>
    </body>
    </html>
  `;
}
