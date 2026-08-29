import { Packet, SecurityAlert, SnifferFilter } from './types';

export function filterPackets(packets: Packet[], filters: SnifferFilter): Packet[] {
  return packets.filter(p => {
    // Protocol Filter
    if (filters.protocol !== 'ALL') {
      if (p.protocol.toUpperCase() !== filters.protocol.toUpperCase()) return false;
    }
    
    // IP Filter (matches src or dst)
    if (filters.ip.trim() !== '') {
      const cleanIp = filters.ip.trim().toLowerCase();
      if (!p.srcIp.toLowerCase().includes(cleanIp) && !p.dstIp.toLowerCase().includes(cleanIp)) return false;
    }

    // Port Filter
    if (filters.port.trim() !== '') {
      const cleanPort = parseInt(filters.port.trim());
      if (!isNaN(cleanPort)) {
        if (p.srcPort !== cleanPort && p.dstPort !== cleanPort) return false;
      }
    }

    // MAC Filter
    if (filters.mac.trim() !== '') {
      const cleanMac = filters.mac.trim().toLowerCase();
      if (!p.macSrc.toLowerCase().includes(cleanMac) && !p.macDst.toLowerCase().includes(cleanMac)) return false;
    }

    // Size range Min
    if (filters.sizeMin.trim() !== '') {
      const minVal = parseInt(filters.sizeMin.trim());
      if (!isNaN(minVal) && p.size < minVal) return false;
    }

    // Size range Max
    if (filters.sizeMax.trim() !== '') {
      const maxVal = parseInt(filters.sizeMax.trim());
      if (!isNaN(maxVal) && p.size > maxVal) return false;
    }

    // Country Filter
    if (filters.country !== 'ALL') {
      if (!p.country || p.country.toUpperCase() !== filters.country.toUpperCase()) return false;
    }

    // TCP Flag Filter
    if (filters.tcpFlag !== 'ALL') {
      if (!p.tcpFlags || !p.tcpFlags.toUpperCase().includes(filters.tcpFlag.toUpperCase())) return false;
    }

    // Direction Filter
    if (filters.direction !== 'ALL') {
      if (p.direction.toUpperCase() !== filters.direction.toUpperCase()) return false;
    }

    // Search Query (covers keywords, summary, hostnames, vendor)
    if (filters.searchQuery.trim() !== '') {
      const q = filters.searchQuery.toLowerCase().trim();
      const match = 
        p.srcIp.toLowerCase().includes(q) ||
        p.dstIp.toLowerCase().includes(q) ||
        p.protocol.toLowerCase().includes(q) ||
        p.summary.toLowerCase().includes(q) ||
        (p.hostname && p.hostname.toLowerCase().includes(q)) ||
        (p.vendor && p.vendor.toLowerCase().includes(q)) ||
        (p.appProtocol && p.appProtocol.toLowerCase().includes(q)) ||
        p.id.toString() === q;
      if (!match) return false;
    }

    return true;
  });
}

// Conservative anomaly & threat detection engine based on actual observed network metadata
export function runSecurityAnalysis(packets: Packet[]): SecurityAlert[] {
  const alerts: SecurityAlert[] = [];
  
  // Track statistics for detecting high-frequency activities (scanning, sweeps)
  const ipPortMap: { [ip: string]: { ports: Set<number>, times: number[], dstIps: Set<string> } } = {};
  const ipPacketCount: { [ip: string]: number } = {};
  const arpCount: { [ip: string]: number } = {};

  packets.forEach((p, idx) => {
    // Count packets per source IP for burst detection
    ipPacketCount[p.srcIp] = (ipPacketCount[p.srcIp] || 0) + 1;

    // Port Scanning Heuristics (TCP/UDP with valid ports)
    if ((p.protocol === 'TCP' || p.protocol === 'UDP') && p.dstPort && p.srcIp) {
      if (!ipPortMap[p.srcIp]) {
        ipPortMap[p.srcIp] = { ports: new Set<number>(), times: [], dstIps: new Set<string>() };
      }
      ipPortMap[p.srcIp].ports.add(p.dstPort);
      ipPortMap[p.srcIp].dstIps.add(p.dstIp);
      ipPortMap[p.srcIp].times.push(new Date(p.timestamp).getTime());
    }

    // Malformed / Suspicious TCP Flag Combinations (e.g. SYN+FIN or NULL scan)
    if (p.protocol === 'TCP' && p.tcpFlags) {
      const flags = p.tcpFlags.toUpperCase();
      if (flags.includes('SYN') && flags.includes('FIN')) {
        alerts.push({
          id: `det_syn_fin_${p.id || idx}`,
          timestamp: p.timestamp,
          severity: 'MEDIUM',
          type: 'Suspicious TCP Flag Combination',
          source: p.srcIp,
          destination: `${p.dstIp}:${p.dstPort || '?'}` ,
          message: `Conflicting TCP flags (SYN+FIN) observed in packet #${p.id}. May indicate host OS fingerprinting or non-standard TCP stack implementation.`,
          packetId: p.id,
          resolved: false
        });
      }
    }

    // DNS Tunneling / Covert Exfiltration Indicators
    if (p.protocol === 'DNS' && (p.size > 512 || (p.summary && p.summary.length > 120))) {
      alerts.push({
        id: `det_dns_anomaly_${p.id || idx}`,
        timestamp: p.timestamp,
        severity: 'MEDIUM',
        type: 'Anomalous DNS Query Size',
        source: p.srcIp,
        destination: `${p.dstIp}:53`,
        message: `Unusually large DNS frame (${p.size} bytes) observed in packet #${p.id}. Pattern may suggest large DNS TXT resolution or potential covert channel.`,
        packetId: p.id,
        resolved: false
      });
    }

    // ARP Rate Anomaly
    if (p.protocol === 'ARP') {
      arpCount[p.srcIp] = (arpCount[p.srcIp] || 0) + 1;
      if (arpCount[p.srcIp] >= 20) {
        alerts.push({
          id: `det_arp_freq_${p.srcIp}`,
          timestamp: p.timestamp,
          severity: 'LOW',
          type: 'High ARP Activity',
          source: p.srcIp,
          destination: p.dstIp || 'Broadcast',
          message: `High frequency of ARP frames (${arpCount[p.srcIp]} packets) observed from ${p.srcIp}. Common during network topology changes, gateway discovery, or ARP storms.`,
          packetId: p.id,
          resolved: false
        });
      }
    }
  });

  // Conservative Port Scan Detection (requiring at least 8 distinct target ports)
  Object.keys(ipPortMap).forEach(ip => {
    const data = ipPortMap[ip];
    if (data.ports.size >= 8) {
      alerts.push({
        id: `det_scan_${ip}`,
        timestamp: new Date().toISOString(),
        severity: 'HIGH',
        type: 'Potential Port Scan',
        source: ip,
        destination: Array.from(data.dstIps).slice(0, 3).join(', ') + (data.dstIps.size > 3 ? '...' : ''),
        message: `Host ${ip} contacted ${data.ports.size} distinct destination ports within the captured window. Pattern is consistent with automated port discovery or vulnerability probing.`,
        resolved: false
      });
    }
  });

  // Rapid Connection Burst Detection
  Object.keys(ipPacketCount).forEach(ip => {
    if (ipPacketCount[ip] >= 60 && !ip.startsWith('127.')) {
      alerts.push({
        id: `det_burst_${ip}`,
        timestamp: new Date().toISOString(),
        severity: 'LOW',
        type: 'Abnormal Traffic Burst',
        source: ip,
        destination: 'Multiple',
        message: `Rapid connection burst (${ipPacketCount[ip]} packets) observed from source ${ip}. Verify whether this is expected file transfer or high-frequency polling activity.`,
        resolved: false
      });
    }
  });

  return alerts;
}
