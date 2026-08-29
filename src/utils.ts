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
  const seenAlertKeys = new Set<string>();

  // Track inbound port probes (SYN packets hitting distinct server ports)
  const probeMap: { [ip: string]: { ports: Set<number>, timestamp: string, dstIp: string } } = {};

  packets.forEach((p, idx) => {
    // 1. Tagged Attack Packets (from IDS Attack Simulator)
    if (p.tagged) {
      const alertKey = `tagged_${p.tagged}_${p.srcIp}`;
      if (!seenAlertKeys.has(alertKey)) {
        seenAlertKeys.add(alertKey);
        alerts.push({
          id: `alert_${p.tagged.toLowerCase()}_${p.id}`,
          timestamp: p.timestamp,
          severity: p.tagged === 'SQL_INJECTION' || p.tagged === 'SYN_FLOOD' ? 'CRITICAL' : 'HIGH',
          type: p.tagged.replace(/_/g, ' '),
          source: p.srcIp,
          destination: `${p.dstIp}:${p.dstPort || '?'}` ,
          message: p.summary,
          packetId: p.id,
          resolved: false
        });
      }
    }

    // 2. Real Inbound Port Scan Probes (Incoming TCP SYN without ACK)
    if (p.direction === 'INCOMING' && p.protocol === 'TCP' && p.tcpFlags?.includes('SYN') && !p.tcpFlags?.includes('ACK') && p.dstPort) {
      if (!probeMap[p.srcIp]) {
        probeMap[p.srcIp] = { ports: new Set<number>(), timestamp: p.timestamp, dstIp: p.dstIp };
      }
      probeMap[p.srcIp].ports.add(p.dstPort);
    }

    // 3. Conflicting TCP Flags (SYN+FIN)
    if (p.protocol === 'TCP' && p.tcpFlags) {
      const flags = p.tcpFlags.toUpperCase();
      if (flags.includes('SYN') && flags.includes('FIN')) {
        const alertKey = `flag_syn_fin_${p.srcIp}`;
        if (!seenAlertKeys.has(alertKey)) {
          seenAlertKeys.add(alertKey);
          alerts.push({
            id: `det_syn_fin_${p.id}`,
            timestamp: p.timestamp,
            severity: 'MEDIUM',
            type: 'Suspicious TCP Flags',
            source: p.srcIp,
            destination: `${p.dstIp}:${p.dstPort || '?'}` ,
            message: `Conflicting TCP flags (SYN+FIN) observed in packet #${p.id}. Pattern may indicate active host OS fingerprinting probe.`,
            packetId: p.id,
            resolved: false
          });
        }
      }
    }
  });

  // Evaluate legitimate Port Scan Probes (only when >= 8 distinct destination ports are contacted with SYN)
  Object.keys(probeMap).forEach(ip => {
    const data = probeMap[ip];
    if (data.ports.size >= 8) {
      const alertKey = `scan_${ip}`;
      if (!seenAlertKeys.has(alertKey)) {
        seenAlertKeys.add(alertKey);
        alerts.push({
          id: `det_scan_${ip.replace(/\./g, '_')}`,
          timestamp: data.timestamp,
          severity: 'HIGH',
          type: 'Potential Port Scan',
          source: ip,
          destination: data.dstIp,
          message: `Inbound host ${ip} probed ${data.ports.size} distinct destination ports with TCP SYN frames. Consistent with network reconnaissance.`,
          resolved: false
        });
      }
    }
  });

  return alerts;
}
