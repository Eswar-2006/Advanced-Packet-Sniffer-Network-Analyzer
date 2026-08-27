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

// Lightweight anomaly detection engine based on heuristics & simple AI scoring
export function runSecurityAnalysis(packets: Packet[]): SecurityAlert[] {
  const alerts: SecurityAlert[] = [];
  
  // Track stats for detecting high-frequency activities (scanning, sweeps)
  const ipCounts: { [ip: string]: { ports: Set<number>, times: number[] } } = {};
  const arpRequestCount: { [ip: string]: number } = {};
  const dnsQueries: string[] = [];

  packets.forEach((p, idx) => {
    // Port Scanning Heuristics
    if (p.protocol === 'TCP' && p.srcPort && p.dstPort) {
      if (!ipCounts[p.srcIp]) {
        ipCounts[p.srcIp] = { ports: new Set<number>(), times: [] };
      }
      ipCounts[p.srcIp].ports.add(p.dstPort);
      ipCounts[p.srcIp].times.push(new Date(p.timestamp).getTime());
    }

    // Malformed packet checks (e.g. invalid size, conflicting TCP flags)
    if (p.protocol === 'TCP' && p.tcpFlags) {
      const flags = p.tcpFlags.toUpperCase();
      // SYN-FIN alert (unusual flag combination used by scanners)
      if (flags.includes('SYN') && flags.includes('FIN')) {
        alerts.push({
          id: `det_malformed_${idx}`,
          timestamp: p.timestamp,
          severity: 'HIGH',
          type: 'Malformed Packet Detected',
          source: p.srcIp,
          destination: p.dstIp,
          message: `Conflicting TCP flags detected: SYN and FIN are set concurrently in Packet #${p.id}. Possible active host fingerprinting.`,
          packetId: p.id,
          resolved: false
        });
      }
    }

    // DNS Tunneling Indicator (extremely large dns query names or abnormal length)
    if (p.protocol === 'DNS' && p.summary.toLowerCase().includes('query')) {
      if (p.size > 250) {
        alerts.push({
          id: `det_dns_tunnel_${idx}`,
          timestamp: p.timestamp,
          severity: 'HIGH',
          type: 'DNS Tunneling Indicators',
          source: p.srcIp,
          destination: p.dstIp,
          message: `Unusually large DNS query size (${p.size} bytes) in Packet #${p.id}. Indicative of possible covert communication tunneling.`,
          packetId: p.id,
          resolved: false
        });
      }
    }

    // ARP Spoofing / Broadcast Storm detection
    if (p.protocol === 'ARP') {
      if (!arpRequestCount[p.srcIp]) arpRequestCount[p.srcIp] = 0;
      arpRequestCount[p.srcIp]++;
      
      if (arpRequestCount[p.srcIp] > 15) {
        alerts.push({
          id: `det_arp_storm_${idx}`,
          timestamp: p.timestamp,
          severity: 'MEDIUM',
          type: 'ARP Broadcast Storm',
          source: p.srcIp,
          destination: p.dstIp,
          message: `Excessive frequency of ARP broadcast responses from ${p.srcIp}. Potential network looping or network mapping.`,
          packetId: p.id,
          resolved: false
        });
      }
    }
  });

  // Evaluate TCP port probing scanners
  Object.keys(ipCounts).forEach(ip => {
    const data = ipCounts[ip];
    if (data.ports.size >= 2) {
      alerts.push({
        id: `det_scan_${ip}`,
        timestamp: new Date().toISOString(),
        severity: 'HIGH',
        type: 'Active Port Scan',
        source: ip,
        destination: 'Multiple',
        message: `Host ${ip} probed ${data.ports.size} distinct destination ports. Immediate firewall isolation is recommended to mitigate active network scanning.`,
        resolved: false
      });
    }
  });

  return alerts;
}
