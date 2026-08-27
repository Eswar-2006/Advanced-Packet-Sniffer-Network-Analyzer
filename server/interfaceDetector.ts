import { execSync } from "child_process";
import os from "os";
import fs from "fs";
import { NetworkInterface, InterfaceType } from "../src/types";

const TSHARK_BIN = process.platform === "win32"
  ? "C:\\Program Files\\Wireshark\\tshark.exe"
  : "tshark";

export function getTsharkBinary(): string | null {
  if (process.platform === "win32") {
    if (fs.existsSync(TSHARK_BIN)) return TSHARK_BIN;
  }
  try {
    execSync(`${TSHARK_BIN} --version`, { stdio: "ignore" });
    return TSHARK_BIN;
  } catch (e) {
    return null;
  }
}

export function detectNetworkInterfaces(): { interfaces: NetworkInterface[]; tsharkAvailable: boolean } {
  const tsharkBin = getTsharkBinary();
  const osInterfaces = os.networkInterfaces();
  const rawTsharkOutput: { index: number; id: string; name: string }[] = [];

  if (tsharkBin) {
    try {
      const stdout = execSync(`"${tsharkBin}" -D`, { encoding: "utf8" });
      const lines = stdout.split("\n");
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        // Format: "1. \Device\NPF_{...} (Wi-Fi)" or "1. eth0 (Ethernet interface)"
        const match = trimmed.match(/^(\d+)\.\s+(\S+)(?:\s+\((.+)\))?/);
        if (match) {
          const index = parseInt(match[1], 10);
          const id = match[2];
          const name = match[3] || match[2];
          rawTsharkOutput.push({ index, id, name });
        }
      }
    } catch (err) {
      console.warn("[InterfaceDetector] Could not execute tshark -D:", err);
    }
  }

  // Create a combined map of OS interfaces and tshark capture devices
  const interfaces: NetworkInterface[] = [];
  const processedOsNames = new Set<string>();

  // Map os.networkInterfaces() entries to get IP & MAC addresses
  const osAdapterList: { osName: string; ip: string; mac: string; internal: boolean }[] = [];
  for (const [osName, addrs] of Object.entries(osInterfaces)) {
    if (!addrs) continue;
    for (const a of addrs) {
      if (a.family === "IPv4") {
        osAdapterList.push({
          osName,
          ip: a.address,
          mac: a.mac && a.mac !== "00:00:00:00:00:00" ? a.mac : "N/A",
          internal: a.internal,
        });
      }
    }
  }

  if (rawTsharkOutput.length > 0) {
    for (const item of rawTsharkOutput) {
      const lowerName = item.name.toLowerCase();
      const lowerId = item.id.toLowerCase();

      let type: InterfaceType = "other";
      if (lowerName.includes("wi-fi") || lowerName.includes("wifi") || lowerName.includes("wlan") || lowerName.includes("wireless")) {
        type = "wireless";
      } else if (lowerName.includes("ethernet") || lowerName.includes("local area connection") || lowerId.includes("eth") || lowerId.includes("en")) {
        type = "ethernet";
      } else if (lowerName.includes("vpn") || lowerName.includes("wireguard") || lowerName.includes("tap") || lowerName.includes("tun") || lowerName.includes("openvpn")) {
        type = "vpn";
      } else if (lowerName.includes("loopback") || lowerId.includes("loopback") || lowerId.includes("lo")) {
        type = "loopback";
      } else if (lowerName.includes("vmware") || lowerName.includes("virtual") || lowerName.includes("vethernet") || lowerName.includes("hyper-v") || lowerName.includes("docker")) {
        type = "virtual";
      }

      // Match with OS interface for IP & MAC
      let matchedIp = "0.0.0.0";
      let matchedMac = "N/A";

      // Try matching by name
      const osMatch = osAdapterList.find(o => 
        o.osName.toLowerCase() === item.name.toLowerCase() ||
        item.name.toLowerCase().includes(o.osName.toLowerCase()) ||
        o.osName.toLowerCase().includes(item.name.toLowerCase())
      );

      if (osMatch) {
        matchedIp = osMatch.ip;
        matchedMac = osMatch.mac;
        processedOsNames.add(osMatch.osName);
      } else if (type === "loopback") {
        matchedIp = "127.0.0.1";
      }

      // Check if status is active
      const status: "active" | "inactive" = (matchedIp !== "0.0.0.0" || type === "loopback") ? "active" : "inactive";

      interfaces.push({
        id: item.id, // Store exact tshark capture identifier!
        name: item.name,
        displayName: `${item.name} (${item.id.length > 30 ? item.id.slice(0, 25) + '...' : item.id})`,
        type,
        ip: matchedIp,
        mac: matchedMac,
        status,
        captureSupported: true,
        notes: tsharkBin ? "tshark packet capture engine supported" : "Capture via simulator fallback only"
      });
    }
  } else {
    // Fallback if tshark -D is unavailable: parse os.networkInterfaces()
    for (const [osName, addrs] of Object.entries(osInterfaces)) {
      if (!addrs) continue;
      for (const a of addrs) {
        if (a.family === "IPv4") {
          const lowerName = osName.toLowerCase();
          let type: InterfaceType = "other";
          if (lowerName.includes("wi-fi") || lowerName.includes("wlan") || lowerName.includes("wireless")) type = "wireless";
          else if (lowerName.includes("eth") || lowerName.includes("ethernet") || lowerName.includes("en")) type = "ethernet";
          else if (lowerName.includes("vpn") || lowerName.includes("tun") || lowerName.includes("tap")) type = "vpn";
          else if (a.internal || lowerName.includes("loopback") || lowerName.includes("lo")) type = "loopback";
          else if (lowerName.includes("veth") || lowerName.includes("docker") || lowerName.includes("vmware")) type = "virtual";

          interfaces.push({
            id: osName,
            name: osName,
            displayName: `${osName} [${a.address}]`,
            type,
            ip: a.address,
            mac: a.mac || "N/A",
            status: "active",
            captureSupported: false, // Cannot run tshark directly without tshark installed
            notes: "tshark binary not detected on system. Install Wireshark/tshark for live raw capture."
          });
        }
      }
    }
  }

  return {
    interfaces,
    tsharkAvailable: !!tsharkBin
  };
}
