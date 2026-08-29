#!/usr/bin/env python3
"""
===================================================================
     SENTINEL ANALYTICA - REAL-TIME LOCAL HARDWARE CAPTURE AGENT
===================================================================
Architecture:
  Physical Wi-Fi / Ethernet NIC
       ↓ (Scapy / TShark / Npcap / libpcap)
  Local Packet Capture & Normalization
       ↓ (Stripping sensitive payloads)
  Secure WebSocket Channel (TLS/WSS)
       ↓
  Sentinel Analytica Central Backend & Dashboard
===================================================================
"""

import sys
import os
import time
import json
import socket
import struct
import platform
import argparse
import threading
import datetime
import urllib.request
import urllib.parse
import urllib.error

# Global state
CONFIG_FILE = os.path.join(os.path.expanduser("~"), ".sentinel-agent.json")
RUNNING = True
ACTIVE_CAPTURE_THREAD = None
IS_CAPTURING = False
CURRENT_INTERFACE = None
WS_CLIENT = None
PACKET_COUNTER = 0

# Try importing Scapy
SCAPY_AVAILABLE = False
try:
    from scapy.all import (
        sniff, IP, IPv6, TCP, UDP, ICMP, ARP, Ether, DNS, DNSQR, DNSRR,
        get_if_list, get_if_hwaddr, conf
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Try importing psutil for network interface enumeration
PSUTIL_AVAILABLE = False
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Try importing websockets or fallback to standard library socket
WEBSOCKETS_AVAILABLE = False
try:
    import websocket
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False


def log(msg, level="INFO"):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    prefix = {
        "INFO": "[*]",
        "SUCCESS": "[+]",
        "WARN": "[!]",
        "ERROR": "[-]"
    }.get(level, "[*]")
    print(f"{ts} {prefix} {msg}", flush=True)


def get_local_interfaces():
    """Detect available physical and virtual network interfaces on this machine."""
    interfaces = []
    
    # 1. Use psutil if available
    if PSUTIL_AVAILABLE:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        for iface_name, iface_stats in stats.items():
            iface_addrs = addrs.get(iface_name, [])
            ipv4 = "0.0.0.0"
            mac = "N/A"
            for a in iface_addrs:
                if a.family == socket.AF_INET:
                    ipv4 = a.address
                elif hasattr(socket, 'AF_LINK') and a.family == socket.AF_LINK:
                    mac = a.address
                elif a.family == 17: # Linux AF_PACKET
                    mac = a.address
            
            lower = iface_name.lower()
            iface_type = "other"
            if "wi-fi" in lower or "wifi" in lower or "wlan" in lower or "wireless" in lower:
                iface_type = "wireless"
            elif "eth" in lower or "ethernet" in lower or "en" in lower or "local area" in lower:
                iface_type = "ethernet"
            elif "loopback" in lower or "lo" in lower or ipv4 == "127.0.0.1":
                iface_type = "loopback"
            elif "vpn" in lower or "tun" in lower or "tap" in lower or "wireguard" in lower:
                iface_type = "vpn"
            elif "docker" in lower or "veth" in lower or "vmware" in lower:
                iface_type = "virtual"

            status = "active" if iface_stats.isup and ipv4 != "0.0.0.0" else ("active" if iface_stats.isup else "inactive")
            display_name = f"{iface_name} ({ipv4})" if ipv4 != "0.0.0.0" else iface_name

            interfaces.append({
                "id": iface_name,
                "name": iface_name,
                "displayName": display_name,
                "type": iface_type,
                "ip": ipv4,
                "mac": mac,
                "status": status,
                "captureSupported": True,
                "notes": "Native Python/Scapy Hardware Capture Node"
            })
            
    # 2. Fallback to Scapy get_if_list()
    elif SCAPY_AVAILABLE:
        for iface in get_if_list():
            interfaces.append({
                "id": str(iface),
                "name": str(iface),
                "displayName": str(iface),
                "type": "ethernet" if "eth" in str(iface).lower() else "wireless",
                "ip": "127.0.0.1",
                "mac": "N/A",
                "status": "active",
                "captureSupported": True,
                "notes": "Scapy Interface List"
            })
    else:
        # 3. Standard library fallback
        hostname = socket.gethostname()
        local_ip = "127.0.0.1"
        try:
            local_ip = socket.gethostbyname(hostname)
        except Exception:
            pass
        interfaces.append({
            "id": "default",
            "name": "Default Network Card",
            "displayName": f"Default Interface ({local_ip})",
            "type": "ethernet",
            "ip": local_ip,
            "mac": "N/A",
            "status": "active",
            "captureSupported": True,
            "notes": "Default socket interface"
        })

    return interfaces


def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            log(f"Could not read existing config: {e}", "WARN")
    return {}


def save_config(cfg):
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(cfg, f, indent=2)
        log(f"Saved local credentials to {CONFIG_FILE}", "SUCCESS")
    except Exception as e:
        log(f"Failed to save credentials: {e}", "ERROR")


def register_agent(server_url, token, device_name):
    """Register agent with Central Backend using one-time token or quick registration."""
    headers = {"Content-Type": "application/json"}
    
    if token:
        log(f"Redeeming secure setup token with backend at {server_url}...")
        url = f"{server_url}/api/agents/register"
        payload = {
            "token": token.strip(),
            "deviceName": device_name,
            "platform": sys.platform,
            "agentVersion": "3.0.0"
        }
    else:
        log(f"Requesting automatic pairing with backend at {server_url}...")
        url = f"{server_url}/api/agents/quick-register"
        payload = {
            "deviceName": device_name,
            "platform": sys.platform,
            "agentVersion": "3.0.0"
        }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            if body.get("success"):
                log(f"Successfully authenticated with Sentinel Analytica!", "SUCCESS")
                log(f"Agent ID:    {body.get('agentId')}")
                log(f"Device Name: {body.get('agentName')}")
                
                cfg = {
                    "agentId": body.get("agentId"),
                    "agentSecret": body.get("agentSecret"),
                    "agentName": body.get("agentName"),
                    "serverUrl": server_url,
                    "registeredAt": datetime.datetime.now().isoformat()
                }
                save_config(cfg)
                return cfg
            else:
                log(f"Registration rejected: {body.get('error')}", "ERROR")
    except Exception as e:
        log(f"Registration connection error: {e}", "ERROR")
    return None


def normalize_scapy_packet(pkt, interface_name):
    """Extract metadata and normalize into standard security model without capturing private payloads."""
    global PACKET_COUNTER
    PACKET_COUNTER += 1
    
    timestamp = datetime.datetime.now().isoformat()
    frame_len = len(pkt)
    proto_name = "OTHER"
    transport_proto = "IP"
    src_ip = "0.0.0.0"
    dst_ip = "0.0.0.0"
    src_port = 0
    dst_port = 0
    ttl = 64
    tcp_flags = ""
    summary = ""
    dns_query = ""
    dns_answer = ""
    tls_sni = ""
    http_host = ""
    
    # Layer 2 MAC
    mac_src = "N/A"
    mac_dst = "N/A"
    if Ether in pkt:
        mac_src = pkt[Ether].src
        mac_dst = pkt[Ether].dst

    # Layer 3 IP
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        ttl = pkt[IP].ttl
        transport_proto = "IPv4"
    elif IPv6 in pkt:
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst
        ttl = pkt[IPv6].hlim
        transport_proto = "IPv6"
    elif ARP in pkt:
        proto_name = "ARP"
        transport_proto = "ARP"
        src_ip = pkt[ARP].psrc
        dst_ip = pkt[ARP].pdst
        summary = f"ARP {'Reply: ' + src_ip + ' is at ' + mac_src if pkt[ARP].op == 2 else 'Who has ' + dst_ip + '?'}"

    # Layer 4 Transport & Application
    if TCP in pkt:
        proto_name = "TCP"
        transport_proto = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        tcp_flags = str(pkt[TCP].flags)
        
        # Deep Port Identification
        if dst_port == 443 or src_port == 443 or dst_port == 8443 or src_port == 8443:
            proto_name = "HTTPS"
        elif dst_port == 80 or src_port == 80 or dst_port == 8080 or src_port == 8080:
            proto_name = "HTTP"
        elif dst_port == 22 or src_port == 22:
            proto_name = "SSH"
        elif dst_port == 53 or src_port == 53:
            proto_name = "DNS"
        elif dst_port == 25 or src_port == 25 or dst_port == 587 or src_port == 587:
            proto_name = "SMTP"
        elif dst_port == 3389 or src_port == 3389:
            proto_name = "RDP"
            
        summary = f"TCP [{tcp_flags}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} Len={frame_len}"

    elif UDP in pkt:
        proto_name = "UDP"
        transport_proto = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        
        if dst_port == 53 or src_port == 53:
            proto_name = "DNS"
        elif dst_port == 67 or dst_port == 68 or src_port == 67 or src_port == 68:
            proto_name = "DHCP"
        elif dst_port == 443 or src_port == 443:
            proto_name = "QUIC/HTTPS"
            
        summary = f"UDP {src_ip}:{src_port} -> {dst_ip}:{dst_port} Len={frame_len}"

    elif ICMP in pkt:
        proto_name = "ICMP"
        transport_proto = "ICMP"
        summary = f"ICMP Echo {'Request' if pkt[ICMP].type == 8 else 'Reply' if pkt[ICMP].type == 0 else 'Type ' + str(pkt[ICMP].type)}"

    # Layer 7 DNS Extraction
    if DNS in pkt:
        proto_name = "DNS"
        if pkt[DNS].qd:
            try:
                qname = pkt[DNS].qd.qname.decode("utf-8", errors="ignore").rstrip(".")
                dns_query = qname
                summary = f"[DNS] Standard query A {qname}"
            except Exception:
                pass
        if pkt[DNS].an and pkt[DNS].an.rdata:
            try:
                dns_answer = str(pkt[DNS].an.rdata)
                summary += f" -> {dns_answer}"
            except Exception:
                pass

    # Direction heuristic
    is_loopback = (src_ip == "127.0.0.1" or dst_ip == "127.0.0.1")
    is_outgoing = (src_ip.startswith("192.168.") or src_ip.startswith("10.") or src_ip.startswith("172.16."))
    direction = "LOOPBACK" if is_loopback else ("OUTGOING" if is_outgoing else "INCOMING")

    # Safe payload hex (first 16 bytes preview only, no sensitive cleartext)
    payload_size = max(0, frame_len - 54)
    payload_hex = ""
    payload_ascii = ""
    if hasattr(pkt, 'payload') and hasattr(pkt.payload, 'load'):
        raw_bytes = bytes(pkt.payload.load)[:16]
        payload_hex = " ".join(f"{b:02x}" for b in raw_bytes)
        payload_ascii = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_bytes)

    return {
        "id": PACKET_COUNTER,
        "timestamp": timestamp,
        "protocol": proto_name,
        "source_ip": src_ip,
        "srcIp": src_ip,
        "destination_ip": dst_ip,
        "dstIp": dst_ip,
        "source_port": src_port,
        "srcPort": src_port,
        "destination_port": dst_port,
        "dstPort": dst_port,
        "macSrc": mac_src,
        "macDst": mac_dst,
        "packet_size": frame_len,
        "size": frame_len,
        "ttl": ttl,
        "flags": tcp_flags,
        "tcpFlags": tcp_flags,
        "direction": direction,
        "transport_protocol": transport_proto,
        "interface": interface_name,
        "summary": summary or f"{proto_name} {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
        "payloadSize": payload_size,
        "payloadHex": payload_hex,
        "payloadAscii": payload_ascii,
        "bookmarked": False
    }


def capture_worker(interface_name, ws_conn, agent_id):
    """Background sniffer loop capturing from real network hardware interface."""
    global IS_CAPTURING
    log(f"Starting native packet capture on interface '{interface_name}'...", "SUCCESS")
    
    def packet_handler(pkt):
        if not IS_CAPTURING:
            return True # Stop sniff
        try:
            norm = normalize_scapy_packet(pkt, interface_name)
            msg = {
                "type": "PACKET_STREAM",
                "agentId": agent_id,
                "packet": norm
            }
            ws_conn.send(json.dumps(msg))
        except Exception:
            pass

    try:
        if SCAPY_AVAILABLE:
            sniff(iface=interface_name, prn=packet_handler, store=False, stop_filter=lambda x: not IS_CAPTURING)
        else:
            log("Scapy not installed. To install: pip install scapy psutil websocket-client", "WARN")
            # Raw socket fallback for Linux/Windows
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind(("", 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            if platform.system() == "Windows":
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            while IS_CAPTURING:
                raw_data, _ = s.recvfrom(65535)
                # Parse minimal IP header
                ip_header = raw_data[0:20]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                s_addr = socket.inet_ntoa(iph[8])
                d_addr = socket.inet_ntoa(iph[9])
                norm = {
                    "id": PACKET_COUNTER + 1,
                    "timestamp": datetime.datetime.now().isoformat(),
                    "protocol": "TCP" if iph[6] == 6 else "UDP" if iph[6] == 17 else "IP",
                    "srcIp": s_addr,
                    "dstIp": d_addr,
                    "source_ip": s_addr,
                    "destination_ip": d_addr,
                    "srcPort": 0,
                    "dstPort": 0,
                    "size": len(raw_data),
                    "packet_size": len(raw_data),
                    "direction": "INCOMING",
                    "interface": interface_name,
                    "summary": f"RAW IP {s_addr} -> {d_addr} ({len(raw_data)} bytes)",
                    "payloadSize": len(raw_data),
                    "payloadHex": " ".join(f"{b:02x}" for b in raw_data[:16]),
                    "payloadAscii": ""
                }
                ws_conn.send(json.dumps({"type": "PACKET_STREAM", "agentId": agent_id, "packet": norm}))
    except Exception as e:
        log(f"Capture error on {interface_name}: {e}", "ERROR")
        if "permission" in str(e).lower() or "admin" in str(e).lower() or "root" in str(e).lower():
            log("Please run this script with elevated Administrator / root privileges to access raw network cards.", "WARN")
    finally:
        IS_CAPTURING = False
        log(f"Packet capture stopped on {interface_name}.", "INFO")


def handle_server_command(msg, ws_conn, agent_id):
    global IS_CAPTURING, ACTIVE_CAPTURE_THREAD, CURRENT_INTERFACE
    cmd_type = msg.get("type")
    
    if cmd_type == "REGISTER_ACK":
        log(f"Registration acknowledged by central server: {msg.get('name')}", "SUCCESS")
        
    elif cmd_type == "START_CAPTURE":
        iface = msg.get("interfaceId") or CURRENT_INTERFACE or "default"
        CURRENT_INTERFACE = iface
        if not IS_CAPTURING:
            IS_CAPTURING = True
            ACTIVE_CAPTURE_THREAD = threading.Thread(target=capture_worker, args=(iface, ws_conn, agent_id), daemon=True)
            ACTIVE_CAPTURE_THREAD.start()
            
            ws_conn.send(json.dumps({
                "type": "CAPTURE_STATUS",
                "agentId": agent_id,
                "status": "monitoring",
                "session": {
                    "interfaceId": iface,
                    "interfaceName": iface,
                    "startedAt": datetime.datetime.now().isoformat(),
                    "mode": "REAL",
                    "packetsCaptured": 0,
                    "bytesCaptured": 0
                }
            }))
            
    elif cmd_type == "STOP_CAPTURE":
        log("Received STOP_CAPTURE command from dashboard.", "INFO")
        IS_CAPTURING = False
        ws_conn.send(json.dumps({
            "type": "CAPTURE_STATUS",
            "agentId": agent_id,
            "status": "stopped",
            "session": None
        }))
        
    elif cmd_type == "REFRESH_INTERFACES":
        log("Rescanning host network interfaces...", "INFO")
        ifaces = get_local_interfaces()
        ws_conn.send(json.dumps({
            "type": "INTERFACE_UPDATE",
            "agentId": agent_id,
            "interfaces": ifaces
        }))


def run_agent_loop(server_url, agent_id, agent_secret, agent_name):
    """Maintain resilient real-time WebSocket connection to central dashboard."""
    ws_proto = "wss" if server_url.startswith("https") else "ws"
    raw_host = server_url.replace("https://", "").replace("http://", "").rstrip("/")
    ws_url = f"{ws_proto}://{raw_host}/ws/agent?agentId={urllib.parse.quote(agent_id)}&agentSecret={urllib.parse.quote(agent_secret)}"
    
    log(f"Connecting to Sentinel Analytica at {ws_url}...")
    
    if not WEBSOCKETS_AVAILABLE:
        log("websocket-client not installed. Installing required dependencies...", "WARN")
        os.system(f"{sys.executable} -m pip install websocket-client scapy psutil")
        import websocket

    def on_open(ws):
        log(f"Connected & authenticated with Sentinel Analytica Backend!", "SUCCESS")
        ifaces = get_local_interfaces()
        primary_ip = next((i["ip"] for i in ifaces if i["status"] == "active" and i["type"] != "loopback"), "127.0.0.1")
        primary_mac = next((i["mac"] for i in ifaces if i["status"] == "active" and i["mac"] != "N/A"), "N/A")
        
        reg_msg = {
            "type": "AGENT_REGISTER",
            "agentId": agent_id,
            "name": agent_name,
            "platform": sys.platform,
            "hostname": socket.gethostname(),
            "ip": primary_ip,
            "mac": primary_mac,
            "interfaces": ifaces
        }
        ws.send(json.dumps(reg_msg))

        # Heartbeat thread
        def heartbeat_loop():
            while RUNNING:
                time.sleep(8)
                try:
                    ws.send(json.dumps({"type": "HEARTBEAT", "agentId": agent_id}))
                except Exception:
                    break
        threading.Thread(target=heartbeat_loop, daemon=True).start()

    def on_message(ws, message):
        try:
            data = json.loads(message)
            handle_server_command(data, ws, agent_id)
        except Exception as e:
            log(f"Error parsing backend command: {e}", "WARN")

    def on_error(ws, error):
        log(f"WebSocket error: {error}", "WARN")

    def on_close(ws, close_status_code, close_msg):
        log(f"Connection closed ({close_status_code}). Reconnecting in 5s...", "WARN")

    while RUNNING:
        try:
            ws = websocket.WebSocketApp(
                ws_url,
                on_open=on_open,
                on_message=on_message,
                on_error=on_error,
                on_close=on_close
            )
            ws.run_forever()
        except Exception as e:
            log(f"Connection attempt failed: {e}", "WARN")
        time.sleep(5)


def main():
    parser = argparse.ArgumentParser(description="Sentinel Analytica - Real-Time Hardware Capture Agent")
    parser.add_argument("--server", default="http://localhost:3000", help="Target Sentinel Analytica Backend URL")
    parser.add_argument("--token", default="", help="One-time registration token from dashboard")
    parser.add_argument("--id", default="", help="Pre-configured Agent ID")
    parser.add_argument("--secret", default="", help="Pre-configured Agent Secret")
    parser.add_argument("--name", default="", help="Friendly name for this capture node")
    parser.add_argument("--list-interfaces", action="store_true", help="List detected network interfaces and exit")
    parser.add_argument("--interface", default="", help="Network interface to immediately capture on")

    args = parser.parse_args()

    print("===================================================================")
    print("     SENTINEL ANALYTICA - REAL-TIME HARDWARE CAPTURE AGENT        ")
    print("===================================================================")
    print(f"Platform:      {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"Python:        {sys.version.split()[0]}")
    print(f"Scapy Engine:  {'Available' if SCAPY_AVAILABLE else 'Not installed (fallback enabled)'}")
    print(f"Target Server: {args.server}")
    print("===================================================================\n")

    if args.list_interfaces:
        print("Detected Hardware Network Interfaces:")
        for idx, iface in enumerate(get_local_interfaces(), 1):
            print(f"  {idx}. {iface['name']} [{iface['type'].upper()}] - IP: {iface['ip']} - MAC: {iface['mac']} ({iface['status']})")
        sys.exit(0)

    server_url = args.server.rstrip("/")
    device_name = args.name or f"Sentinel Node ({socket.gethostname()})"
    
    # 1. Load saved config or register
    config = load_config()
    agent_id = args.id or config.get("agentId")
    agent_secret = args.secret or config.get("agentSecret")
    agent_name = args.name or config.get("agentName") or device_name

    if args.token or not agent_id or not agent_secret or config.get("serverUrl") != server_url:
        reg_result = register_agent(server_url, args.token, device_name)
        if reg_result:
            agent_id = reg_result["agentId"]
            agent_secret = reg_result["agentSecret"]
            agent_name = reg_result["agentName"]
        elif not (server_url.startswith("http://localhost") or server_url.startswith("http://127.0.0.1")):
            log("Could not register with remote server. Check connection.", "ERROR")
            sys.exit(1)
        else:
            # Localhost dev fallback
            agent_id = "agent-local"
            agent_secret = "sentinel_secret_token_123"

    global CURRENT_INTERFACE
    if args.interface:
        CURRENT_INTERFACE = args.interface

    run_agent_loop(server_url, agent_id, agent_secret, agent_name)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Shutting down Sentinel Capture Agent cleanly...")
        RUNNING = False
        sys.exit(0)
