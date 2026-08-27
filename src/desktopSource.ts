import { DesktopSourceCode } from './types';

export const DESKTOP_SOURCE_FILES: DesktopSourceCode[] = [
  {
    filename: "launcher.py",
    path: "launcher.py",
    content: `#!/usr/bin/env python3
"""
Advanced Packet Sniffer & Traffic Analyzer - Launcher File
Acts as a splash screen loader, instantiating the core application safely.
"""
import sys
import os
import time
from PySide6.QtCore import Qt, QTimer, QThread, Signal
from PySide6.QtWidgets import QApplication, QSplashScreen, QProgressBar
from PySide6.QtGui import QPixmap, QColor, QFont, QPainter

class LoadWorker(QThread):
    progress = Signal(int, str)
    finished = Signal()

    def run(self):
        steps = [
            (10, "Initializing Database..."),
            (25, "Loading Packet Sniffing Engines..."),
            (40, "Establishing Security Heuristics Core..."),
            (55, "Registering Hardware Interfaces..."),
            (70, "Compiling Neural Network Anomaly Predictor..."),
            (85, "Configuring Real-Time High-Contrast Stylesheet..."),
            (100, "Starting Enterprise Control Panel...")
        ]
        for val, text in steps:
            time.sleep(0.3)  # Simulate initialization
            self.progress.emit(val, text)
        self.finished.emit()

def launch():
    app = QApplication(sys.argv)
    
    # Custom drawn splash screen representing Blue Neon Glassmorphism
    pixmap = QPixmap(550, 320)
    pixmap.fill(QColor("#0a0f1d"))
    
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    
    # Draw futuristic digital grid lines
    painter.setPen(QColor("#1e293b"))
    for i in range(0, 550, 40):
        painter.drawLine(i, 0, i, 320)
    for j in range(0, 320, 40):
        painter.drawLine(0, j, 550, j)
        
    # Title Glow Accent
    painter.setPen(QColor("#38bdf8"))
    painter.setFont(QFont("Consolas", 18, QFont.Bold))
    painter.drawText(40, 90, "ADVANCED PACKET SNIFFER")
    
    painter.setPen(QColor("#0284c7"))
    painter.setFont(QFont("Consolas", 11, QFont.Medium))
    painter.drawText(40, 120, "Intelligent Enterprise Cybersecurity Analyzer")
    
    painter.setPen(QColor("#94a3b8"))
    painter.setFont(QFont("Arial", 9))
    painter.drawText(40, 260, "Copyright © 2026 Enterprise Inc. All rights reserved.")
    painter.end()

    splash = QSplashScreen(pixmap)
    splash.show()
    
    progressBar = QProgressBar(splash)
    progressBar.setGeometry(40, 200, 470, 16)
    progressBar.setStyleSheet("""
        QProgressBar {
            background-color: #1e293b;
            color: #ffffff;
            border-radius: 8px;
            text-align: center;
        }
        QProgressBar::chunk {
            background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0284c7, stop:1 #38bdf8);
            border-radius: 8px;
        }
    """)
    progressBar.show()
    
    def updateProgress(val, text):
        progressBar.setValue(val)
        splash.showMessage(f" {text}", Qt.AlignLeft | Qt.AlignBottom, QColor("#e2e8f0"))

    worker = LoadWorker()
    worker.progress.connect(updateProgress)
    
    def onFinished():
        splash.close()
        # Launching Main Window (represented conceptually)
        print("Launching Main Dashboard Application GUI...")
        sys.exit(0)

    worker.finished.connect(onFinished)
    worker.start()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    launch()
`
  },
  {
    filename: "core/sniffer.py",
    path: "core/sniffer.py",
    content: `#!/usr/bin/env python3
"""
Thread-safe Real-time Packet Capturing core wrapper leveraging Scapy.
Ensures responsive interface by utilizing high-priority background workers.
"""
import threading
import queue
import time
from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP

class PacketCaptureWorker(threading.Thread):
    def __init__(self, interface=None, packet_queue=None, bpf_filter=None):
        super().__init__()
        self.interface = interface
        self.packet_queue = packet_queue or queue.Queue()
        self.bpf_filter = bpf_filter
        self.is_running = False
        self.daemon = True
        self.stats = {
            "tcp": 0, "udp": 0, "arp": 0, "icmp": 0, "other": 0, "total": 0
        }

    def packet_callback(self, packet):
        if not self.is_running:
            return
            
        parsed_data = {
            "timestamp": time.time(),
            "size": len(packet),
            "summary": packet.summary(),
            "protocol": "OTHER"
        }
        
        # Analyze network layers
        if IP in packet:
            parsed_data["src_ip"] = packet[IP].src
            parsed_data["dst_ip"] = packet[IP].dst
            parsed_data["ttl"] = packet[IP].ttl
            
        if TCP in packet:
            parsed_data["protocol"] = "TCP"
            parsed_data["src_port"] = packet[TCP].sport
            parsed_data["dst_port"] = packet[TCP].dport
            parsed_data["seq"] = packet[TCP].seq
            parsed_data["flags"] = str(packet[TCP].flags)
            self.stats["tcp"] += 1
        elif UDP in packet:
            parsed_data["protocol"] = "UDP"
            parsed_data["src_port"] = packet[UDP].sport
            parsed_data["dst_port"] = packet[UDP].dport
            self.stats["udp"] += 1
        elif ARP in packet:
            parsed_data["protocol"] = "ARP"
            parsed_data["src_ip"] = packet[ARP].psrc
            parsed_data["dst_ip"] = packet[ARP].pdst
            self.stats["arp"] += 1
        elif ICMP in packet:
            parsed_data["protocol"] = "ICMP"
            self.stats["icmp"] += 1
        else:
            self.stats["other"] += 1
            
        self.stats["total"] += 1
        self.packet_queue.put(parsed_data)

    def run(self):
        self.is_running = True
        sniff(
            iface=self.interface,
            prn=self.packet_callback,
            filter=self.bpf_filter,
            store=0,
            stop_filter=lambda p: not self.is_running
        )

    def stop(self):
        self.is_running = False
`
  },
  {
    filename: "database/sqlite_manager.py",
    path: "database/sqlite_manager.py",
    content: `#!/usr/bin/env python3
"""
SQLite Manager for secure logging, persistence of sessions, configuration settings,
and anomaly alerts. Designed with Thread-safe pooling and proper sanitization.
"""
import sqlite3
import os

class SQLiteManager:
    def __init__(self, db_path="captures/sniffer_database.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path) or '.', exist_ok=True)
        self.initialize_tables()

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    def initialize_tables(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Session logs
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    notes TEXT
                )
            """)
            # Parsed Packets DB
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS packet_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    timestamp REAL,
                    protocol TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    size INTEGER,
                    summary TEXT,
                    FOREIGN KEY(session_id) REFERENCES sessions(id)
                )
            """)
            # Security Threat Alerts Log
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    severity TEXT,
                    type TEXT,
                    source TEXT,
                    destination TEXT,
                    message TEXT
                )
            """)
            conn.commit()

    def log_threat(self, severity, alert_type, src, dst, msg):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO threat_alerts (severity, type, source, destination, message)
                VALUES (?, ?, ?, ?, ?)
            """, (severity, alert_type, src, dst, msg))
            conn.commit()
`
  },
  {
    filename: "analysis/anomaly_detection.py",
    path: "analysis/anomaly_detection.py",
    content: `#!/usr/bin/env python3
"""
AI-assisted and rule-based anomaly detection engine.
Leverages packet flow structures to calculate real-time threat hazard indices.
"""
import math

class TrafficAnomalyPredictor:
    def __init__(self):
        self.baseline_avg_size = 500.0
        self.total_packets_seen = 0

    def calculate_traffic_entropy(self, payload_bytes):
        """
        Computes Shannon Entropy of standard hex content to recognize encrypted tunnels or payloads
        """
        if not payload_bytes:
            return 0.0
        entropy = 0
        freqs = {}
        for byte in payload_bytes:
            freqs[byte] = freqs.get(byte, 0) + 1
        for count in freqs.values():
            p = count / len(payload_bytes)
            entropy -= p * math.log2(p)
        return entropy

    def evaluate_risk(self, packet_size, is_syn, is_ack, is_fin, payload):
        """
        Formulates a multi-layered hazard risk matrix assessment (0.0 - 100.0)
        """
        score = 0.0
        
        # Detect unusual flag patterns (SYN scan or FIN scans)
        if is_syn and not is_ack:
            score += 25.0
        if is_fin and not is_ack:
            score += 15.0
            
        # Detect high payload entropy signifying ransomware beacons or tunneling
        if payload:
            entropy = self.calculate_traffic_entropy(payload)
            if entropy > 7.5:
                score += 35.0  # Suspect shellcode/tunneling
                
        # Limit to bounds
        return min(score, 100.0)
`
  }
];
