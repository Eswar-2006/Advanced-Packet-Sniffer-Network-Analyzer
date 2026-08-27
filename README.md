<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://ai.google.dev/static/site-assets/images/share-ais-513315318.png" />
</div>

# Run and deploy your AI Studio app

This contains everything you need to run your app locally.

View your app in AI Studio: https://ai.studio/apps/7c03a433-28b2-4f70-8a57-e75be6ad20cf

## Run Locally

**Prerequisites:**  Node.js


1. Install dependencies:
   `npm install`
2. Set the `GEMINI_API_KEY` in [.env.local](.env.local) to your Gemini API key
3. Run the app:
   `npm run dev`

## Available Packet Sniffing Tools & Command Reference

This project utilizes both real-time packet capturing tools and simulation engines to analyze network traffic. Below is the documentation of each tool, its role in the project, and how to use it.

---

### 1. tshark (Wireshark Command Line Interface)
`tshark` is the primary CLI packet dissection tool utilized by the backend server (`server.ts`) to stream live packet data in real-time.

*   **How it is used in the project:** 
    The Node/Express backend spawns `tshark` as a child process using specific field extractions to pipe tab-separated data into the application for real-time visualization.
*   **Installation:** 
    *   **Windows:** Install [Wireshark](https://www.wireshark.org/download.html). Ensure you check the box to add Wireshark to your system PATH during installation.
    *   **macOS:** Install via Homebrew: `brew install wireshark`
    *   **Linux (Ubuntu/Debian):** Run `sudo apt-get install tshark` and choose "Yes" to allow non-superuser captures.

#### Essential `tshark` Commands:
*   **List all available network interfaces:**
    ```bash
    tshark -D
    ```
    *(The backend uses this API at `/api/interfaces` to let you select interfaces from the dashboard.)*

*   **Start a live field-based packet capture (similar to backend engine):**
    ```bash
    tshark -i <interface_name_or_index> -l -n -T fields -E separator=\t -e frame.number -e frame.time_epoch -e ip.proto -e ip.src -e ip.dst -e frame.len -e tcp.srcport -e tcp.dstport
    ```

*   **Capture a fixed number of packets and print summary:**
    ```bash
    tshark -i 1 -c 20
    ```

*   **Capture traffic and save to a pcap file:**
    ```bash
    tshark -i 1 -w capture.pcap
    ```

---

### 2. Wireshark (Graphical User Interface)
Wireshark is the world's foremost network protocol analyzer, used for manual deep-dive analysis of saved packet streams.

*   **How it is used in the project:**
    Used externally to open and verify standard `.pcap` files or to cross-verify the dashboard's analytics.
*   **Usage Steps for Accurate Sniffing:**
    1. Open the Wireshark GUI.
    2. Double-click the active network interface (e.g., `Wi-Fi` or `Ethernet`) that has network activity.
    3. Use the **Filter bar** to search for specific traffic:
        *   Show only HTTP traffic: `http`
        *   Show a specific IP: `ip.addr == 192.168.1.1`
        *   Show TCP traffic on port 443 (HTTPS): `tcp.port == 443`
        *   Show DNS queries: `dns`
    4. Save captures via `File > Save As` in `.pcap` or `.pcapng` format to load them into external tools.

---

### 3. Npcap / WinPcap (Windows) & libpcap (macOS/Linux)
These are system-level packet capture drivers/libraries required to capture raw network traffic from network interfaces.

*   **How it is used in the project:**
    `tshark` requires these drivers to place network interfaces into **promiscuous mode** (or monitor mode) to read packets.
*   **Setup/Steps:**
    *   **Windows:** Automatically installed during the Wireshark installation. Ensure "Npcap" is selected and run with administrator privileges.
    *   **macOS/Linux:** Native driver libraries (`libpcap`) are already bundled. You may need to run commands with `sudo` permissions or add your user to the `wireshark` group.

---

### 4. Scapy (Python Framework)
*For advanced programmatic sniffing, scripting, and custom analysis modules (highlighted in the technical design specs).*

*   **How to use Scapy for packet sniffing:**
    1. Ensure Python 3 is installed.
    2. Install Scapy: `pip install scapy`
    3. Run a custom sniffing script:
        ```python
        from scapy.all import sniff

        # Callback function to process each packet
        def process_packet(packet):
            if packet.haslayer('IP'):
                print(f"[{packet.summary()}] Src: {packet['IP'].src} -> Dst: {packet['IP'].dst}")

        # Sniff 20 packets on the default interface
        print("Sniffing started...")
        sniff(prn=process_packet, count=20)
        ```

---

### 5. Built-in Real-Time Simulator (Offline Fallback)
If `tshark` is not installed or the application lacks administrator permission to capture raw sockets, the project automatically falls back to its built-in traffic simulator.

*   **How it works:**
    Generates realistic, structured TCP, UDP, HTTP, HTTPS, DNS, ICMP, and ARP traffic bursts in memory, allowing you to test and explore the React dashboard, charts, connections tracker, and AI Copilot completely offline and setup-free.

