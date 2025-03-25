# Swiss Army Knife Scanner

A multi-tool network scanner that does it all—because why settle for less?

## Overview

Welcome to the **Swiss Army Knife Scanner**, a versatile network analysis tool built with Python and Qt, packed with features. Whether you’re scanning ports, visualizing network traffic, training AI models to identify devices, or SSH-ing into multiple systems at once, this tool has you covered. It’s still under development as I experiment with new ideas, but it’s already in a reliable, working state. I’m a student still mastering programming, so please bear with me and feel free to raise any issues you might find! (There are some duplicate functions, but they’ll be cleaned up or replaced with better solutions down the line.)

With a slick UI, threaded performance, and a hidden pirate mode (`Ctrl+Alt+G`), it’s fast, functional, and fairly fun.

For network administrators, cybersecurity professionals, hobbyists, and IT enthusiasts alike, this tool combines advanced networking capabilities with AI-driven insights and a suite of utilities to comprehensively scan, monitor, manage, and analyze your network.

---

## Features

### Core Features

- **Network Scanning**  
  - Scan IP ranges (e.g., 192.168.1.0/24) for open ports, device details (MAC addresses, hostnames, vendors), and service banners.  
  - Uses `scapy` for packet crafting, supplemented with ARP lookups and PyShark for packet analysis.  
  - Customizable port ranges and protocols (TCP/UDP).

- **Device Monitoring**  
  - Continuously ping devices to track uptime and latency.  
  - Remote access via SSH, RDP, AnyDesk, RustDesk, and Wake-on-LAN.  
  - Alerts for status changes and whitelist support to flag rogue devices.

- **Traffic Visualization**  
  - Live packet capture and visualization using `pyshark` and QGraphicsView.  
  - Filter packets by protocol, source, or destination.

- **Speed Testing & Network Stats**  
  - Measure download/upload speeds using `speedtest-cli`.  
  - Compute ping/packet statistics with `numpy` and display histograms.

- **Remote Commands & SSH Operations**  
  - Connect to devices using `paramiko`, `netmiko`, `pexpect`, or `napalm`.  
  - Broadcast commands to multiple devices simultaneously.

- **Network Mapping & Graph Analysis**  
  - Export static (`PNG`) or interactive (`HTML`) graphs with `networkx` and `pyvis`.  
  - Analyze topology with `igraph` and optional `graph-tool`.

- **Voice Commands**  
  - Hands-free control via `speech_recognition` (e.g., say `"scan 192.168.1.0/24"` to begin scanning).

- **Easter Eggs**  
  - Hit `Ctrl+Alt+G` for pirate mode—argh, matey!  
  - Optional "Retro Mode" (`Ctrl+Alt+R`) for a green-screen terminal aesthetic.

### AI Capabilities

- **Device Classification**  
  - Train a model using scikit-learn’s RandomForestClassifier to predict device types (e.g., router, server, IoT).  
  - Accuracy improves with user-labeled training data.

- **Anomaly Detection & Performance Prediction**  
  - Detect unusual network behavior with IsolationForest.  
  - Forecast ping times using RandomForestRegressor and visualize trends.

- **Small Language Model (SLM) Integration**  
  - Powered by DistilBERT (via transformers) for natural language processing on SSH outputs.  
  - Suggest commands or flag issues like resource exhaustion.

### Additional Utilities & Enhancements

- **Broadcast & Batch Commands**  
  - Send SSH commands (e.g., reboot, ifconfig) to all devices at once.

- **History Management**  
  - Save scan results with timestamps and metadata; export history (CSV, JSON, PDF).

- **Security Features**  
  - Encrypt SSH credentials and whitelist data using AES-256.  
  - Detect firewalls and perform vulnerability scans by cross-referencing open ports with CVE databases.

- **Extensibility**  
  - Plugin system for adding custom modules (e.g., SNMP support, DNS enumeration).  
  - Scripting interface to execute user-defined Python scripts for custom workflows.

- **Remote Desktop Integration & API Testing**  
  - Launch remote sessions (RDP/AnyDesk/RustDesk) directly from the UI.  
  - Test APIs or web services by sending HTTP/HTTPS requests.

---

## Requirements

### Prerequisites

- **Python:** Version 3.8 or higher (Python 3.11 is recommended for the installer script).
- **Root/Admin Privileges:** Required for `scapy` and `pyshark` to access raw packets.
- **Operating System:** Linux (Ubuntu, Debian), Windows (10/11), macOS (10.15+).

### External Tools (Optional)

- `wakeonlan` (for Wake-on-LAN).
- `mstsc` (Windows), `anydesk`, `rustdesk` (for remote desktop support).

### Python Packages

```sh
pip install paramiko netifaces PySide6 scapy dnspython pandas networkx netmiko napalm requests pexpect pyshark python-igraph speedtest-cli matplotlib scikit-learn pyvis nltk SpeechRecognition pyaudio transformers torch cryptography
```

#### Optional (Advanced Install)

- **graph-tool** – For enhanced graph analysis:

  ```sh
  conda install -c conda-forge graph-tool
  ```

*If missing, `build_graphtool_graph` fails, but core features remain intact.*

---

## Installation

1. **Clone the Repository**

   ```sh
   git clone https://github.com/coff33ninja/swiss-army-knife-scanner.git
   cd swiss-army-knife-scanner
   ```

2. **Run the Installer**

   For quick setup, simply execute `launch.bat` in the command prompt or double-click it. This script will:
   
   - ✅ Check for Python 3.11 or higher.
   - ✅ Set up a virtual environment.
   - ✅ Install all required dependencies.
   - ✅ Launch the application with administrative privileges (you may need to accept a UAC prompt).

   🔹 **Note:** Ensure Python 3.11 or higher is installed before running the batch file.

3. **Manual Setup (Alternative Method)**

   ```sh
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate     # Windows
   pip install -r requirements.txt
   ```

4. **Run with Privileges**

   - **Linux/macOS:**

     ```sh
     sudo python3 swiss_army_knife_scanner.py --verbose
     ```

   - **Windows:**

     Right-click `launch.bat` → "Run as Administrator"  
     *(Only if the VBA fails to make .bat run as Administrator.)*

Additionally, the tool supports command-line arguments:

- `--verbose`: Enable detailed logging.
- `--install`: Install dependencies and exit.
- `--verify`: Check imports and exit.
- `--config <file>`: Load a custom config file.
- `--headless`: Run scans without the GUI (outputs to console/JSON).

---

## Usage

### Launching the Tool

- On startup, a dialog prompts you to choose between:
  - **Monitored Devices UI:** For continuous monitoring of specific devices.
  - **Swiss Army Knife Scanning UI:** For comprehensive network scanning, SSH operations, AI insights, and more.

### Monitored Devices UI

- **Features:**
  - Add/remove devices by IP or hostname.
  - Real-time ping status (green = online, red = offline, yellow = high latency).
  - Right-click context menu for SSH, RDP, WoL, traceroute, etc.
  - Whitelist devices to bypass anomaly detection.
  - Export the device list to JSON.

### Swiss Army Knife Scanner UI

- **Components:**
  - **Network Selection:** Choose from local interfaces or input a custom CIDR.
  - **Port Selection:** Check common ports (SSH:22, HTTP:80, HTTPS:443) or enter custom ports.
  - **SSH Section:** Input IP, username, password, and commands.
  - **HTTP Query:** Test APIs by specifying URLs and methods.
  - **Output Tree & Progress Bar:** View hierarchical scan results and track progress.
  
- **Usage Examples:**
  - **Basic Network Scan:**  
    Select `192.168.1.0/24`, check ports `22, 80, 443`, then click "Scan Network" to see IPs, open ports, MACs, and hostnames.
  - **SSH Connection:**  
    Enter IP `192.168.1.1`, username, and password, then click "SSH (paramiko)" to see system stats like uptime.
  - **AI Analysis:**  
    Run a scan, click "AI Insights" to view device type predictions, and use "Train AI" to label devices and retrain the model.
  - **Voice Control:**  
    Click "Voice Command" and speak a command (e.g., "scan 192.168.1.0/24") to start a scan.
  - **Traffic Visualization:**  
    Click "Traffic Visualizer," select an interface (e.g., `eth0`), and watch real-time packet flows.

---

## How It Works

- **Scanning:** Uses `scapy` for ARP/TCP scans, parallelized with `ThreadPoolExecutor`.
- **Monitoring:** A dedicated `MonitorThread` pings devices every 5 seconds.
- **AI Operations:**  
  - **Training:** `AITrainer` collects data and trains a RandomForestClassifier.
  - **Prediction:** `AIPredictor` provides device type predictions based on the trained model.
- **User Interface:** Built with `PySide6` and multi-threaded (via QThread) for smooth responsiveness.

---

## Files Used

- **network_scan_history.json** – Scan logs.
- **monitored_devices.json** – Tracked devices.
- **scanner_config.json** – Configuration (ports, whitelist, API keys).
- **device_classifier.pkl** – Trained AI model.
- **ai_dataset.csv** – Training data.

---

## Training the AI

1. **Open "Train AI" in the Swiss Army Knife UI.**
2. **Choose a Mode:**
   - **Rescan Network:** Use fresh scan data.
   - **Ping Monitored Devices:** Use continuous ping stats.
   - **Load History:** Retrieve data from past scans.
   - **Manual Input:** Add IP, ports, MAC, and hostname manually.
3. **Label Devices:** Tag devices as Router, Server, Desktop, IoT, etc.
4. **Train the Model:** Generate `device_classifier.pkl` and review accuracy.
5. **Predict:** After training, run a scan and click "AI Insights" to see predictions.

---

## Examples

### Scan a Network

1. Select `192.168.1.0/24` and check ports `22, 80, 443`.
2. Click "Scan Network".

**Result:**

```
IP: 192.168.1.1 (router.local)
Ports: [80, 443]
MAC: 00:14:22:01:23:45
```

### Train AI

1. Click "Train AI" → "Rescan Network".
2. Label `192.168.1.1` as "Router".
3. Train the model.
4. On the next scan, click "AI Insights" to view the predicted device type.

---

## Code Structure & Customization

### Key Modules

- **Utilities:**  
  - `install_requirements()`: Automates dependency installation.
  - `smart_mac_lookup()`: Retrieves MAC addresses via multiple methods (Scapy, Nmap, ARP, PyShark).
  - `scan_ip()`: Performs multi-threaded port scanning.
- **QThread Classes:**  
  - `ScanThread`: Handles background scanning.
  - `MonitorThread`: Continuously pings devices.
  - `AITrainer` and `AIPredictor`: Manage AI model operations.
- **UI Classes:**  
  - `StartupDialog`: Initial interface choice.
  - `MonitoredDevicesUI`: Device monitoring dashboard.
  - `SwissArmyKnifeUI`: Main scanner interface.
  - `TrafficVisualizer`: Displays packet visualization.

### File Management & Customization

- **Config File:** `scanner_config.json` for ports, themes, and whitelist settings.
- **History File:** `network_scan_history.json` for past scan data.
- **Logs:** `scanner.log` for verbose debugging.
- **Customization:**  
  - Modify `COMMON_PORTS` in code or via config.
  - Extend `AITrainer` with new algorithms (e.g., XGBoost).
  - Update themes by editing CSS files or using `setStyleSheet()`.
  - Add plugins in the `plugins/` directory for extra features.

---

## Troubleshooting

- **Permission Errors:** Run with `sudo` (Linux/macOS) or as Administrator (Windows).
- **Missing Packages:** Re-run `pip install -r requirements.txt` or check `scanner.log`.
- **AI Model Issues:** Ensure `ai_dataset.csv` exists and contains sufficient data.
- **GUI Problems:** Update PySide6 or verify Qt compatibility.
- **Voice Control Failures:** Test your microphone and reinstall PyAudio if needed.
- **Nmap or External Tools:** Install them manually if not auto-detected.

---

## Future Enhancements

- Still thinking ;)

---

## Contributing

Fork it, tweak it, PR it! Got a wild idea or find a bug? Open an issue and let’s make this tool legendary.

---

## License

📝 **MIT License** – Use it, tweak it, just don’t blame me if it wakes your smart fridge.

---

## Credits

Built with love, caffeine, and chaos by [Your Name].

---

Feel free to further modify sections as your project evolves. Happy scanning!

## Credits

Built with love, caffeine, and chaos by coff33ninja.
