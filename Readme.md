# Swiss Army Knife Scanner

A multi-tool network scanner that does it all—because why settle for less?

## Overview

Welcome to the Swiss Army Knife Scanner, a versatile network analysis tool built with Python and Qt, packed with features. Whether you’re scanning ports, visualizing network traffic, training AI models to identify devices, or SSH-ing into multiple systems at once, this tool has you covered. It’s still under development as I experiment with new ideas, but it’s already in a reliable, working state. I’m a student still mastering programming, so please bear with me and feel free to raise any issues you might find! There are some duplicate functions, but they’ll be cleaned up or replaced with better solutions down the line.

With a slick UI, threaded performance, and a hidden pirate mode (Ctrl+Alt+G), it’s fast, functional, and fairly fun.

## Features

✅ **Network Scanning** – Scan IP ranges for open ports using `scapy`.
✅ **Device Monitoring** – Real-time ping tracking with Wake-on-LAN, RDP, AnyDesk, and RustDesk support.
✅ **Traffic Visualization** – Live packet flow display with `pyshark`.
✅ **Rogue Detection** – Spot unknown devices with a MAC whitelist.
✅ **Speed Testing** – Measure download/upload speeds via `speedtest-cli`.
✅ **AI Insights** – Train a model to predict device types (Router, Server, Desktop, IoT, etc.).
✅ **Remote Commands** – SSH via `paramiko`, `netmiko`, or `pexpect`; broadcast commands to all devices.
✅ **Network Mapping** – Export static (`PNG`) or interactive (`HTML`) graphs with `networkx` and `pyvis`.
✅ **Graph Analysis** – Topology insights with `networkx`, `igraph`, and optional `graph-tool`.
✅ **Network Stats** – Compute ping/packet stats with `numpy` and visualize histograms.
✅ **Voice Commands** – Control it hands-free with `speech_recognition`.
🦜 **Easter Egg** – Hit `Ctrl+Alt+G` for pirate mode—argh, matey!

---

## Requirements

### Prerequisites

🔹 **Python**: 3.8 or higher.
🔹 **Root/Admin Privileges**: Needed for `scapy` and `pyshark` (raw packet access).
🔹 **External Tools (Optional):**

- `wakeonlan` (for Wake-on-LAN).
- `mstsc` (Windows), `anydesk`, `rustdesk` (remote desktop clients).

### Python Packages

```sh
pip install paramiko netifaces PySide6 scapy dnspython pandas networkx netmiko napalm requests pexpect pyshark python-igraph speedtest-cli matplotlib scikit-learn pyvis nltk SpeechRecognition pyaudio transformers torch
```

#### Optional (Advanced Install)

🔹 `graph-tool` – For enhanced graph analysis.

```sh
conda install -c conda-forge graph-tool
```

*(If missing, ********************************************`build_graphtool_graph`******************************************** fails, but core features remain intact.)*

---

## Installation

1. **Clone the Repository**

```sh
git clone https://github.com/coff33ninja/swiss-army-knife-scanner.git
cd swiss-army-knife-scanner
```

2. &#x20;   Run the Installer

   For quick setup, just execute launch.bat in the command prompt or double-click it. This script will:

   ✅ Check for Python 3.11 or higher.

   ✅ Set up a virtual environment.

   ✅ Install all required dependencies.

   ✅ Launch the application with administrative privileges (you may need to accept a UAC prompt).

   🔹 Note: Ensure Python 3.11 or higher is installed before running the batch file.
3. **Manual Setup (Alternative Method)**

```sh
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
pip install -r requirements.txt
```

4. **Run with Privileges**

🔹 **Linux/macOS:**

```sh
sudo python3 swiss_army_knife_scanner.py --verbose
```

🔹 **Windows:**

Right-click → "Run as Administrator". (Only if the VBA failed to make .bat run as Administrator.)

---

## Usage

### Launching the Tool

- Start with a dialog: pick **Monitored Devices** or **Swiss Army Knife Scanning**.

### **Monitored Devices UI**

- Add IPs, start/stop monitoring, and use right-click menus for RDP/AnyDesk/RustDesk/WOL.
- Whitelist MACs to flag rogue devices.

### **Swiss Army Knife UI**

🖥️ **Scan Network** – Select a network, choose ports, scan for IPs, ports, and MACs.\
🤖 **Train AI** – Rescan, ping, load history, or add data → label devices → train model.\
🔍 **AI Insights** – Get device type predictions post-scan.\
📊 **Traffic Visualizer** – Live packet animation.\
📡 **Speed Test** – Check network performance.\
🔑 **SSH Tools** – Connect via `paramiko`, `netmiko`, `pexpect`, or `napalm`.\
📢 **Broadcast Commands** – Send SSH commands to all devices.\
📈 **Network Stats** – View ping/packet stats and histograms.\
🗺️ **Export Results** – Save scan results (`JSON`) or maps (`PNG/HTML`).\
📜 **History** – View, filter, or clear past scans.\
🎙️ **Voice Commands** – Say `"scan 192.168.1.0/24"` to start scanning.\
🏴‍☠️ **Easter Egg** – Press `Ctrl+Alt+G` for pirate-themed labels!

---

## How It Works

🔹 **Scanning** – `scapy` for ARP/TCP scans, parallelized with `ThreadPoolExecutor`.\
🔹 **Monitoring** – `MonitorThread` pings every 5 seconds.\
🔹 **AI** – `AITrainer` gathers data, `AIPredictor` uses `RandomForestClassifier`.\
🔹 **UI** – Built with `PySide6`, fully threaded for responsiveness.

---

## Files Used

📄 **network\_scan\_history.json** – Scan logs.\
📄 **monitored\_devices.json** – Tracked devices.\
📄 **scanner\_config.json** – Config (ports, whitelist, API keys).\
📄 **device\_classifier.pkl** – Trained AI model.\
📄 **ai\_dataset.csv** – Training data.

---

## Training the AI

1️⃣ **Open "Train AI" in the Swiss Army Knife UI**.\
2️⃣ **Choose Mode:**

- **Rescan Network** – Fresh scan data.
- **Ping Monitored Devices** – Use ping stats.
- **Load History** – Pull from past scans.
- **Manual Input** – Add IP, ports, MAC, hostname manually.

3️⃣ **Label Devices** – Tag as Router, Server, Desktop, IoT, etc.\
4️⃣ **Train Model** – Generate `device_classifier.pkl` and review accuracy.\
5️⃣ **Predict** – Scan, then click "AI Insights" for predictions.

---

## Examples

🔎 **Scan a Network**

1. Select `192.168.1.0/24`, check ports `22, 80, 443`.
2. Click "Scan Network".

**Result:**

```
IP: 192.168.1.1 (router.local)
Ports: [80, 443]
MAC: 00:14:22:01:23:45
```

🧠 **Train AI**

1. Click "Train AI" → "Rescan Network".
2. Label `192.168.1.1` as "Router".
3. Train Model.
4. Next scan → "AI Insights" → Predicted Type: Router.

---

## Troubleshooting

🚫 **Permission Errors** – Run with `sudo` or as Administrator.\
🔍 **Missing Packages** – Re-run `pip install` or check `scanner.log`.\
🤖 **AI Model Fails** – Train it first (`device_classifier.pkl`).\
📈 **Graph-tool Issues** – Install via `conda` or skip it.\
🛠️ **Verbose Mode** – Add `--verbose` to debug.

---

## Contributing

Fork it, tweak it, PR it! Got a wild idea? Open an issue. Let’s make this tool legendary.

## License

📝 **MIT License** – Use it, tweak it, just don’t blame me if it wakes your smart fridge.

## Credits

Built with love, caffeine, and chaos by coff33ninja.

