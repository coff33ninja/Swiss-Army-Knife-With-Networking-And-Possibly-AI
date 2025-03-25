import subprocess
import re
import ipaddress
import os
import json
import time
from datetime import datetime
import logging
import warnings
import requests
from concurrent.futures import ThreadPoolExecutor
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QComboBox,
    QCheckBox, QLineEdit, QPushButton, QTreeWidget, QTreeWidgetItem, QInputDialog,
    QFileDialog, QDialog, QTextBrowser, QProgressBar, QLabel, QMessageBox, QMenu,
    QGraphicsView, QGraphicsScene, QFormLayout, QListWidget, QListWidgetItem
)
from PySide6.QtCore import Qt, QThread, Signal, QPropertyAnimation, QRectF
from PySide6.QtGui import QAction, QPen, QColor, QKeySequence
from scapy.all import srp, ARP, sr1, IP, TCP  # Fixed scapy import
import dns.resolver
import pandas as pd
import networkx as nx
from netmiko import ConnectHandler
import napalm
import pexpect
import pyshark
import igraph as ig
import paramiko
import socket
import netifaces
import speedtest
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from sklearn.ensemble import RandomForestClassifier, RandomForestRegressor, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import pickle
import numpy as np
from pyvis.network import Network
import sys
import nltk
from nltk.tokenize import word_tokenize
import speech_recognition as sr  # Added for voice commands
import argparse
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
import torch

# Download NLTK data
nltk.download('punkt', quiet=True)

# Scapy and warnings configuration
warnings.filterwarnings("ignore", category=SyntaxWarning)

# Constants
DEFAULT_PORTS = [22, 80, 443, 161]
DEFAULT_CONFIG = {
    "default_ports": DEFAULT_PORTS, "saved_macs": [], "http_api": "http://example.com/api", "whitelist": []
}
HISTORY_FILE = "network_scan_history.json"
CONFIG_FILE = "scanner_config.json"
MONITORED_FILE = "monitored_devices.json"
LOG_FILE = "scanner.log"
GRAPH_FILE = "network_graph.gml"
AI_MODEL_FILE = "device_classifier.pkl"
AI_DATASET_FILE = "ai_dataset.csv"

COMMON_PORTS = {
    "SSH": 22, "HTTP": 80, "HTTPS": 443, "FTP": 21, "Telnet": 23,
    "SMTP": 25, "DNS": 53, "MySQL": 3306, "RDP": 3389, "SNMP": 161
}

# Setup logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Utility Functions
def install_requirements(verbose=False):
    packages = [
        "paramiko", "netifaces", "PySide6", "scapy", "dnspython", "pandas", "networkx",
        "netmiko", "napalm", "requests", "pexpect", "pyshark", "python-igraph",
        "speedtest-cli", "matplotlib", "scikit-learn", "pyvis", "nltk", "SpeechRecognition", "pyaudio", "transformers", "torch"
    ]
    success = True
    for pkg in packages:
        try:
            __import__(pkg.split("-")[0])
            if verbose:
                print(f"{pkg} already installed")
        except ImportError:
            try:
                subprocess.check_call(["pip", "install", pkg])
                logging.info(f"Installed package: {pkg}")
                if verbose:
                    print(f"Installed {pkg}")
            except subprocess.CalledProcessError:
                logging.error(f"Failed to install {pkg}")
                if verbose:
                    print(f"Failed to install {pkg}")
                success = False
    return success

def verify_imports():
    packages = {
        "paramiko": "paramiko",
        "netifaces": "netifaces",
        "PySide6": "PySide6",
        "scapy": "scapy",
        "dnspython": "dns",
        "pandas": "pandas",
        "networkx": "networkx",
        "netmiko": "netmiko",
        "napalm": "napalm",
        "requests": "requests",
        "pexpect": "pexpect",
        "pyshark": "pyshark",
        "python-igraph": "igraph",
        "speedtest-cli": "speedtest",
        "matplotlib": "matplotlib",
        "scikit-learn": "sklearn",
        "pyvis": "pyvis",
        "nltk": "nltk",
        "SpeechRecognition": "speech_recognition",
        "transformers": "transformers", "torch": "torch"
    }
    all_good = True
    for pkg_name, import_name in packages.items():
        try:
            __import__(import_name)
            logging.info(f"Successfully imported {pkg_name}")
        except ImportError as e:
            logging.error(f"Failed to import {pkg_name}: {e}")
            all_good = False
    if all_good:
        print("All packages imported successfully!")
    return all_good

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return DEFAULT_CONFIG

def save_config(config):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=4)

def load_monitored():
    if os.path.exists(MONITORED_FILE):
        with open(MONITORED_FILE, "r") as f:
            return json.load(f)
    return []

def save_monitored(devices):
    with open(MONITORED_FILE, "w") as f:
        json.dump(devices, f, indent=4)

def is_local_ip(ip, networks):
    target = ipaddress.ip_address(ip)
    return any(target in ipaddress.ip_network(net) for _, _, net in networks)

def arp_request(ip, iface=None):
    try:
        if iface is None:
            iface = netifaces.gateways()["default"][netifaces.AF_INET][1]
        arp_packet = ARP(pdst=ip)
        answer = srp(arp_packet, timeout=2, verbose=0, iface=iface)[0]
        return answer[0][1].hwsrc if answer else None
    except (KeyError, IndexError, Exception) as e:
        logging.error(f"Scapy ARP failed for {ip}: {e}")
        return None

def nmap_mac_scan(ip):
    try:
        result = subprocess.check_output(["nmap", "-sn", ip], text=True, stderr=subprocess.STDOUT)
        mac_match = re.search(r"MAC Address: ([0-9A-F:]+) \((.+?)\)", result)
        if mac_match:
            mac, vendor = mac_match.groups()
            return {"mac": mac, "vendor": vendor}
        return None
    except subprocess.CalledProcessError as e:
        logging.error(f"Nmap failed for {ip}: {e.output}")
        return None
    except FileNotFoundError:
        logging.warning("Nmap not installed; skipping.")
        return None

def arp_table_lookup(ip):
    try:
        cmd = "arp -a" if os.name == "nt" else "ip -s neigh"
        result = subprocess.check_output(cmd, shell=True, text=True)
        for line in result.splitlines():
            if ip in line:
                mac = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", line)
                if mac:
                    return {"mac": mac.group(0).replace("-", ":"), "vendor": "Unknown"}
        return None
    except Exception as e:
        logging.error(f"ARP table lookup failed for {ip}: {e}")
        return None

def pyshark_mac_sniff(ip, interface=None, timeout=5):
    try:
        if not interface:
            interface = netifaces.gateways()["default"][netifaces.AF_INET][1]
        capture = pyshark.LiveCapture(interface=interface, bpf_filter=f"host {ip}")
        for packet in capture.sniff_continuously(timeout=timeout):
            if "eth" in packet and packet.ip.src == ip:
                return {"mac": packet.eth.src, "vendor": "Unknown"}
        return None
    except Exception as e:
        logging.error(f"Pyshark failed for {ip}: {e}")
        return None

def get_vendor(mac):
    try:
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=5)
        return response.text if response.status_code == 200 else "Unknown"
    except Exception as e:
        logging.error(f"Vendor lookup failed for {mac}: {e}")
        return "Unknown"

def smart_mac_lookup(ip, iface=None, timeout=5):
    local_networks = [(i, a["addr"], str(ipaddress.IPv4Network(f"{a['addr']}/{a['netmask']}", strict=False)))
                      for i in netifaces.interfaces() for a in netifaces.ifaddresses(i).get(netifaces.AF_INET, [])]
    if not is_local_ip(ip, local_networks):
        logging.info(f"Skipping MAC lookup for non-local IP: {ip}")
        return None
    for method in [arp_table_lookup, nmap_mac_scan, lambda x: {"mac": arp_request(x, iface), "vendor": "Unknown"}, pyshark_mac_sniff]:
        result = method(ip) if method != pyshark_mac_sniff else method(ip, iface, timeout)
        if result:
            if "vendor" not in result or result["vendor"] == "Unknown":
                result["vendor"] = get_vendor(result["mac"])
            logging.info(f"Found MAC for {ip} with {method.__name__}: {result}")
            return result
    logging.info(f"No MAC found for {ip}")
    return None

def scan_ip(ip, ports, iface=None):
    open_ports = []
    packet_count = 0
    for port in ports:
        try:
            pkt = IP(dst=ip) / TCP(dport=port, flags="S")
            response = sr1(pkt, timeout=1, verbose=0, iface=iface)
            packet_count += 1
            if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
                open_ports.append(port)
        except Exception as e:
            logging.warning(f"Failed to scan {ip}:{port}: {e}")
            continue  # Added continue for robustness
    device_info = {"ip": ip, "ports": open_ports, "packet_count": packet_count}
    mac_info = smart_mac_lookup(ip, iface)
    device_info["mac"] = mac_info if mac_info else None
    device_info["hostname"] = get_hostname(ip)
    return device_info if open_ports else None

def get_hostname(ip):
    try:
        return dns.resolver.resolve_address(ip)[0].to_text()
    except Exception:
        return ip

def ping_device(ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        start = time.time()
        result = sock.connect_ex((ip, 22))
        duration = (time.time() - start) * 1000
        sock.close()
        return {
            "ip": ip, "status": "up" if result == 0 else "down", "ping": f"{duration:.2f}ms",
            "last_checked": datetime.now().isoformat(), "uptime": 1 if result == 0 else 0
        }
    except Exception as e:
        logging.error(f"Ping failed for {ip}: {e}")
        return {"ip": ip, "status": "down", "ping": "N/A", "last_checked": datetime.now().isoformat(), "uptime": 0}

def paramiko_ssh(ip, username, password, command="uptime"):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, timeout=5)
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode()
        client.close()
        # SLM processing
        load_state = slm.process_output(command, output) if output else 0
        return {"output": output, "load_state": "High" if load_state == 1 else "Normal"}
    except Exception as e:
        return {"output": str(e), "load_state": "Error"}

def netmiko_ssh(ip, username, password, command="show version"):
    try:
        device = {"device_type": "cisco_ios", "ip": ip, "username": username, "password": password}
        connection = ConnectHandler(**device)
        output = connection.send_command(command)
        connection.disconnect()
        return output
    except Exception as e:
        return str(e)

def pexpect_ssh(ip, username, password, command="uptime"):
    try:
        ssh = pexpect.spawn(f"ssh {username}@{ip}", timeout=5)
        ssh.expect("password:")
        ssh.sendline(password)
        ssh.expect(".*#|.*$")
        ssh.sendline(command)
        ssh.expect(".*#|.*$")
        output = ssh.before.decode()
        ssh.sendline("exit")
        ssh.close()
        return output
    except Exception as e:
        return str(e)

def napalm_query(ip, username, password):
    try:
        driver = napalm.get_network_driver("ios")
        device = driver(ip, username, password)
        device.open()
        facts = device.get_facts()
        device.close()
        return facts
    except Exception as e:
        return {"error": str(e)}

def pyshark_capture(interface, count=10):
    try:
        capture = pyshark.LiveCapture(interface=interface)
        packets = [pkt for pkt in capture.sniff_continuously(packet_count=count)]
        return [{"src": pkt.ip.src, "dst": pkt.ip.dst, "proto": pkt.highest_layer} for pkt in packets if "ip" in pkt]
    except Exception as e:
        return str(e)

def http_request(url):
    try:
        response = requests.get(url, timeout=5)
        return response.text if response.status_code == 200 else "Error"
    except Exception as e:
        return str(e)

def run_speed_test():
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        download = st.download() / 1_000_000
        upload = st.upload() / 1_000_000
        ping = st.results.ping
        return {"download": download, "upload": upload, "ping": ping}
    except Exception as e:
        return str(e)

def get_mac_vendor(mac):
    oui = mac[:8].upper() if mac else "00:00:00"
    vendor_map = {"00:14:22": "Cisco", "00:16:17": "Dell", "00:18:F3": "HP", "B8:27:EB": "RaspberryPi"}
    return vendor_map.get(oui, "Unknown")

# AI Classes
class AITrainer(QThread):
    progress = Signal(str)
    finished = Signal(str)

    def __init__(self, mode, network=None, ports=None):
        super().__init__()
        self.mode = mode
        self.network = network
        self.ports = ports if ports else COMMON_PORTS.values()

    def run(self):
        self.progress.emit("Starting AI training...")
        data = []
        if self.mode == "rescan":
            if not self.network:
                self.finished.emit("Error: No network specified for rescan")
                return
            network = ipaddress.IPv4Network(self.network)
            self.progress.emit(f"Scanning {self.network}...")
            for ip in network:
                if ip in [network.network_address, network.broadcast_address]:
                    continue
                device_info = scan_ip(str(ip), self.ports)
                if device_info:
                    data.append(device_info)
        elif self.mode == "ping":
            self.progress.emit("Pinging monitored devices...")
            devices = load_monitored()
            for device in devices:
                ping_result = ping_device(device["ip"])
                device_info = scan_ip(device["ip"], self.ports) or {"ip": device["ip"], "ports": []}
                device_info["ping"] = ping_result["ping"]
                device_info["uptime"] = ping_result["uptime"]
                data.append(device_info)
        elif self.mode == "history":
            self.progress.emit("Loading scan history...")
            history = load_history()
            for entry in history:
                data.extend(entry["results"])
        if not data:
            self.finished.emit("Error: No data collected for training")
            return
        self.progress.emit("Preprocessing data...")
        processed_data = []
        for device in data:
            ports = device.get("ports", [])
            mac_info = device.get("mac", None)
            mac = mac_info["mac"] if isinstance(mac_info, dict) else (mac_info or "00:00:00:00:00:00")
            hostname = device.get("hostname", device["ip"]).lower()
            ping = device.get("ping", "N/A").replace("ms", "") if "ping" in device else "N/A"
            entry = {
                "ip": device["ip"], "Port_Count": len(ports), "MAC_Vendor": get_mac_vendor(mac),
                "Hostname_Router": 1 if "router" in hostname else 0, "Ping": float(ping) if ping != "N/A" and ping else 0,
                "Ports": ",".join(map(str, ports)), "Packet_Count": device.get("packet_count", 0),
                "Uptime": device.get("uptime", 0)
            }
            processed_data.append(entry)
        df = pd.DataFrame(processed_data)
        df.to_csv(AI_DATASET_FILE, index=False)
        self.finished.emit("Data collected and saved. Please label devices in the UI.")

class AIPredictor(QThread):
    result = Signal(list)
    finished = Signal()

    def __init__(self, devices):
        super().__init__()
        self.devices = devices

    def run(self):
        if not os.path.exists(AI_MODEL_FILE):
            self.result.emit([{"ip": d["ip"], "prediction": "Model not trained"} for d in self.devices])
            self.finished.emit()
            return
        clf = pickle.load(open(AI_MODEL_FILE, "rb"))
        predictions = []
        feature_names = getattr(clf, "feature_names_in_", None) if hasattr(clf, "feature_names_in_") else None
        for device in self.devices:
            ports = device.get("ports", [])
            mac_info = device.get("mac", None)
            mac = mac_info["mac"] if isinstance(mac_info, dict) else (mac_info or "00:00:00:00:00:00")
            hostname = device.get("hostname", device["ip"]).lower()
            X = pd.DataFrame([[len(ports), 1 if "router" in hostname else 0, 0]],
                            columns=["Port_Count", "Hostname_Router", "Ping"])
            X = pd.get_dummies(X.join(pd.Series([get_mac_vendor(mac)], name="MAC_Vendor")), columns=["MAC_Vendor"])
            if feature_names is not None:
                X = X.reindex(columns=feature_names, fill_value=0)
            else:
                logging.warning("Feature names not found in model; using input columns.")
            pred = clf.predict(X)[0]
            predictions.append({"ip": device["ip"], "prediction": pred})
        self.result.emit(predictions)
        self.finished.emit()

class AIAnomalyDetector(QThread):
    anomaly_detected = Signal(list)
    finished = Signal()

    def __init__(self, devices):
        super().__init__()
        self.devices = devices
        self.model = None
        if os.path.exists("anomaly_detector.pkl"):
            self.model = pickle.load(open("anomaly_detector.pkl", "rb"))

    def run(self):
        if not self.model:
            self.train_model()
        X = pd.DataFrame([
            {"Port_Count": len(d["ports"]), "Packet_Count": d.get("packet_count", 0)}
            for d in self.devices
        ])
        predictions = self.model.predict(X)
        anomaly_scores = self.model.decision_function(X)
        config = load_config()
        anomalies = []
        for d, pred, score in zip(self.devices, predictions, anomaly_scores):
            if pred == -1:
                mac = d["mac"]["mac"] if isinstance(d["mac"], dict) else d["mac"]
                threat_score = abs(score) * 10 + (5 if mac and mac not in config["whitelist"] else 0)
                anomalies.append({"ip": d["ip"], "anomaly_score": pred, "threat_score": threat_score})
        self.anomaly_detected.emit(anomalies)
        self.finished.emit()

    def train_model(self):
        if self.devices:
            X = pd.DataFrame([
                {"Port_Count": len(d["ports"]), "Packet_Count": d.get("packet_count", 0)}
                for d in self.devices
            ])
        else:
            X = pd.DataFrame({"Port_Count": [0, 1, 2], "Packet_Count": [0, 10, 20]})
            logging.warning("No real data available; using minimal fallback data for anomaly model.")
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.model.fit(X)
        with open("anomaly_detector.pkl", "wb") as f:
            pickle.dump(self.model, f)

class AIPerformancePredictor(QThread):
    prediction = Signal(list)
    finished = Signal()

    def __init__(self, history):
        super().__init__()
        self.history = history
        self.model = None
        if os.path.exists("performance_predictor.pkl"):
            self.model = pickle.load(open("performance_predictor.pkl", "rb"))

    def run(self):
        if not self.model:
            self.train_model()
        data = []
        for entry in self.history:
            for device in entry["results"]:
                ping = float(device.get("ping", "N/A").replace("ms", "")) if "ping" in device and device["ping"] != "N/A" else 0
                data.append({"ip": device["ip"], "Ping": ping, "Uptime": device.get("uptime", 0)})
        df = pd.DataFrame(data)
        X = df[["Uptime"]]
        predictions = self.model.predict(X)
        results = [{"ip": row["ip"], "predicted_ping": pred} for row, pred in zip(df.to_dict("records"), predictions)]
        self.prediction.emit(results)
        self.finished.emit()

    def train_model(self):
        data = []
        for entry in self.history:
            for device in entry["results"]:
                ping = float(device.get("ping", "N/A").replace("ms", "")) if "ping" in device and device["ping"] != "N/A" else 0
                data.append({"Ping": ping, "Uptime": device.get("uptime", 0)})
        if not data:
            data = [{"Ping": 10.0, "Uptime": 1}, {"Ping": 50.0, "Uptime": 0}]
            logging.warning("No historical data; using minimal fallback for performance model.")
        df = pd.DataFrame(data)
        X = df[["Uptime"]]
        y = df["Ping"]
        self.model = RandomForestRegressor(n_estimators=50, random_state=42)
        self.model.fit(X, y)
        with open("performance_predictor.pkl", "wb") as f:
            pickle.dump(self.model, f)

def train_ai_model(df):
    X = df[["Port_Count", "Hostname_Router", "Ping"]]
    X = pd.get_dummies(X.join(df["MAC_Vendor"]), columns=["MAC_Vendor"])
    y = df["Device_Type"]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    report = classification_report(y_test, y_pred, zero_division=0)
    with open(AI_MODEL_FILE, "wb") as f:
        pickle.dump(clf, f)
    return report

# QThread Classes
class ScanThread(QThread):
    update_progress = Signal(int, int)
    result = Signal(list)
    finished = Signal()

    def __init__(self, network, ports):
        super().__init__()
        self.network = network
        self.ports = ports

    def run(self):
        iface = None
        network_str = self.network
        if ": " in self.network:
            iface, network_str = self.network.split(": ", 1)
        network = ipaddress.IPv4Network(network_str)
        results = []
        total_ips = network.num_addresses - 2
        scanned_ips = 0
        def scan_single_ip(ip):
            nonlocal scanned_ips
            if ip in [network.network_address, network.broadcast_address]:
                return None
            device_info = scan_ip(str(ip), self.ports, iface=iface)
            scanned_ips += 1
            self.update_progress.emit(scanned_ips, total_ips)
            return device_info
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(scan_single_ip, ip) for ip in network]
            results = [f.result() for f in futures if f.result()]
        self.result.emit(results)
        self.finished.emit()

class MonitorThread(QThread):
    update_devices = Signal(list)
    finished = Signal()

    def __init__(self, devices):
        super().__init__()
        self.devices = devices
        self.running = True

    def run(self):
        while self.running:
            for i, device in enumerate(self.devices):
                self.devices[i] = ping_device(device["ip"])
            self.update_devices.emit(self.devices)
            save_monitored(self.devices)
            time.sleep(5)
        self.finished.emit()

    def stop(self):
        self.running = False

class NetworkToolThread(QThread):
    result = Signal(str, str, str)
    finished = Signal()

    def __init__(self, tool, ip, username, password, *args):
        super().__init__()
        self.tool = tool
        self.ip = ip
        self.username = username
        self.password = password
        self.args = args

    def run(self):
        if self.tool == "paramiko":
            output = paramiko_ssh(self.ip, self.username, self.password, *self.args)
            self.result.emit(f"SSH (paramiko) {self.ip}", output, "N/A")
        elif self.tool == "netmiko":
            output = netmiko_ssh(self.ip, self.username, self.password)
            self.result.emit(f"SSH (netmiko) {self.ip}", output, "N/A")
        elif self.tool == "pexpect":
            output = pexpect_ssh(self.ip, self.username, self.password)
            self.result.emit(f"SSH (pexpect) {self.ip}", output, "N/A")
        elif self.tool == "napalm":
            output = napalm_query(self.ip, self.username, self.password)
            details = "\n".join(f"{k}: {v}" for k, v in output.items()) if isinstance(output, dict) else output
            self.result.emit(f"NAPALM {self.ip}", "Device Facts", details)
        elif self.tool == "http":
            output = http_request(self.args[0])
            self.result.emit("HTTP Query", self.args[0], output)
        elif self.tool == "pyshark":
            output = pyshark_capture(self.args[0])
            details = "\n".join(f"Src: {pkt['src']} -> Dst: {pkt['dst']} ({pkt['proto']})" for pkt in output) if isinstance(output, list) else output
            self.result.emit("Pyshark Capture", f"Interface: {self.args[0]}", details)
        elif self.tool == "speed":
            output = run_speed_test()
            details = f"Download: {output['download']:.2f} Mbps\nUpload: {output['upload']:.2f} Mbps\nPing: {output['ping']:.2f} ms" if isinstance(output, dict) else output
            self.result.emit("Speed Test", "Results", details)
        self.finished.emit()

class TrafficVisualizerThread(QThread):
    update_traffic = Signal(list)
    finished = Signal()

    def __init__(self, interface):
        super().__init__()
        self.interface = interface
        self.running = True

    def run(self):
        while self.running:
            packets = pyshark_capture(self.interface, count=50)
            self.update_traffic.emit(packets)
            time.sleep(1)
        self.finished.emit()

    def stop(self):
        self.running = False

def save_to_history(network, results):
    timestamp = datetime.now().isoformat()
    entry = {"timestamp": timestamp, "network": network, "results": results}
    history = load_history()
    history.append(entry)
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=4)

def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    with open(HISTORY_FILE, "r") as f:
        return json.load(f)

def build_networkx_graph(results):
    G = nx.Graph()
    for device in results:
        G.add_node(device["ip"], hostname=device["hostname"])
        for port in device["ports"]:
            G.add_edge(device["ip"], f"{device['ip']}:{port}")
    nx.write_gml(G, GRAPH_FILE)
    return G

def build_igraph_graph(results):
    G = ig.Graph()
    nodes = {device["ip"]: i for i, device in enumerate(results)}
    G.add_vertices(len(results))
    for i, device in enumerate(results):
        G.vs[i]["ip"] = device["ip"]
        G.vs[i]["hostname"] = device["hostname"]
        for port in device["ports"]:
            G.add_edge(nodes[device["ip"]], nodes[device["ip"]], port=port)
    G.write_gml(GRAPH_FILE.replace(".gml", "_igraph.gml"))
    return G

# UI Classes
class TrafficVisualizer(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Network Traffic Visualizer")
        self.setGeometry(200, 200, 600, 400)
        self.setStyleSheet("background-color: #1e1e1e;")
        layout = QVBoxLayout()
        self.scene = QGraphicsScene()
        self.view = QGraphicsView(self.scene)
        self.view.setStyleSheet("background-color: #2e2e2e; border: none;")
        layout.addWidget(self.view)
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Capture")
        self.start_btn.setStyleSheet("background-color: #2196F3; padding: 5px;")
        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn = QPushButton("Stop Capture")
        self.stop_btn.setStyleSheet("background-color: #f44336; padding: 5px;")
        self.stop_btn.clicked.connect(self.stop_capture)
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        layout.addLayout(btn_layout)
        self.setLayout(layout)
        self.thread = None
        self.nodes = {}
        self.edges = {}

    def start_capture(self):
        interface, ok = QInputDialog.getText(self, "Interface", "Enter network interface (e.g., eth0):")
        if not ok or not interface:
            return
        self.scene.clear()
        self.nodes.clear()
        self.edges.clear()
        self.thread = TrafficVisualizerThread(interface)
        self.thread.update_traffic.connect(self.update_traffic)
        self.thread.finished.connect(self.capture_finished)
        self.thread.start()

    def stop_capture(self):
        if self.thread and self.thread.isRunning():
            self.thread.stop()

    def update_traffic(self, packets):
        self.scene.clear()
        for pkt in packets:
            src, dst = pkt["src"], pkt["dst"]
            if src not in self.nodes:
                self.nodes[src] = self.scene.addEllipse(0, 0, 20, 20, QPen(Qt.white), QColor(Qt.blue))
                self.nodes[src].setPos(len(self.nodes) * 50 % 500, len(self.nodes) * 50 // 500 * 50)
            if dst not in self.nodes:
                self.nodes[dst] = self.scene.addEllipse(0, 0, 20, 20, QPen(Qt.white), QColor(Qt.green))
                self.nodes[dst].setPos(len(self.nodes) * 50 % 500, len(self.nodes) * 50 // 500 * 50)
            edge_key = (src, dst)
            if edge_key not in self.edges:
                self.edges[edge_key] = self.scene.addLine(
                    self.nodes[src].x() + 10, self.nodes[src].y() + 10,
                    self.nodes[dst].x() + 10, self.nodes[dst].y() + 10,
                    QPen(Qt.yellow)
                )

    def capture_finished(self):
        self.thread = None

class SpeedTestUI(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Speed Test")
        self.setGeometry(300, 300, 300, 200)
        self.setStyleSheet("background-color: #1e1e1e; color: #ffffff;")
        layout = QVBoxLayout()
        self.result_label = QLabel("Press Start to test network speed")
        layout.addWidget(self.result_label)
        self.start_btn = QPushButton("Start Test")
        self.start_btn.setStyleSheet("background-color: #2196F3; padding: 5px;")
        self.start_btn.clicked.connect(self.start_test)
        layout.addWidget(self.start_btn)
        self.setLayout(layout)
        self.thread = None

    def start_test(self):
        self.thread = NetworkToolThread("speed", "", "", "")
        self.thread.result.connect(self.show_result)
        self.thread.finished.connect(self.test_finished)
        self.thread.start()
        self.start_btn.setEnabled(False)
        self.animate_button()

    def show_result(self, _, __, details):
        self.result_label.setText(details)

    def test_finished(self):
        self.start_btn.setEnabled(True)
        self.thread = None

    def animate_button(self):
        anim = QPropertyAnimation(self.start_btn, b"geometry")
        anim.setDuration(500)
        anim.setStartValue(self.start_btn.geometry())
        anim.setEndValue(QRectF(self.start_btn.x() + 5, self.start_btn.y(),
                               self.start_btn.width() - 10, self.start_btn.height()))
        anim.setLoopCount(-1)
        anim.start()


class AITrainingUI(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Train AI Model")
        self.setGeometry(300, 300, 500, 400)
        self.setStyleSheet("background-color: #1e1e1e; color: #ffffff;")
        layout = QVBoxLayout()
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(
            ["Rescan Network", "Ping Monitored Devices", "Load History", "Manual Input"]
        )
        layout.addWidget(self.mode_combo)
        self.status_label = QLabel("Select training mode and start")
        layout.addWidget(self.status_label)
        self.device_list = QListWidget()
        layout.addWidget(self.device_list)
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Training")
        self.start_btn.setStyleSheet("background-color: #2196F3; padding: 5px;")
        self.start_btn.clicked.connect(self.start_training)
        self.label_btn = QPushButton("Label Devices")
        self.label_btn.setStyleSheet("background-color: #4CAF50; padding: 5px;")
        self.label_btn.clicked.connect(self.label_devices)
        self.train_btn = QPushButton("Train Model")
        self.train_btn.setStyleSheet("background-color: #9C27B0; padding: 5px;")
        self.train_btn.clicked.connect(self.train_model)
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.label_btn)
        btn_layout.addWidget(self.train_btn)
        layout.addLayout(btn_layout)
        self.setLayout(layout)
        self.trainer = None
        self.parent = parent

    def start_training(self):
        mode = self.mode_combo.currentText().lower().replace(" ", "_")
        if mode == "rescan_network":
            network = (
                self.parent.network_combo.currentText().split(": ")[-1]
                if self.parent.network_combo.currentText() != "Custom Range"
                else None
            )
            if not network:
                network, ok = QInputDialog.getText(
                    self, "Network", "Enter network to scan (e.g., 192.168.1.0/24):"
                )
                if not ok or not network:
                    return
            self.trainer = AITrainer(
                "rescan", network, self.parent.get_selected_ports()
            )
        elif mode == "ping_monitored_devices":
            self.trainer = AITrainer("ping")
        elif mode == "load_history":
            self.trainer = AITrainer("history")
        elif mode == "manual_input":
            self.add_manual_device()
            return
        self.trainer.progress.connect(self.update_status)
        self.trainer.finished.connect(self.training_finished)
        self.trainer.start()

    def update_status(self, message):
        self.status_label.setText(message)

    def training_finished(self, message):
        self.status_label.setText(message)
        self.load_devices()

    def load_devices(self):
        self.device_list.clear()
        if os.path.exists(AI_DATASET_FILE):
            df = pd.read_csv(AI_DATASET_FILE)
            for _, row in df.iterrows():
                item = QListWidgetItem(
                    f"IP: {row['ip'] if 'ip' in row else 'N/A'}, Ports: {row['Ports']}, MAC: {row['MAC_Vendor']}"
                )
                item.setData(Qt.UserRole, row.to_dict())
                self.device_list.addItem(item)

    def add_manual_device(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Add Device Manually")
        layout = QFormLayout()
        ip_entry = QLineEdit()
        ports_entry = QLineEdit(placeholderText="e.g., 22,80,443")
        mac_entry = QLineEdit()
        hostname_entry = QLineEdit()
        layout.addRow("IP:", ip_entry)
        layout.addRow("Ports:", ports_entry)
        layout.addRow("MAC:", mac_entry)
        layout.addRow("Hostname:", hostname_entry)
        btn = QPushButton("Add")
        btn.clicked.connect(
            lambda: self.save_manual_device(
                ip_entry.text(),
                ports_entry.text(),
                mac_entry.text(),
                hostname_entry.text(),
                dialog,
            )
        )
        layout.addWidget(btn)
        dialog.setLayout(layout)
        dialog.exec()

    def save_manual_device(self, ip, ports, mac, hostname, dialog):
        try:
            ports = [int(p) for p in ports.split(",") if p] if ports else []
            entry = {
                "Port_Count": len(ports),
                "MAC_Vendor": get_mac_vendor(mac),
                "Hostname_Router": 1 if "router" in hostname.lower() else 0,
                "Ping": 0,
                "Ports": ",".join(map(str, ports)),
                "ip": ip,
                "Packet_Count": 0,
                "Uptime": 0,
            }
            df = (
                pd.read_csv(AI_DATASET_FILE)
                if os.path.exists(AI_DATASET_FILE)
                else pd.DataFrame()
            )
            df = pd.concat([df, pd.DataFrame([entry])], ignore_index=True)
            df.to_csv(AI_DATASET_FILE, index=False)
            self.load_devices()
            dialog.accept()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to add device: {e}")

    def label_devices(self):
        if self.device_list.count() == 0:
            QMessageBox.warning(self, "Label", "No devices to label")
            return
        for i in range(self.device_list.count()):
            item = self.device_list.item(i)
            data = item.data(Qt.UserRole)
            device_type, ok = QInputDialog.getItem(
                self,
                "Label Device",
                f"Label {data['ip'] if 'ip' in data else 'Unknown'} (Ports: {data['Ports']})",
                ["Router", "Server", "Desktop", "Laptop", "Printer", "IoT", "Tablet", "Cellphone", "Unknown"],
                4,
                True,
            )
            if ok:
                data["Device_Type"] = device_type
                item.setData(Qt.UserRole, data)
                item.setText(
                    f"IP: {data['ip'] if 'ip' in data else 'N/A'}, Ports: {data['Ports']}, Type: {device_type}"
                )

    def train_model(self):
        if self.device_list.count() == 0:
            QMessageBox.warning(self, "Train", "No devices to train on")
            return
        df = pd.DataFrame(
            [
                self.device_list.item(i).data(Qt.UserRole)
                for i in range(self.device_list.count())
            ]
        )
        if "Device_Type" not in df.columns or df["Device_Type"].isna().all():
            QMessageBox.warning(self, "Train", "Please label some devices first")
            return
        df["Device_Type"] = df["Device_Type"].fillna("Unknown")
        report = train_ai_model(df)
        QMessageBox.information(
            self, "Training Complete", f"Model trained!\n\n{report}"
        )


class AIInsightsUI(QDialog):
    def __init__(self, results, parent=None):
        super().__init__(parent)
        self.setWindowTitle("AI Device Insights")
        self.setGeometry(300, 300, 400, 300)
        self.setStyleSheet("background-color: #1e1e1e; color: #ffffff;")
        layout = QVBoxLayout()
        self.results = results
        self.text_browser = QTextBrowser()
        layout.addWidget(self.text_browser)
        analyze_btn = QPushButton("Analyze Devices")
        analyze_btn.setStyleSheet("background-color: #9C27B0; padding: 5px;")
        analyze_btn.clicked.connect(self.analyze)
        layout.addWidget(analyze_btn)
        self.setLayout(layout)
        self.predictor = None

    def analyze(self):
        self.predictor = AIPredictor(self.results)
        self.predictor.result.connect(self.show_predictions)
        self.predictor.finished.connect(self.predictor_finished)
        self.predictor.start()

    def show_predictions(self, predictions):
        insights = "\n".join(
            f"IP: {p['ip']} - Predicted Type: {p['prediction']}" for p in predictions
        )
        self.text_browser.setText(insights)

    def predictor_finished(self):
        self.predictor = None


class NetworkMapExportUI(QDialog):
    def __init__(self, results, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Network Map Export")
        self.setGeometry(300, 300, 300, 200)
        self.setStyleSheet("background-color: #1e1e1e; color: #ffffff;")
        layout = QVBoxLayout()
        self.results = results
        self.format_combo = QComboBox()
        self.format_combo.addItems(["PNG (Static)", "HTML (Interactive)"])
        layout.addWidget(self.format_combo)
        export_btn = QPushButton("Export Map")
        export_btn.setStyleSheet("background-color: #ff9800; padding: 5px;")
        export_btn.clicked.connect(self.export_map)
        layout.addWidget(export_btn)
        self.setLayout(layout)

    def export_map(self):
        G = build_networkx_graph(self.results)
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Network Map", "", "PNG Files (*.png);;HTML Files (*.html)"
        )
        if not filename:
            return
        if self.format_combo.currentText() == "PNG (Static)":
            pos = nx.spring_layout(G)
            nx.draw(G, pos, with_labels=True, node_color="skyblue", edge_color="gray")
            plt.savefig(filename)
            plt.close()
        else:
            net = Network(notebook=False)
            net.from_nx(G)
            net.show(filename)
        QMessageBox.information(self, "Export", f"Map saved to {filename}")
        self.accept()


class StartupDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Scanner")
        self.setGeometry(300, 300, 300, 200)
        self.setStyleSheet(
            "background-color: #2e2e2e; color: #ffffff; font-size: 16px;"
        )
        layout = QVBoxLayout()
        title = QLabel("Welcome to the Network Scanner!")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #00ff00;")
        layout.addWidget(title)
        monitored_btn = QPushButton("View Monitored Devices")
        monitored_btn.setStyleSheet(
            "background-color: #4CAF50; padding: 10px; border-radius: 5px;"
        )
        monitored_btn.clicked.connect(self.accept_monitored)
        monitored_btn.enterEvent = lambda e: monitored_btn.setStyleSheet(
            "background-color: #45a049; padding: 10px; border-radius: 5px;"
        )
        monitored_btn.leaveEvent = lambda e: monitored_btn.setStyleSheet(
            "background-color: #4CAF50; padding: 10px; border-radius: 5px;"
        )
        layout.addWidget(monitored_btn)
        swiss_btn = QPushButton("Swiss Army Knife Scanning")
        swiss_btn.setStyleSheet(
            "background-color: #2196F3; padding: 10px; border-radius: 5px;"
        )
        swiss_btn.clicked.connect(self.accept_swiss)
        swiss_btn.enterEvent = lambda e: swiss_btn.setStyleSheet(
            "background-color: #1e88e5; padding: 10px; border-radius: 5px;"
        )
        swiss_btn.leaveEvent = lambda e: swiss_btn.setStyleSheet(
            "background-color: #2196F3; padding: 10px; border-radius: 5px;"
        )
        layout.addWidget(swiss_btn)
        self.setLayout(layout)
        self.choice = None

    def accept_monitored(self):
        self.choice = "monitored"
        self.accept()

    def accept_swiss(self):
        self.choice = "swiss"
        self.accept()


class MonitoredDevicesUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Monitored Devices")
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet("background-color: #1e1e1e; color: #ffffff;")
        self.monitored_devices = load_monitored()
        self.monitor_thread = None
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["IP/Hostname", "Status", "Ping", "Last Checked"])
        self.tree.setColumnWidth(0, 200)
        self.tree.setStyleSheet("background-color: #2e2e2e; border: 1px solid #555;")
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_context_menu)
        layout.addWidget(self.tree)
        btn_layout = QHBoxLayout()
        add_btn = QPushButton("Add Device")
        add_btn.setStyleSheet("background-color: #4CAF50; padding: 5px;")
        add_btn.clicked.connect(self.add_device)
        remove_btn = QPushButton("Remove Device")
        remove_btn.setStyleSheet("background-color: #f44336; padding: 5px;")
        remove_btn.clicked.connect(self.remove_device)
        start_btn = QPushButton("Start Monitoring")
        start_btn.setStyleSheet("background-color: #2196F3; padding: 5px;")
        start_btn.clicked.connect(self.start_monitoring)
        stop_btn = QPushButton("Stop Monitoring")
        stop_btn.setStyleSheet("background-color: #ff9800; padding: 5px;")
        stop_btn.clicked.connect(self.stop_monitoring)
        whitelist_btn = QPushButton("Add to Whitelist")
        whitelist_btn.setStyleSheet("background-color: #673AB7; padding: 5px;")
        whitelist_btn.clicked.connect(self.add_to_whitelist)
        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(remove_btn)
        btn_layout.addWidget(start_btn)
        btn_layout.addWidget(stop_btn)
        btn_layout.addWidget(whitelist_btn)
        layout.addLayout(btn_layout)

    def show_context_menu(self, position):
        item = self.tree.itemAt(position)
        if not item:
            return
        ip = item.text(0).split(" (")[0]
        menu = QMenu(self)
        menu.setStyleSheet("background-color: #2e2e2e; color: #ffffff;")
        rdp_action = QAction("RDP", self)
        rdp_action.triggered.connect(lambda: self.launch_rdp(ip))
        anydesk_action = QAction("AnyDesk", self)
        anydesk_action.triggered.connect(lambda: self.launch_anydesk(ip))
        rustdesk_action = QAction("RustDesk", self)
        rustdesk_action.triggered.connect(lambda: self.launch_rustdesk(ip))
        wol_action = QAction("Wake-on-LAN", self)
        wol_action.triggered.connect(lambda: self.send_wol(ip))
        menu.addAction(rdp_action)
        menu.addAction(anydesk_action)
        menu.addAction(rustdesk_action)
        menu.addAction(wol_action)
        menu.exec(self.tree.viewport().mapToGlobal(position))

    def launch_rdp(self, ip):
        try:
            subprocess.Popen(["mstsc", f"/v:{ip}"])
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to launch RDP: {e}")

    def launch_anydesk(self, ip):
        try:
            subprocess.Popen(["anydesk", ip])
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to launch AnyDesk: {e}")

    def launch_rustdesk(self, ip):
        try:
            subprocess.Popen(["rustdesk", "--connect", ip])
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to launch RustDesk: {e}")

    def send_wol(self, ip, mac):
        mac = mac.split("\n")[0] if "\n" in mac else mac  # Extract MAC only
        if not mac or mac == "None":
            mac = arp_request(ip)
            if not mac:
                QMessageBox.warning(self, "WOL", "MAC not found.")
            return
        try:
            subprocess.Popen(["wakeonlan", mac])
            QMessageBox.information(self, "WOL", f"WOL packet sent to {mac}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to send WOL: {e}")

    def add_device(self):
        ip, ok = QInputDialog.getText(self, "Add Device", "Enter IP to monitor:")
        if ok and ip:
            try:
                ipaddress.IPv4Address(ip)
                if ip not in [d["ip"] for d in self.monitored_devices]:
                    self.monitored_devices.append(ping_device(ip))
                    save_monitored(self.monitored_devices)
                    self.update_tree()
            except ValueError:
                QMessageBox.critical(self, "Error", "Invalid IP address")

    def remove_device(self):
        item = self.tree.currentItem()
        if item:
            ip = item.text(0).split(" (")[0]
            self.monitored_devices = [
                d for d in self.monitored_devices if d["ip"] != ip
            ]
            save_monitored(self.monitored_devices)
            self.update_tree()

    def add_to_whitelist(self):
        item = self.tree.currentItem()
        if item:
            ip = item.text(0).split(" (")[0]
            mac = arp_request(ip)
            config = load_config()
            if mac and mac not in config["whitelist"]:
                config["whitelist"].append(mac)
                save_config(config)
                QMessageBox.information(self, "Whitelist", f"Added {mac} to whitelist")

    def start_monitoring(self):
        if not self.monitor_thread or not self.monitor_thread.isRunning():
            self.monitor_thread = MonitorThread(self.monitored_devices)
            self.monitor_thread.update_devices.connect(self.update_tree_with_devices)
            self.monitor_thread.finished.connect(self.monitor_finished)
            self.monitor_thread.start()

    def stop_monitoring(self):
        if self.monitor_thread and self.monitor_thread.isRunning():
            self.monitor_thread.stop()

    def monitor_finished(self):
        self.monitor_thread = None

    def update_tree_with_devices(self, devices):
        self.monitored_devices = devices
        self.update_tree()

    def update_tree(self):
        self.tree.clear()
        config = load_config()
        for device in self.monitored_devices:
            item = QTreeWidgetItem(self.tree)
            ip_host = f"{device['ip']} ({get_hostname(device['ip'])})"
            mac_info = smart_mac_lookup(device["ip"])
            mac = (
                mac_info["mac"] if isinstance(mac_info, dict) else (mac_info or "None")
            )
            item.setText(0, ip_host)
            item.setText(1, device["status"])
            item.setText(2, device["ping"])
            item.setText(3, device["last_checked"])
            item.setForeground(1, Qt.green if device["status"] == "up" else Qt.red)
            if mac and mac != "None" and mac not in config["whitelist"]:
                item.setForeground(0, Qt.red)
                item.setToolTip(0, "Rogue Device Detected!")


def parse_command(command):
    tokens = word_tokenize(command.lower())
    if "scan" in tokens:
        for token in tokens:
            try:
                ipaddress.IPv4Network(token)
                return {"action": "scan", "network": token}
            except ValueError:
                continue
    elif "predict" in tokens and "performance" in tokens:
        return {"action": "predict_performance"}
    return {"action": "unknown", "message": "Command not recognized"}

class SwissArmyKnifeUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Swiss Army Knife Scanner")
        self.setGeometry(100, 100, 900, 700)
        self.setStyleSheet("background-color: #1e1e1e; color: #ffffff;")
        self.custom_ports = {}
        self.selected_ports = []
        self.config = load_config()
        self.scan_thread = None
        self.tool_thread = None

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)

        network_layout = QHBoxLayout()
        network_label = QLabel("Select Network:")
        self.network_combo = QComboBox()
        self.networks = [(iface, addr["addr"], str(ipaddress.IPv4Network(f"{addr['addr']}/{addr['netmask']}", strict=False)))
                         for iface in netifaces.interfaces()
                         for addr in netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
                         if "addr" in addr and "netmask" in addr]
        self.network_combo.addItems(["Custom Range"] + [f"{iface}: {network}" for iface, _, network in self.networks])
        network_layout.addWidget(network_label)
        network_layout.addWidget(self.network_combo)
        layout.addLayout(network_layout)

        ports_layout = QVBoxLayout()
        ports_label = QLabel("Select Ports:")
        ports_layout.addWidget(ports_label)
        self.port_checkboxes = {}
        for name, port in COMMON_PORTS.items():
            cb = QCheckBox(f"{name} ({port})")
            cb.setChecked(port in self.config.get("default_ports", []))
            self.port_checkboxes[port] = cb
            ports_layout.addWidget(cb)
        auto_ports_btn = QPushButton("Auto-Select Ports")
        auto_ports_btn.setStyleSheet("background-color: #CDDC39; padding: 5px;")
        auto_ports_btn.clicked.connect(self.auto_select_ports)
        ports_layout.addWidget(auto_ports_btn)
        layout.addLayout(ports_layout)

        custom_layout = QHBoxLayout()
        self.custom_ip_entry = QLineEdit(placeholderText="IP for custom ports")
        self.custom_ports_entry = QLineEdit(placeholderText="Custom ports (comma-separated)")
        custom_btn = QPushButton("Add Custom Ports")
        custom_btn.clicked.connect(self.add_custom_ports)
        custom_layout.addWidget(self.custom_ip_entry)
        custom_layout.addWidget(self.custom_ports_entry)
        custom_layout.addWidget(custom_btn)
        layout.addLayout(custom_layout)

        ssh_layout = QHBoxLayout()
        ssh_ip_label = QLabel("Device IP:")
        self.ssh_ip_entry = QLineEdit()
        ssh_user_label = QLabel("Username:")
        self.ssh_user_entry = QLineEdit()
        ssh_pass_label = QLabel("Password:")
        self.ssh_pass_entry = QLineEdit(echoMode=QLineEdit.Password)
        ssh_btn = QPushButton("SSH (paramiko)")
        ssh_btn.clicked.connect(self.paramiko_connect)
        netmiko_btn = QPushButton("SSH (netmiko)")
        netmiko_btn.clicked.connect(self.netmiko_connect)
        pexpect_btn = QPushButton("SSH (pexpect)")
        pexpect_btn.clicked.connect(self.pexpect_connect)
        napalm_btn = QPushButton("NAPALM Query")
        napalm_btn.clicked.connect(self.napalm_connect)
        ssh_layout.addWidget(ssh_ip_label)
        ssh_layout.addWidget(self.ssh_ip_entry)
        ssh_layout.addWidget(ssh_user_label)
        ssh_layout.addWidget(self.ssh_user_entry)
        ssh_layout.addWidget(ssh_pass_label)
        ssh_layout.addWidget(self.ssh_pass_entry)
        ssh_layout.addWidget(ssh_btn)
        ssh_layout.addWidget(netmiko_btn)
        ssh_layout.addWidget(pexpect_btn)
        ssh_layout.addWidget(napalm_btn)
        layout.addLayout(ssh_layout)

        http_layout = QHBoxLayout()
        http_label = QLabel("HTTP API URL:")
        self.http_entry = QLineEdit(text=self.config.get("http_api", "http://example.com/api"))
        http_btn = QPushButton("Query HTTP")
        http_btn.clicked.connect(self.http_query)
        traffic_btn = QPushButton("Traffic Visualizer")
        traffic_btn.clicked.connect(self.show_traffic_visualizer)
        http_layout.addWidget(http_label)
        http_layout.addWidget(self.http_entry)
        http_layout.addWidget(http_btn)
        http_layout.addWidget(traffic_btn)
        layout.addLayout(http_layout)

        self.progress = QProgressBar()
        layout.addWidget(self.progress)

        # New progress bar for SSH operations with styling
        self.ssh_progress = QProgressBar()
        self.ssh_progress.setRange(0, 0)  # Indeterminate mode
        self.ssh_progress.setVisible(False)  # Hidden by default
        self.ssh_progress.setStyleSheet(
            "QProgressBar {background-color: #2e2e2e; color: #ffffff; border: 1px solid #555;}"
            "QProgressBar::chunk {background-color: #2196F3;}"
        )
        layout.addWidget(self.ssh_progress)

        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)

        btn_layout = QHBoxLayout()
        self.scan_btn = QPushButton("Scan Network")
        self.scan_btn.setStyleSheet("background-color: #2196F3; padding: 5px;")
        self.scan_btn.clicked.connect(self.start_scan)
        history_btn = QPushButton("Show History")
        history_btn.setStyleSheet("background-color: #4CAF50; padding: 5px;")
        history_btn.clicked.connect(self.show_history)
        export_btn = QPushButton("Export Results")
        export_btn.setStyleSheet("background-color: #ff9800; padding: 5px;")
        export_btn.clicked.connect(self.export_results)
        analyze_btn = QPushButton("Analyze Results")
        analyze_btn.setStyleSheet("background-color: #9C27B0; padding: 5px;")
        analyze_btn.clicked.connect(self.analyze_results)
        graph_btn = QPushButton("Graph Analysis")
        graph_btn.setStyleSheet("background-color: #673AB7; padding: 5px;")
        graph_btn.clicked.connect(self.graph_analysis)
        speed_btn = QPushButton("Speed Test")
        speed_btn.setStyleSheet("background-color: #FF5722; padding: 5px;")
        speed_btn.clicked.connect(self.show_speed_test)
        ai_btn = QPushButton("AI Insights")
        ai_btn.setStyleSheet("background-color: #E91E63; padding: 5px;")
        ai_btn.clicked.connect(self.show_ai_insights)
        train_ai_btn = QPushButton("Train AI")
        train_ai_btn.setStyleSheet("background-color: #00BCD4; padding: 5px;")
        train_ai_btn.clicked.connect(self.show_ai_training)
        broadcast_btn = QPushButton("Broadcast Command")
        broadcast_btn.setStyleSheet("background-color: #F44336; padding: 5px;")
        broadcast_btn.clicked.connect(self.broadcast_command)
        map_btn = QPushButton("Export Network Map")
        map_btn.setStyleSheet("background-color: #FFC107; padding: 5px;")
        map_btn.clicked.connect(self.show_network_map)
        self.anomaly_btn = QPushButton("Detect Anomalies")
        self.anomaly_btn.setStyleSheet("background-color: #FF9800; padding: 5px;")
        self.anomaly_btn.clicked.connect(self.detect_anomalies)
        self.predict_btn = QPushButton("Predict Performance")
        self.predict_btn.setStyleSheet("background-color: #03A9F4; padding: 5px;")
        self.predict_btn.clicked.connect(self.predict_performance)
        self.stats_btn = QPushButton("Network Stats")
        self.stats_btn.setStyleSheet("background-color: #8BC34A; padding: 5px;")
        self.stats_btn.clicked.connect(self.compute_network_stats)
        btn_layout.addWidget(self.scan_btn)
        btn_layout.addWidget(history_btn)
        btn_layout.addWidget(export_btn)
        btn_layout.addWidget(analyze_btn)
        btn_layout.addWidget(graph_btn)
        btn_layout.addWidget(speed_btn)
        btn_layout.addWidget(ai_btn)
        btn_layout.addWidget(train_ai_btn)
        btn_layout.addWidget(broadcast_btn)
        btn_layout.addWidget(map_btn)
        btn_layout.addWidget(self.anomaly_btn)
        btn_layout.addWidget(self.stats_btn)
        layout.addLayout(btn_layout)

        ai_ssh_btn = QPushButton("AI SSH Insights")
        ai_ssh_btn.setStyleSheet("background-color: #E91E63; padding: 5px;")
        ai_ssh_btn.clicked.connect(self.show_ai_ssh_insights)
        btn_layout.addWidget(ai_ssh_btn)

        command_layout = QHBoxLayout()
        self.command_entry = QLineEdit(placeholderText="Enter command (e.g., 'scan 192.168.1.0/24')")
        self.command_entry.textChanged.connect(self.update_command_suggestions)
        command_btn = QPushButton("Execute")
        command_btn.setStyleSheet("background-color: #8BC34A; padding: 5px;")
        command_btn.clicked.connect(self.execute_command)
        voice_btn = QPushButton("Voice Command")
        voice_btn.setStyleSheet("background-color: #FF5722; padding: 5px;")
        voice_btn.clicked.connect(self.listen_command)
        command_layout.addWidget(self.command_entry)
        command_layout.addWidget(command_btn)
        command_layout.addWidget(voice_btn)
        layout.addLayout(command_layout)

        history_filter_layout = QHBoxLayout()
        filter_label = QLabel("Filter History by IP:")
        self.filter_entry = QLineEdit(placeholderText="Enter IP to filter")
        filter_btn = QPushButton("Filter")
        filter_btn.clicked.connect(self.filter_history)
        clear_history_btn = QPushButton("Clear History")
        clear_history_btn.clicked.connect(self.clear_history)
        history_filter_layout.addWidget(filter_label)
        history_filter_layout.addWidget(self.filter_entry)
        history_filter_layout.addWidget(filter_btn)
        history_filter_layout.addWidget(clear_history_btn)
        layout.addLayout(history_filter_layout)

        self.output_tree = QTreeWidget()
        self.output_tree.setHeaderLabels(["IP/Hostname", "Ports/Details", "MAC/Extra Info"])
        self.output_tree.setColumnWidth(0, 200)
        self.output_tree.setColumnWidth(1, 150)
        self.output_tree.setStyleSheet("background-color: #2e2e2e; border: 1px solid #555;")
        self.output_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.output_tree.customContextMenuRequested.connect(self.show_context_menu)
        layout.addWidget(self.output_tree)

    def keyPressEvent(self, event):
        shortcut = QKeySequence("Ctrl+Alt+G")
        if QKeySequence(event.keyCombination()) == shortcut:
            QMessageBox.information(self, "Easter Egg", "Argh! Ye found the pirate mode, matey!")
            self.scan_btn.setText("Scan Ye Network")
            self.output_tree.setHeaderLabels(["Ship/Port", "Loot/Details", "Crew/Extra"])

    def show_ai_ssh_insights(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("AI SSH Insights")
        layout = QVBoxLayout()
        insights = QTextBrowser()
        insights.setText("\n".join(f"{h['command']}: {h['output']}" for h in slm.history[-5:]))
        layout.addWidget(insights)
        train_btn = QPushButton("Train SLM")
        train_btn.clicked.connect(self.train_slm)
        layout.addWidget(train_btn)
        dialog.setLayout(layout)
        dialog.exec()

    def train_slm(self):
        if not slm.history:
            QMessageBox.warning(self, "Train SLM", "No history to train on")
            return
        labeled_data = [(h["command"] + " " + h["output"], h["label"]) for h in slm.history]
        inputs = slm.tokenizer([d[0] for d in labeled_data], return_tensors="pt", padding=True, truncation=True)
        labels = torch.tensor([d[1] for d in labeled_data])
        optimizer = torch.optim.Adam(slm.model.parameters(), lr=1e-5)
        slm.model.train()
        for _ in range(3):
            outputs = slm.model(**inputs, labels=labels)
            loss = outputs.loss
            loss.backward()
            optimizer.step()
            optimizer.zero_grad()
        slm.model.eval()
        QMessageBox.information(self, "Train SLM", "Model fine-tuned with history")

    def show_context_menu(self, position):
        item = self.output_tree.itemAt(position)
        if not item:
            return
        ip = item.text(0).split(" (")[0]
        mac = item.text(2).split("\n")[0] if "\n" in item.text(2) else item.text(2)
        menu = QMenu(self)
        menu.setStyleSheet("background-color: #2e2e2e; color: #ffffff;")

        # Existing actions
        rdp_action = QAction("RDP", self)
        rdp_action.triggered.connect(lambda: self.launch_rdp(ip))
        anydesk_action = QAction("AnyDesk", self)
        anydesk_action.triggered.connect(lambda: self.launch_anydesk(ip))
        rustdesk_action = QAction("RustDesk", self)
        rustdesk_action.triggered.connect(lambda: self.launch_rustdesk(ip))
        wol_action = QAction("Wake-on-LAN", self)
        wol_action.triggered.connect(lambda: self.send_wol(ip, mac))

        # New SSH actions
        ssh_action = QAction("SSH Connect", self)
        ssh_action.triggered.connect(lambda: self.ssh_with_ai(ip))
        check_load_action = QAction("Check Load", self)
        check_load_action.triggered.connect(lambda: self.check_load(ip))
        export_action = QAction("Export Device Info", self)
        export_action.triggered.connect(lambda: self.export_device(ip))

        menu.addAction(rdp_action)
        menu.addAction(anydesk_action)
        menu.addAction(rustdesk_action)
        menu.addAction(wol_action)
        menu.addAction(ssh_action)
        menu.addAction(check_load_action)
        menu.addAction(export_action)
        menu.exec(self.output_tree.viewport().mapToGlobal(position))

    def ssh_with_ai(self, ip):
        if not self.ssh_user_entry.text() or not self.ssh_pass_entry.text():
            QMessageBox.critical(self, "Error", "Enter SSH credentials")
            return
        command, ok = QInputDialog.getText(
            self, "SSH Command", "Enter command (or leave blank for suggestion):"
        )
        if not ok:
            return
        if not command:
            context = (
                "linux" if "linux" in get_hostname(ip).lower() else "windows"
            )  # Basic OS guess
            command = slm.suggest_command(context)
        result = paramiko_ssh(
            ip, self.ssh_user_entry.text(), self.ssh_pass_entry.text(), command
        )
        self.add_to_tree(
            ip, f"SSH: {command}", f"{result['output']}\nLoad: {result['load_state']}"
        )

    def check_load(self, ip):
        if not self.ssh_user_entry.text() or not self.ssh_pass_entry.text():
            QMessageBox.critical(self, "Error", "Enter SSH credentials")
            return
        command = "top -bn1" if "linux" in get_hostname(ip).lower() else "tasklist"
        self.status_label.setText(f"Checking load on {ip}...")
        self.ssh_progress.setVisible(True)  # Show spinning bar

        result = paramiko_ssh(
            ip, self.ssh_user_entry.text(), self.ssh_pass_entry.text(), command
        )
        time.sleep(1)
        self.ssh_progress.setVisible(False)  # Hide spinning bar
        self.add_to_tree(
            ip, "Load Check", f"{result['output']}\nLoad: {result['load_state']}"
        )
        if result["load_state"] == "High":
            suggestion = slm.suggest_command("high load")
            reply = QMessageBox.question(
                self,
                "High Load",
                f"High load detected on {ip}. Run '{suggestion}'?",
                QMessageBox.Yes | QMessageBox.No,
            )
            if reply == QMessageBox.Yes:
                self.status_label.setText(f"Mitigating high load on {ip}...")
                self.ssh_progress.setVisible(True)  # Show spinning bar again

                mitigation = paramiko_ssh(
                    ip, self.ssh_user_entry.text(), self.ssh_pass_entry.text(), suggestion
                )

                self.ssh_progress.setVisible(False)  # Hide spinning bar
                self.add_to_tree(ip, f"Mitigation: {suggestion}", mitigation["output"])
                self.status_label.setText(f"Mitigation applied to {ip}")
        self.status_label.setText("Ready")

    def export_device(self, ip):
        device = next((d for d in getattr(self, "scan_results", []) if d["ip"] == ip), None)
        if not device:
            QMessageBox.warning(self, "Export", "Device not found in results")
            return
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Device Info", "", "JSON Files (*.json)"
        )
        if filename:
            with open(filename, "w") as f:
                json.dump(device, f, indent=4)
            QMessageBox.information(self, "Export", f"Device info saved to {filename}")

    def launch_rdp(self, ip):
        try:
            subprocess.Popen(["mstsc", f"/v:{ip}"])
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to launch RDP: {e}")

    def launch_anydesk(self, ip):
        try:
            subprocess.Popen(["anydesk", ip])
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to launch AnyDesk: {e}")

    def launch_rustdesk(self, ip):
        try:
            subprocess.Popen(["rustdesk", "--connect", ip])
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to launch RustDesk: {e}")

    def send_wol(self, ip, mac):
        if not mac or mac == "None":
            mac = arp_request(ip)
            if not mac:
                QMessageBox.warning(self, "WOL", "MAC not found.")
                return
        try:
            subprocess.Popen(["wakeonlan", mac])
            QMessageBox.information(self, "WOL", f"WOL packet sent to {mac}")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to send WOL: {e}")

    def add_custom_ports(self):
        ip = self.custom_ip_entry.text()
        ports = self.custom_ports_entry.text()
        try:
            ipaddress.IPv4Address(ip)
            ports = [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()]
            if not ports:
                QMessageBox.critical(self, "Error", "Invalid ports")
                return
            self.custom_ports[ip] = ports
            self.add_to_tree(f"{ip} (Custom)", f"Ports added: {ports}", "N/A")
        except ValueError:
            QMessageBox.critical(self, "Error", "Invalid IP address")

    def get_selected_ports(self):
        return [port for port, cb in self.port_checkboxes.items() if cb.isChecked()]

    def suggest_ports(self):
        history = load_history()
        if not history:
            return list(COMMON_PORTS.values())
        port_counts = pd.Series([port for entry in history for device in entry["results"] for port in device["ports"]]).value_counts()
        return port_counts.head(5).index.tolist()

    def auto_select_ports(self):
        suggested = self.suggest_ports()
        for port, cb in self.port_checkboxes.items():
            cb.setChecked(port in suggested)
        self.status_label.setText("Ports auto-selected based on history")

    def suggest_commands(self, partial_input):
        common_commands = ["scan 192.168.1.0/24", "predict performance", "show history"]
        suggestions = [cmd for cmd in common_commands if partial_input.lower() in cmd.lower()]
        return suggestions[:3]

    def update_command_suggestions(self):
        text = self.command_entry.text()
        if text:
            suggestions = self.suggest_commands(text)
            if suggestions:
                self.command_entry.setToolTip("\n".join(suggestions))
            else:
                self.command_entry.setToolTip("")
        else:
            self.command_entry.setToolTip("")

    def listen_command(self):
        recognizer = sr.Recognizer()
        with sr.Microphone() as source:
            self.status_label.setText("Listening...")
            try:
                audio = recognizer.listen(source, timeout=5)
                command = recognizer.recognize_google(audio)
                self.command_entry.setText(command)
                self.execute_command()
            except sr.UnknownValueError:
                self.status_label.setText("Could not understand audio")
            except sr.RequestError as e:
                self.status_label.setText(f"Speech recognition error: {e}")
            except Exception as e:
                self.status_label.setText(f"Error: {e}")
            finally:
                time.sleep(1)  # Brief pause for user to read status
                self.status_label.setText("Ready")

    def update_progress(self, scanned, total):
        if total > 0:
            self.progress.setValue(int((scanned / total) * 100))

    def start_scan(self):
        self.output_tree.clear()
        selected_network = self.network_combo.currentText()
        if selected_network == "Custom Range":
            range_input, ok = QInputDialog.getText(self, "Custom Range", "Enter IP range (e.g., 192.168.1.0/24):")
            if not ok or not range_input:
                return
            try:
                network = ipaddress.IPv4Network(range_input)
                selected_network = f"Custom: {range_input}"
            except ValueError:
                QMessageBox.critical(self, "Error", "Invalid IP range")
                return
        else:
            network = ipaddress.IPv4Network(selected_network.split(": ")[-1])

        local_networks = [ipaddress.IPv4Network(n[2]) for n in self.networks]
        if not any(network.subnet_of(local) for local in local_networks):
            QMessageBox.warning(self, "Warning", "Selected network may not be local. ARP might fail.")

        self.selected_ports = self.get_selected_ports()
        if not self.selected_ports and not self.custom_ports:
            QMessageBox.critical(self, "Error", "Select at least one port to scan")
            return

        self.config["default_ports"] = self.selected_ports
        save_config(self.config)

        self.progress.setValue(0)
        self.status_label.setText("Scanning network...")
        self.scan_thread = ScanThread(selected_network, self.selected_ports)
        self.scan_thread.update_progress.connect(self.update_progress)
        self.scan_thread.result.connect(self.scan_finished)
        self.scan_thread.finished.connect(self.scan_thread_finished)
        self.scan_thread.start()
        self.animate_button(self.scan_btn)

    def scan_finished(self, results):
        self.scan_results = results
        config = load_config()
        for device in results:
            ip_host = f"{device['ip']} ({device['hostname']})"
            ports_str = str(device['ports'])
            mac_info = device.get("mac")
            if isinstance(mac_info, dict):
                mac = mac_info["mac"]
                mac_display = f"{mac}\nVendor: {mac_info['vendor']}"
            else:
                mac = mac_info or "None"
                mac_display = mac
            if mac and mac not in config["whitelist"]:
                self.add_to_tree(ip_host, ports_str, mac_display, rogue=True)
                QMessageBox.warning(self, "Rogue Alert", f"Unknown device detected: {ip_host}")
            else:
                self.add_to_tree(ip_host, ports_str, mac_display)
        if results:
            save_to_history(self.network_combo.currentText(), results)
            self.add_to_tree("Summary", f"Scanned {len(results)} devices", "N/A")
        else:
            self.add_to_tree("Summary", "No devices with open ports found", "N/A")

    def scan_thread_finished(self):
        self.progress.setValue(100)
        self.status_label.setText("Ready")

    def animate_button(self, button):
        anim = QPropertyAnimation(button, b"geometry")
        anim.setDuration(500)
        anim.setStartValue(button.geometry())
        anim.setEndValue(QRectF(button.x() + 5, button.y(), button.width() - 10, button.height()))
        anim.setLoopCount(4)
        anim.start()

    def add_to_tree(self, ip, ports, extra_info, rogue=False, parent=None):
        item = QTreeWidgetItem(parent if parent else self.output_tree)
        item.setText(0, ip)
        item.setText(1, ports)
        item.setText(2, extra_info)
        if rogue:
            item.setForeground(0, Qt.red)
            item.setToolTip(0, "Rogue Device Detected!")

    def run_tool_thread(self, tool, *args):
        if self.tool_thread and self.tool_thread.isRunning():
            QMessageBox.warning(self, "Busy", "Another tool is running. Please wait.")
            return
        self.tool_thread = NetworkToolThread(tool, self.ssh_ip_entry.text(),
                                            self.ssh_user_entry.text(),
                                            self.ssh_pass_entry.text(), *args)
        self.tool_thread.result.connect(self.add_to_tree)
        self.tool_thread.finished.connect(self.tool_thread_finished)
        self.tool_thread.start()

    def tool_thread_finished(self):
        self.tool_thread = None
        self.status_label.setText("Ready")

    def paramiko_connect(self):
        if not (
            self.ssh_ip_entry.text()
            and self.ssh_user_entry.text()
            and self.ssh_pass_entry.text()
        ):
            QMessageBox.critical(self, "Error", "Enter SSH details")
            return
        try:
            ipaddress.IPv4Address(self.ssh_ip_entry.text())
            self.status_label.setText("Connecting via Paramiko SSH...")
            self.run_tool_thread("paramiko")
        except ValueError:
            QMessageBox.critical(self, "Error", "Invalid IP address")

    def netmiko_connect(self):
        if not (
            self.ssh_ip_entry.text()
            and self.ssh_user_entry.text()
            and self.ssh_pass_entry.text()
        ):
            QMessageBox.critical(self, "Error", "Enter SSH details")
            return
        try:
            ipaddress.IPv4Address(self.ssh_ip_entry.text())
            self.status_label.setText("Connecting via Netmiko SSH...")
            self.run_tool_thread("netmiko")
        except ValueError:
            QMessageBox.critical(self, "Error", "Invalid IP address")

    def pexpect_connect(self):
        if not (
            self.ssh_ip_entry.text()
            and self.ssh_user_entry.text()
            and self.ssh_pass_entry.text()
        ):
            QMessageBox.critical(self, "Error", "Enter SSH details")
            return
        try:
            ipaddress.IPv4Address(self.ssh_ip_entry.text())
            self.status_label.setText("Connecting via Pexpect SSH...")
            self.run_tool_thread("pexpect")
        except ValueError:
            QMessageBox.critical(self, "Error", "Invalid IP address")

    def napalm_connect(self):
        if not (
            self.ssh_ip_entry.text()
            and self.ssh_user_entry.text()
            and self.ssh_pass_entry.text()
        ):
            QMessageBox.critical(self, "Error", "Enter SSH details")
            return
        try:
            ipaddress.IPv4Address(self.ssh_ip_entry.text())
            self.status_label.setText("Querying via NAPALM...")
            self.run_tool_thread("napalm")
        except ValueError:
            QMessageBox.critical(self, "Error", "Invalid IP address")

    def http_query(self):
        url = self.http_entry.text()
        if not url:
            QMessageBox.critical(self, "Error", "Enter an HTTP URL")
            return
        self.status_label.setText("Querying HTTP API...")
        self.config["http_api"] = url
        save_config(self.config)
        self.run_tool_thread("http", url)

    def show_traffic_visualizer(self):
        self.traffic_dialog = TrafficVisualizer(self)
        self.traffic_dialog.show()

    def show_speed_test(self):
        self.speed_dialog = SpeedTestUI(self)
        self.speed_dialog.show()

    def show_ai_insights(self):
        if not hasattr(self, "scan_results") or not self.scan_results:
            QMessageBox.warning(self, "AI Insights", "No scan results to analyze")
            return
        self.ai_dialog = AIInsightsUI(self.scan_results, self)
        self.ai_dialog.show()

    def show_ai_training(self):
        self.ai_training_dialog = AITrainingUI(self)
        self.ai_training_dialog.show()

    def show_network_map(self):
        if not hasattr(self, "scan_results") or not self.scan_results:
            QMessageBox.warning(self, "Network Map", "No scan results to export")
            return
        self.map_dialog = NetworkMapExportUI(self.scan_results, self)
        self.map_dialog.show()

    def show_history(self):
        self.output_tree.clear()
        history = load_history()
        if not history:
            self.add_to_tree("History", "No previous scans", "N/A")
            return
        for entry in history:
            timestamp = entry["timestamp"]
            network = entry["network"]
            parent = QTreeWidgetItem(self.output_tree)
            parent.setText(0, f"{timestamp} - {network}")
            parent.setText(1, f"Devices: {len(entry['results'])}")
            for device in entry["results"]:
                ip_host = f"{device['ip']} ({device['hostname']})"
                ports_str = str(device["ports"])
                mac_info = device.get("mac")
                mac_display = (
                    f"{mac_info['mac']}\nVendor: {mac_info['vendor']}"
                    if isinstance(mac_info, dict)
                    else (mac_info or "None")
                )
                self.add_to_tree(ip_host, ports_str, mac_display, parent=parent)
            parent.setExpanded(False)

    def filter_history(self):
        ip_filter = self.filter_entry.text()
        if not ip_filter:
            self.show_history()
            return
        self.output_tree.clear()
        history = load_history()
        for entry in history:
            timestamp = entry["timestamp"]
            network = entry["network"]
            filtered_results = [d for d in entry["results"] if ip_filter in d["ip"]]
            if filtered_results:
                parent = QTreeWidgetItem(self.output_tree)
                parent.setText(0, f"{timestamp} - {network}")
                parent.setText(1, f"Filtered Devices: {len(filtered_results)}")
                for device in filtered_results:
                    ip_host = f"{device['ip']} ({device['hostname']})"
                    ports_str = str(device["ports"])
                    mac_info = device.get("mac")
                    mac_display = (
                        f"{mac_info['mac']}\nVendor: {mac_info['vendor']}"
                        if isinstance(mac_info, dict)
                        else (mac_info or "None")
                    )
                    self.add_to_tree(ip_host, ports_str, mac_display, parent=parent)
                parent.setExpanded(False)

    def clear_history(self):
        reply = QMessageBox.question(
            self,
            "Clear History",
            "Are you sure you want to clear all scan history?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            with open(HISTORY_FILE, "w") as f:
                json.dump([], f)
            self.show_history()

    def export_results(self):
        if not hasattr(self, "scan_results") or not self.scan_results:
            QMessageBox.warning(self, "Export", "No scan results to export")
            return
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Results", "", "JSON Files (*.json)"
        )
        if filename:
            with open(filename, "w") as f:
                json.dump(self.scan_results, f, indent=4)
            QMessageBox.information(self, "Export", f"Results saved to {filename}")

    def analyze_results(self):
        if not hasattr(self, "scan_results") or not self.scan_results:
            QMessageBox.warning(self, "Analyze", "No scan results to analyze")
            return
        self.ai_dialog = AIInsightsUI(self.scan_results, self)
        self.ai_dialog.show()

    def graph_analysis(self):
        if not hasattr(self, "scan_results") or not self.scan_results:
            QMessageBox.warning(self, "Graph", "No scan results to graph")
            return
        G = build_networkx_graph(self.scan_results)
        pos = nx.spring_layout(G)
        nx.draw(G, pos, with_labels=True, node_color="skyblue", edge_color="gray")
        plt.title(f"Network Graph - {self.network_combo.currentText()}")
        plt.show()

    def broadcast_command(self):
        if not hasattr(self, "scan_results") or not self.scan_results:
            QMessageBox.warning(self, "Broadcast", "No devices to send command to")
            return
        command, ok = QInputDialog.getText(
            self, "Broadcast Command", "Enter command to broadcast (e.g., shutdown):"
        )
        if not ok or not command:
            return
        self.status_label.setText("Broadcasting command...")
        for device in self.scan_results:
            ip = device["ip"]
            if 22 in device["ports"]:
                output = paramiko_ssh(
                    ip, self.ssh_user_entry.text(), self.ssh_pass_entry.text(), command
                )
                self.add_to_tree(ip, f"Command: {command}", output)
        self.status_label.setText("Command broadcast complete")

    def detect_anomalies(self):
        if not hasattr(self, "scan_results") or not self.scan_results:
            QMessageBox.warning(self, "Anomaly Detection", "No scan results to analyze")
            return
        self.status_label.setText("Detecting anomalies...")
        self.anomaly_detector = AIAnomalyDetector(self.scan_results)
        self.anomaly_detector.anomaly_detected.connect(self.show_anomalies)
        self.anomaly_detector.finished.connect(self.anomaly_finished)
        self.anomaly_detector.start()

    def show_anomalies(self, anomalies):
        for anomaly in anomalies:
            self.add_to_tree(
                f"{anomaly['ip']} (Anomaly)",
                "Suspicious Activity",
                f"Threat Score: {anomaly['threat_score']:.2f}",
                rogue=True,
            )
        if not anomalies:
            self.add_to_tree("Anomaly Check", "No anomalies detected", "N/A")

    def anomaly_finished(self):
        self.status_label.setText("Ready")
        self.anomaly_detector = None

    def predict_performance(self):
        history = load_history()
        if not history:
            QMessageBox.warning(
                self, "Performance Prediction", "No historical data available"
            )
            return
        self.status_label.setText("Predicting performance...")
        self.predict_btn.clicked.connect(self.predict_performance)
        self.performance_predictor = AIPerformancePredictor(history)
        self.performance_predictor.prediction.connect(self.show_performance_predictions)
        self.performance_predictor.finished.connect(self.performance_finished)
        self.performance_predictor.start()

    def show_performance_predictions(self, predictions):
        for pred in predictions:
            self.add_to_tree(
                pred["ip"],
                "Performance Prediction",
                f"Predicted Ping: {pred['predicted_ping']:.2f}ms",
            )

    def performance_finished(self):
        self.status_label.setText("Ready")
        self.performance_predictor = None

    def execute_command(self):
        command = self.command_entry.text()
        if not command:
            return
        parsed = parse_command(command)
        if parsed["action"] == "scan":
            self.network_combo.setCurrentText(f"Custom: {parsed['network']}")
            self.start_scan()
        elif parsed["action"] == "predict_performance":
            self.predict_performance()
        elif parsed["action"] == "unknown":
            QMessageBox.warning(self, "Command Error", parsed["message"])
        self.command_entry.clear()

    def compute_network_stats(self):
        """Compute and display network statistics using numpy with a ping histogram in a dialog."""
        if not hasattr(self, "scan_results") or not self.scan_results:
            history = load_history()
            if not history:
                QMessageBox.warning(
                    self, "Network Stats", "No scan results or historical data available"
                )
                return
            all_results = [device for entry in history for device in entry["results"]]
        else:
            all_results = self.scan_results

        pings = []
        packet_counts = []
        for device in all_results:
            ping = device.get("ping", "N/A")
            if ping != "N/A" and isinstance(ping, str) and ping.endswith("ms"):
                try:
                    pings.append(float(ping.replace("ms", "")))
                except ValueError:
                    continue
            packet_counts.append(device.get("packet_count", 0))

        if not pings and not packet_counts:
            QMessageBox.warning(self, "Network Stats", "No valid numerical data to analyze")
            return

        self.output_tree.clear()
        self.status_label.setText("Computing network statistics...")

        if pings:
            ping_array = np.array(pings)
            ping_stats = {
                "Mean Ping": np.mean(ping_array),
                "Median Ping": np.median(ping_array),
                "Std Dev Ping": np.std(ping_array),
                "Min Ping": np.min(ping_array),
                "Max Ping": np.max(ping_array),
            }
            parent = QTreeWidgetItem(self.output_tree)
            parent.setText(0, "Ping Statistics (ms)")
            parent.setText(1, f"Devices: {len(pings)}")
            for stat, value in ping_stats.items():
                self.add_to_tree(stat, f"{value:.2f}", "N/A", parent=parent)
            parent.setExpanded(True)

            # Show histogram in dialog
            dialog = NetworkStatsDialog(ping_array, self)
            dialog.exec()

        if packet_counts:
            packet_array = np.array(packet_counts)
            packet_stats = {
                "Mean Packet Count": np.mean(packet_array),
                "Median Packet Count": np.median(packet_array),
                "Std Dev Packet Count": np.std(packet_array),
                "Min Packet Count": np.min(packet_array),
                "Max Packet Count": np.max(packet_array),
            }
            parent = QTreeWidgetItem(self.output_tree)
            parent.setText(0, "Packet Count Statistics")
            parent.setText(1, f"Devices: {len(packet_counts)}")
            for stat, value in packet_stats.items():
                self.add_to_tree(stat, f"{value:.2f}", "N/A", parent=parent)
            parent.setExpanded(True)

        self.status_label.setText("Network statistics computed")


class NetworkStatsDialog(QDialog):
    def __init__(self, ping_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Network Statistics - Ping Distribution")
        self.setGeometry(300, 300, 600, 400)
        self.setStyleSheet("background-color: #1e1e1e; color: #ffffff;")

        layout = QVBoxLayout()

        # Create matplotlib figure and canvas
        self.figure = Figure(figsize=(5, 4), dpi=100)
        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)

        # Plot histogram
        ax = self.figure.add_subplot(111)
        ax.hist(ping_data, bins=10, color="skyblue", edgecolor="black")
        ax.set_title("Ping Time Distribution", color="white")
        ax.set_xlabel("Ping (ms)", color="white")
        ax.set_ylabel("Frequency", color="white")
        ax.grid(True, linestyle="--", alpha=0.7)
        ax.set_facecolor("#2e2e2e")
        self.figure.patch.set_facecolor("#1e1e1e")
        ax.tick_params(colors="white")

        # Add Save Plot button
        save_btn = QPushButton("Save Plot")
        save_btn.setStyleSheet("background-color: #2196F3; padding: 5px;")
        save_btn.clicked.connect(self.save_plot)
        layout.addWidget(save_btn)

        self.setLayout(layout)

    def save_plot(self):
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Plot", "", "PNG Files (*.png)"
        )
        if filename:
            self.figure.savefig(filename)
            QMessageBox.information(self, "Save Plot", f"Plot saved to {filename}")


class SSHSLM:
    def __init__(self):
        self.tokenizer = None
        self.model = None
        self.history = []
        self.load_model()

    def load_model(self):
        if not self.tokenizer or not self.model:
            self.tokenizer = DistilBertTokenizer.from_pretrained(
                "distilbert-base-uncased"
            )
            self.model = DistilBertForSequenceClassification.from_pretrained(
                "distilbert-base-uncased"
            )

    def process_output(self, command, output):
        inputs = self.tokenizer(f"{command} {output}", return_tensors="pt", truncation=True, padding=True)
        with torch.no_grad():
            logits = self.model(**inputs).logits
        # Simple classification (e.g., 0=normal, 1=high load) - fine-tune later
        prediction = torch.argmax(logits, dim=1).item()
        self.history.append({"command": command, "output": output, "label": prediction})
        return prediction

    def suggest_command(self, context):
        if not self.history:
            return "uptime"
        high_load_cmds = [h["command"] for h in self.history if h["label"] == 1]
        if "high load" in context.lower() and high_load_cmds:
            return max(set(high_load_cmds), key=high_load_cmds.count)
        return "uptime" if "linux" in context else "tasklist"


# Add to imports
slm = SSHSLM()

def main():
    parser = argparse.ArgumentParser(description="Network Scanner Tool")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    if not install_requirements(verbose=args.verbose):
        print("Some packages failed to install. Continuing anyway...")
    if not verify_imports():
        print("Some imports failed. Functionality may be limited.")

    app = QApplication(sys.argv)
    dialog = StartupDialog()
    dialog.exec()
    if dialog.choice == "monitored":
        window = MonitoredDevicesUI()
    elif dialog.choice == "swiss":
        window = SwissArmyKnifeUI()
    else:
        return
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
