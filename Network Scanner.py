"""
*** IMPORTANT LEGAL DISCLAIMER & ETHICAL USE POLICY ***

This software is provided for educational purposes, ethical security testing, and academic
research ONLY.

- DO NOT USE THIS TOOL ON ANY NETWORK OR SYSTEM YOU DO NOT OWN OR HAVE EXPLICIT,
  WRITTEN PERMISSION TO TEST.
- Unauthorized scanning of networks is illegal and can lead to severe legal consequences.
- The authors and contributors of this software accept NO liability for any damage,
  data loss, or legal issues caused by the use or misuse of this tool.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

By using this software, you agree that you are solely responsible for your
actions and for complying with all applicable local, state, and federal laws.
"""

import os
import threading
import socket
import ipaddress
import time
import json
import subprocess
import platform
from datetime import datetime
from tkinter import ttk, messagebox, filedialog
import customtkinter as ctk
import google.generativeai as genai
from scapy.all import ARP, Ether, srp, ICMP, IP, sr1
import nmap
from dotenv import load_dotenv
import requests

# Load environment variables
load_dotenv()
GENAI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GENAI_API_KEY:
    print("Warning: API key not found. Set GEMINI_API_KEY as an environment variable for AI features.")

# Configure AI if API key is available
if GENAI_API_KEY:
    genai.configure(api_key=GENAI_API_KEY)
    tuned_model_id = "tunedModels/geminiprojectchatbot-gq16xik80ycb"
    models = ["gemini-1.5-pro", "gemini-1.0-pro", "gemini-flash", tuned_model_id]

# GUI Settings
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class NetworkScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("AI Network Scanner Pro")
        self.geometry("1200x800")
        self.resizable(True, True)
        
        # Configure grid layout
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # Create main container with sidebar
        self.create_main_layout()
        
        # Initialize variables
        self.devices = []
        self.scan_results = {}
        self.scan_thread = None
        self.stop_scan = False
        self.current_scan_type = None
        self.scan_history = []
        
        # Auto-detect network
        self.auto_detect_network()

    def create_main_layout(self):
        """Create the main layout with sidebar and content area"""
        # Main container
        self.main_container = ctk.CTkFrame(self)
        self.main_container.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.main_container.grid_columnconfigure(1, weight=1)
        self.main_container.grid_rowconfigure(0, weight=1)
        
        # Sidebar
        self.create_sidebar()
        
        # Content area
        self.create_content_area()

    def create_sidebar(self):
        """Create the sidebar with controls"""
        self.sidebar = ctk.CTkFrame(self.main_container, width=300)
        self.sidebar.grid(row=0, column=0, padx=(0, 10), pady=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        
        # Title
        title_label = ctk.CTkLabel(
            self.sidebar, text="Network Scanner", 
            font=ctk.CTkFont(size=20, weight="bold")
        )
        title_label.grid(row=0, column=0, padx=20, pady=(20, 10), sticky="w")
        
        # Network Configuration Section
        self.create_network_config_section()
        
        # Scan Options Section
        self.create_scan_options_section()
        
        # Control Buttons
        self.create_control_buttons()
        
        # Status Section
        self.create_status_section()

    def create_network_config_section(self):
        """Create network configuration section"""
        config_frame = ctk.CTkFrame(self.sidebar)
        config_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")
        
        ctk.CTkLabel(config_frame, text="Network Configuration", 
                    font=ctk.CTkFont(weight="bold")).pack(pady=(10, 5))
        
        # Network range
        ctk.CTkLabel(config_frame, text="Network Range:").pack(anchor="w", padx=10)
        self.network_combo = ctk.CTkComboBox(
            config_frame, 
            values=["Auto-detect", "192.168.1.0/24", "192.168.0.0/24", 
                   "192.168.43.0/24", "10.0.0.0/24", "172.16.0.0/24"],
            width=260
        )
        self.network_combo.pack(padx=10, pady=(5, 10))
        self.network_combo.set("Auto-detect")
        
        # Custom network entry
        ctk.CTkLabel(config_frame, text="Custom Network:").pack(anchor="w", padx=10)
        self.custom_network_entry = ctk.CTkEntry(
            config_frame, placeholder_text="192.168.x.0/24", width=260
        )
        self.custom_network_entry.pack(padx=10, pady=(5, 15))

    def create_scan_options_section(self):
        """Create scan options section"""
        options_frame = ctk.CTkFrame(self.sidebar)
        options_frame.grid(row=2, column=0, padx=20, pady=10, sticky="ew")
        
        ctk.CTkLabel(options_frame, text="Scan Options", 
                    font=ctk.CTkFont(weight="bold")).pack(pady=(10, 5))
        
        # Scan type
        ctk.CTkLabel(options_frame, text="Scan Type:").pack(anchor="w", padx=10)
        self.scan_type_combo = ctk.CTkComboBox(
            options_frame, 
            values=["Network Discovery", "Port Scan", "Service Detection", 
                   "Vulnerability Scan", "Full Scan"],
            width=260
        )
        self.scan_type_combo.pack(padx=10, pady=(5, 10))
        self.scan_type_combo.set("Network Discovery")
        
        # Port range
        ctk.CTkLabel(options_frame, text="Port Range:").pack(anchor="w", padx=10)
        self.port_range_combo = ctk.CTkComboBox(
            options_frame,
            values=["Common Ports", "1-1024", "1-65535", "Custom"],
            width=260
        )
        self.port_range_combo.pack(padx=10, pady=(5, 5))
        self.port_range_combo.set("Common Ports")
        
        # Custom port entry
        self.custom_port_entry = ctk.CTkEntry(
            options_frame, placeholder_text="80,443,22,21", width=260
        )
        self.custom_port_entry.pack(padx=10, pady=(5, 10))
        
        # Scan speed
        ctk.CTkLabel(options_frame, text="Scan Speed:").pack(anchor="w", padx=10)
        self.speed_slider = ctk.CTkSlider(options_frame, from_=1, to=5, number_of_steps=4)
        self.speed_slider.pack(padx=10, pady=(5, 5))
        self.speed_slider.set(3)  # Medium speed
        
        self.speed_label = ctk.CTkLabel(options_frame, text="Medium")
        self.speed_label.pack(pady=(0, 15))
        
        self.speed_slider.configure(command=self.update_speed_label)

    def create_control_buttons(self):
        """Create control buttons"""
        button_frame = ctk.CTkFrame(self.sidebar)
        button_frame.grid(row=3, column=0, padx=20, pady=10, sticky="ew")
        
        # Start scan button
        self.start_scan_btn = ctk.CTkButton(
            button_frame, text="Start Scan", height=40,
            command=self.start_comprehensive_scan,
            font=ctk.CTkFont(weight="bold")
        )
        self.start_scan_btn.pack(padx=10, pady=(15, 5), fill="x")
        
        # Stop scan button
        self.stop_scan_btn = ctk.CTkButton(
            button_frame, text="Stop Scan", height=35,
            fg_color="red", hover_color="dark red",
            command=self.stop_current_scan
        )
        self.stop_scan_btn.pack(padx=10, pady=5, fill="x")
        self.stop_scan_btn.configure(state="disabled")
        
        # Export results button
        self.export_btn = ctk.CTkButton(
            button_frame, text="Export Results", height=35,
            command=self.export_results
        )
        self.export_btn.pack(padx=10, pady=5, fill="x")
        
        # Clear results button
        self.clear_btn = ctk.CTkButton(
            button_frame, text="Clear Results", height=35,
            fg_color="orange", hover_color="dark orange",
            command=self.clear_results
        )
        self.clear_btn.pack(padx=10, pady=(5, 15), fill="x")

    def create_status_section(self):
        """Create status section"""
        status_frame = ctk.CTkFrame(self.sidebar)
        status_frame.grid(row=4, column=0, padx=20, pady=10, sticky="ew")
        
        ctk.CTkLabel(status_frame, text="Status", 
                    font=ctk.CTkFont(weight="bold")).pack(pady=(10, 5))
        
        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(status_frame, width=260)
        self.progress_bar.pack(padx=10, pady=5)
        self.progress_bar.set(0)
        
        # Status label
        self.status_label = ctk.CTkLabel(status_frame, text="Ready to scan")
        self.status_label.pack(padx=10, pady=(5, 15))

    def create_content_area(self):
        """Create the main content area with tabs"""
        self.content_frame = ctk.CTkFrame(self.main_container)
        self.content_frame.grid(row=0, column=1, padx=0, pady=0, sticky="nsew")
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)
        
        # Create tabview
        self.tabview = ctk.CTkTabview(self.content_frame)
        self.tabview.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        
        # Create tabs
        self.create_devices_tab()
        self.create_ports_tab()
        self.create_vulnerabilities_tab()
        self.create_network_map_tab()
        self.create_ai_chat_tab()
        self.create_logs_tab()

    def create_devices_tab(self):
        """Create devices tab"""
        devices_tab = self.tabview.add("Devices")
        
        # Create treeview with scrollbar
        tree_frame = ctk.CTkFrame(devices_tab)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Treeview
        columns = ("IP", "MAC", "Hostname", "Vendor", "OS", "Status", "Response Time")
        self.devices_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=15)
        
        # Configure column headings and widths
        column_widths = {"IP": 120, "MAC": 150, "Hostname": 120, "Vendor": 120, 
                        "OS": 100, "Status": 80, "Response Time": 100}
        
        for col in columns:
            self.devices_tree.heading(col, text=col)
            self.devices_tree.column(col, width=column_widths.get(col, 100))
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.devices_tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.devices_tree.xview)
        self.devices_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Pack treeview and scrollbars
        self.devices_tree.pack(side="left", fill="both", expand=True)
        v_scrollbar.pack(side="right", fill="y")
        h_scrollbar.pack(side="bottom", fill="x")
        
        # Bind double-click event
        self.devices_tree.bind("<Double-1>", self.on_device_double_click)

    def create_ports_tab(self):
        """Create ports tab"""
        ports_tab = self.tabview.add("Ports")
        
        # Create treeview
        tree_frame = ctk.CTkFrame(ports_tab)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        columns = ("IP", "Port", "Protocol", "Status", "Service", "Version", "Security")
        self.ports_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=15)
        
        column_widths = {"IP": 120, "Port": 60, "Protocol": 80, "Status": 80, 
                        "Service": 100, "Version": 150, "Security": 100}
        
        for col in columns:
            self.ports_tree.heading(col, text=col)
            self.ports_tree.column(col, width=column_widths.get(col, 100))
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.ports_tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.ports_tree.xview)
        self.ports_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.ports_tree.pack(side="left", fill="both", expand=True)
        v_scrollbar.pack(side="right", fill="y")
        h_scrollbar.pack(side="bottom", fill="x")

    def create_vulnerabilities_tab(self):
        """Create vulnerabilities tab"""
        vuln_tab = self.tabview.add("Vulnerabilities")
        
        tree_frame = ctk.CTkFrame(vuln_tab)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        columns = ("IP", "Port", "Vulnerability", "Severity", "Description", "Recommendation")
        self.vuln_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=15)
        
        column_widths = {"IP": 120, "Port": 60, "Vulnerability": 150, "Severity": 80, 
                        "Description": 200, "Recommendation": 200}
        
        for col in columns:
            self.vuln_tree.heading(col, text=col)
            self.vuln_tree.column(col, width=column_widths.get(col, 100))
        
        # Configure row colors based on severity
        self.vuln_tree.tag_configure("critical", background="#ff4444")
        self.vuln_tree.tag_configure("high", background="#ff8844")
        self.vuln_tree.tag_configure("medium", background="#ffaa44")
        self.vuln_tree.tag_configure("low", background="#88aa44")
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.vuln_tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.vuln_tree.xview)
        self.vuln_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.vuln_tree.pack(side="left", fill="both", expand=True)
        v_scrollbar.pack(side="right", fill="y")
        h_scrollbar.pack(side="bottom", fill="x")

    def create_network_map_tab(self):
        """Create network topology visualization tab"""
        map_tab = self.tabview.add("Network Map")
        
        # Network summary frame
        summary_frame = ctk.CTkFrame(map_tab)
        summary_frame.pack(fill="x", padx=10, pady=(10, 5))
        
        self.network_summary = ctk.CTkTextbox(summary_frame, height=100)
        self.network_summary.pack(fill="x", padx=10, pady=10)
        
        # Network details frame
        details_frame = ctk.CTkFrame(map_tab)
        details_frame.pack(fill="both", expand=True, padx=10, pady=(5, 10))
        
        self.network_details = ctk.CTkTextbox(details_frame, wrap="word")
        self.network_details.pack(fill="both", expand=True, padx=10, pady=10)

    def create_ai_chat_tab(self):
        """Create AI chat tab"""
        chat_tab = self.tabview.add("AI Assistant")
        
        # Chat display
        self.chat_display = ctk.CTkTextbox(chat_tab, wrap="word", state="disabled")
        self.chat_display.pack(fill="both", expand=True, padx=10, pady=(10, 5))
        
        # Chat input frame
        input_frame = ctk.CTkFrame(chat_tab)
        input_frame.pack(fill="x", padx=10, pady=(5, 10))
        
        # Chat entry
        self.chat_entry = ctk.CTkEntry(
            input_frame, placeholder_text="Ask the AI about network security, vulnerabilities, or scan results..."
        )
        self.chat_entry.pack(side="left", fill="x", expand=True, padx=(10, 5), pady=10)
        self.chat_entry.bind("<Return>", lambda e: self.process_chat_input())
        
        # Send button
        self.chat_button = ctk.CTkButton(
            input_frame, text="Send", width=80, command=self.process_chat_input
        )
        self.chat_button.pack(side="right", padx=(5, 10), pady=10)
        
        # Preset questions
        presets_frame = ctk.CTkFrame(chat_tab)
        presets_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        ctk.CTkLabel(presets_frame, text="Quick Questions:").pack(anchor="w", padx=10, pady=(10, 5))
        
        preset_questions = [
            "Analyze my scan results for security issues",
            "What ports should I be concerned about?",
            "How can I improve network security?",
            "Explain the vulnerabilities found"
        ]
        
        for i, question in enumerate(preset_questions):
            btn = ctk.CTkButton(
                presets_frame, text=question, height=30,
                command=lambda q=question: self.ask_preset_question(q)
            )
            btn.pack(side="left", padx=5, pady=(5, 10))
        
        # Initialize chat
        if GENAI_API_KEY:
            self.update_chat_display("AI Assistant", 
                "Hello! I'm your network security AI assistant. I can help you analyze scan results, "
                "identify security issues, and provide recommendations. How can I assist you today?")
        else:
            self.update_chat_display("System", 
                "AI Assistant is not available. Please set GEMINI_API_KEY environment variable to enable AI features.")

    def create_logs_tab(self):
        """Create logs tab"""
        logs_tab = self.tabview.add("Logs")
        
        # Log display
        self.log_display = ctk.CTkTextbox(logs_tab, wrap="word")
        self.log_display.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Add initial log entry
        self.log_message("System", "Network Scanner Pro initialized")

    def auto_detect_network(self):
        """Auto-detect the current network"""
        try:
            # Get default gateway
            if platform.system() == "Windows":
                result = subprocess.run(["ipconfig"], capture_output=True, text=True)
                output = result.stdout
            else:
                result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
                output = result.stdout
            
            # Extract network information
            import socket
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            # Determine network range
            ip_parts = local_ip.split('.')
            network_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            self.log_message("System", f"Auto-detected network: {network_range}")
            
            # Update combo box
            current_values = list(self.network_combo.cget("values"))
            if network_range not in current_values:
                current_values.insert(1, network_range)
                self.network_combo.configure(values=current_values)
            
        except Exception as e:
            self.log_message("Error", f"Failed to auto-detect network: {str(e)}")

    def update_speed_label(self, value):
        """Update speed label based on slider value"""
        speed_labels = ["Very Slow", "Slow", "Medium", "Fast", "Very Fast"]
        self.speed_label.configure(text=speed_labels[int(value) - 1])

    def start_comprehensive_scan(self):
        """Start a comprehensive network scan"""
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showwarning("Scan in Progress", "Please wait for the current scan to complete.")
            return
        
        # Get network range
        network = self.network_combo.get()
        if network == "Auto-detect":
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                ip_parts = local_ip.split('.')
                network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            except Exception as e:
                messagebox.showerror("Error", f"Failed to auto-detect network: {str(e)}")
                return
        elif self.custom_network_entry.get():
            network = self.custom_network_entry.get()
        
        # Validate network range
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError:
            messagebox.showerror("Invalid Network", "Please enter a valid network range (e.g., 192.168.1.0/24)")
            return
        
        # Clear previous results
        self.clear_results()
        
        # Start scan thread
        self.stop_scan = False
        self.scan_thread = threading.Thread(
            target=self.comprehensive_scan_thread, 
            args=(network,), 
            daemon=True
        )
        
        # Update UI
        self.start_scan_btn.configure(state="disabled")
        self.stop_scan_btn.configure(state="normal")
        self.progress_bar.set(0)
        self.status_label.configure(text="Starting scan...")
        
        self.scan_thread.start()
        self.monitor_scan_thread()

    def comprehensive_scan_thread(self, network):
        """Comprehensive network scanning thread"""
        try:
            scan_type = self.scan_type_combo.get()
            self.log_message("Scan", f"Starting {scan_type} on {network}")
            
            # Phase 1: Network Discovery
            self.update_status("Discovering devices...", 0.1)
            devices = self.discover_devices(network)
            
            if self.stop_scan:
                return
            
            # Phase 2: OS Detection and Service Detection
            if scan_type in ["Service Detection", "Full Scan"]:
                self.update_status("Detecting services...", 0.3)
                self.detect_services(devices)
            
            if self.stop_scan:
                return
            
            # Phase 3: Port Scanning
            if scan_type in ["Port Scan", "Full Scan"]:
                self.update_status("Scanning ports...", 0.5)
                self.scan_ports_comprehensive(devices)
            
            if self.stop_scan:
                return
            
            # Phase 4: Vulnerability Assessment
            if scan_type in ["Vulnerability Scan", "Full Scan"]:
                self.update_status("Checking vulnerabilities...", 0.7)
                self.vulnerability_assessment()
            
            # Phase 5: Generate Network Map
            self.update_status("Generating network map...", 0.9)
            self.generate_network_map()
            
            self.update_status("Scan completed successfully!", 1.0)
            self.log_message("Scan", f"Completed {scan_type} - Found {len(self.devices)} devices")
            
        except Exception as e:
            self.log_message("Error", f"Scan failed: {str(e)}")
            self.after(0, self.update_status, "Scan failed", 0)

    def discover_devices(self, network):
        """Discover devices on the network"""
        try:
            # Use ARP scan for fast discovery
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            
            result = srp(packet, timeout=3, verbose=0, inter=0.1)[0]
            
            devices = []
            for sent, received in result:
                if self.stop_scan:
                    break
                
                device = {
                    "ip": received.psrc,
                    "mac": received.hwsrc,
                    "hostname": self.get_hostname(received.psrc),
                    "vendor": self.get_mac_vendor(received.hwsrc),
                    "os": "Unknown",
                    "status": "Up",
                    "response_time": self.ping_host(received.psrc)
                }
                
                devices.append(device)
                self.devices.append(device)
                
                # Update UI
                self.after(0, self.add_device_to_tree, device)
                self.log_message("Discovery", f"Found device: {device['ip']} ({device['mac']})")
            
            return devices
            
        except Exception as e:
            self.log_message("Error", f"Device discovery failed: {str(e)}")
            return []

    def detect_services(self, devices):
        """Detect services and OS on discovered devices"""
        scanner = nmap.PortScanner()
        
        for device in devices:
            if self.stop_scan:
                break
                
            try:
                # OS detection scan
                scanner.scan(device["ip"], arguments="-O -sV --version-intensity 5")
                
                if device["ip"] in scanner.all_hosts():
                    host_info = scanner[device["ip"]]
                    
                    # OS detection
                    if "osmatch" in host_info:
                        os_matches = host_info["osmatch"]
                        if os_matches:
                            device["os"] = os_matches[0]["name"]
                    
                    # Update device info
                    self.after(0, self.update_device_in_tree, device)
                    
            except Exception as e:
                self.log_message("Error", f"Service detection failed for {device['ip']}: {str(e)}")

    def scan_ports_comprehensive(self, devices):
        """Comprehensive port scanning"""
        scanner = nmap.PortScanner()
        port_range = self.get_port_range()
        
        for device in devices:
            if self.stop_scan:
                break
                
            try:
                arguments = f"-sS -sV -p {port_range} --version-intensity 5"
                scanner.scan(device["ip"], arguments=arguments)
                
                if device["ip"] not in scanner.all_hosts():
                    continue
                
                host_info = scanner[device["ip"]]
                
                for proto in host_info.all_protocols():
                    for port in host_info[proto].keys():
                        if self.stop_scan:
                            break
                        
                        port_info = host_info[proto][port]
                        
                        if port_info["state"] == "open":
                            service_info = {
                                "ip": device["ip"],
                                "port": port,
                                "protocol": proto,
                                "status": port_info["state"],
                                "service": port_info.get("name", "unknown"),
                                "version": port_info.get("version", ""),
                                "security": self.assess_port_security(port, port_info.get("name", ""))
                            }
                            
                            self.after(0, self.add_port_to_tree, service_info)
                            self.log_message("Port Scan", 
                                f"Open port found: {device['ip']}:{port}/{proto} ({service_info['service']})")
                
            except Exception as e:
                self.log_message("Error", f"Port scan failed for {device['ip']}: {str(e)}")

    def vulnerability_assessment(self):
        """Perform basic vulnerability assessment"""
        # Common vulnerable ports and services
        vulnerable_services = {
            21: {"service": "FTP", "vuln": "Unencrypted data transfer", "severity": "Medium"},
            23: {"service": "Telnet", "vuln": "Unencrypted remote access", "severity": "High"},
            53: {"service": "DNS", "vuln": "DNS amplification attacks", "severity": "Medium"},
            80: {"service": "HTTP", "vuln": "Unencrypted web traffic", "severity": "Low"},
            135: {"service": "RPC", "vuln": "Remote code execution", "severity": "High"},
            139: {"service": "NetBIOS", "vuln": "Information disclosure", "severity": "Medium"},
            445: {"service": "SMB", "vuln": "SMB vulnerabilities", "severity": "Critical"},
            1433: {"service": "MSSQL", "vuln": "Database exposure", "severity": "High"},
            3389: {"service": "RDP", "vuln": "Brute force attacks", "severity": "High"},
        }
        
        # Check for vulnerabilities based on open ports
        for item in self.ports_tree.get_children():
            if self.stop_scan:
                break
                
            values = self.ports_tree.item(item)["values"]
            ip, port, protocol, status, service = values[:5]
            
            if status == "open" and int(port) in vulnerable_services:
                vuln_info = vulnerable_services[int(port)]
                vulnerability = {
                    "ip": ip,
                    "port": port,
                    "vulnerability": vuln_info["vuln"],
                    "severity": vuln_info["severity"],
                    "description": f"{vuln_info['service']} service detected on port {port}",
                    "recommendation": self.get_security_recommendation(int(port), vuln_info["service"])
                }
                
                self.after(0, self.add_vulnerability_to_tree, vulnerability)
                self.log_message("Vulnerability", 
                    f"Found {vuln_info['severity']} vulnerability: {vuln_info['vuln']} on {ip}:{port}")

    def get_port_range(self):
        """Get port range for scanning"""
        port_selection = self.port_range_combo.get()
        
        if port_selection == "Common Ports":
            return "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5432,5900"
        elif port_selection == "1-1024":
            return "1-1024"
        elif port_selection == "1-65535":
            return "1-65535"
        elif port_selection == "Custom":
            return self.custom_port_entry.get() or "1-1024"
        else:
            return "1-1024"

    def get_hostname(self, ip):
        """Get hostname for IP address"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Unknown"

    def get_mac_vendor(self, mac):
        """Get vendor information from MAC address"""
        try:
            # Use MAC vendor lookup API
            response = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
            if response.status_code == 200:
                return response.text
        except:
            pass
        
        # Fallback to common vendor prefixes
        vendor_prefixes = {
            "00:50:56": "VMware",
            "08:00:27": "VirtualBox",
            "00:0C:29": "VMware",
            "00:1C:42": "Parallels",
            "00:03:FF": "Microsoft",
            "00:15:5D": "Microsoft",
        }
        
        mac_prefix = mac[:8].upper()
        return vendor_prefixes.get(mac_prefix, "Unknown")

    def ping_host(self, ip):
        """Ping host and return response time"""
        try:
            packet = IP(dst=ip)/ICMP()
            start_time = time.time()
            reply = sr1(packet, timeout=2, verbose=0)
            if reply:
                return f"{(time.time() - start_time) * 1000:.1f}ms"
        except:
            pass
        return "N/A"

    def assess_port_security(self, port, service):
        """Assess security level of a port/service"""
        high_risk_ports = [21, 23, 135, 139, 445, 1433, 3389]
        medium_risk_ports = [53, 80, 110, 143, 993, 995]
        
        if port in high_risk_ports:
            return "High Risk"
        elif port in medium_risk_ports:
            return "Medium Risk"
        elif port in [22, 443]:
            return "Secure"
        else:
            return "Unknown"

    def get_security_recommendation(self, port, service):
        """Get security recommendation for a service"""
        recommendations = {
            21: "Disable FTP or use SFTP/FTPS instead",
            23: "Disable Telnet and use SSH instead",
            53: "Secure DNS configuration, disable recursion",
            80: "Implement HTTPS redirection",
            135: "Disable RPC if not needed, use firewall",
            139: "Disable NetBIOS or restrict access",
            445: "Keep SMB updated, use SMB3+, restrict access",
            1433: "Secure database access, use encryption",
            3389: "Use strong passwords, enable NLA, restrict access"
        }
        
        return recommendations.get(port, "Review service configuration and access controls")

    def generate_network_map(self):
        """Generate network topology and summary"""
        try:
            # Network summary
            total_devices = len(self.devices)
            total_ports = len(self.ports_tree.get_children())
            total_vulns = len(self.vuln_tree.get_children())
            
            summary = f"""Network Scan Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Total Devices Found: {total_devices}
Total Open Ports: {total_ports}
Total Vulnerabilities: {total_vulns}

Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
            
            self.network_summary.delete("1.0", "end")
            self.network_summary.insert("1.0", summary)
            
            # Network details
            details = "Network Topology Analysis\n" + "="*50 + "\n\n"
            
            # Device breakdown
            os_count = {}
            vendor_count = {}
            
            for device in self.devices:
                os = device.get("os", "Unknown")
                vendor = device.get("vendor", "Unknown")
                
                os_count[os] = os_count.get(os, 0) + 1
                vendor_count[vendor] = vendor_count.get(vendor, 0) + 1
            
            details += "Operating Systems:\n"
            for os, count in sorted(os_count.items(), key=lambda x: x[1], reverse=True):
                details += f"  • {os}: {count} devices\n"
            
            details += "\nVendors:\n"
            for vendor, count in sorted(vendor_count.items(), key=lambda x: x[1], reverse=True):
                details += f"  • {vendor}: {count} devices\n"
            
            # Service analysis
            details += "\nCommon Services Found:\n"
            service_count = {}
            
            for item in self.ports_tree.get_children():
                values = self.ports_tree.item(item)["values"]
                service = values[4] if len(values) > 4 else "unknown"
                service_count[service] = service_count.get(service, 0) + 1
            
            for service, count in sorted(service_count.items(), key=lambda x: x[1], reverse=True)[:10]:
                details += f"  • {service}: {count} instances\n"
            
            # Security recommendations
            details += "\nSecurity Recommendations:\n"
            if total_vulns > 0:
                details += f"  ⚠️  {total_vulns} vulnerabilities found - review immediately\n"
            
            high_risk_count = sum(1 for item in self.ports_tree.get_children() 
                                if "High Risk" in str(self.ports_tree.item(item)["values"]))
            if high_risk_count > 0:
                details += f"  🔴 {high_risk_count} high-risk services detected\n"
            
            details += "  🔒 Implement network segmentation\n"
            details += "  🛡️  Keep all systems updated\n"
            details += "  🔐 Use strong authentication\n"
            details += "  📊 Regular security audits recommended\n"
            
            self.network_details.delete("1.0", "end")
            self.network_details.insert("1.0", details)
            
        except Exception as e:
            self.log_message("Error", f"Failed to generate network map: {str(e)}")

    def add_device_to_tree(self, device):
        """Add device to the devices tree"""
        values = (
            device["ip"],
            device["mac"],
            device["hostname"],
            device["vendor"],
            device["os"],
            device["status"],
            device["response_time"]
        )
        self.devices_tree.insert("", "end", values=values)

    def update_device_in_tree(self, device):
        """Update device information in the tree"""
        for item in self.devices_tree.get_children():
            if self.devices_tree.item(item)["values"][0] == device["ip"]:
                values = (
                    device["ip"],
                    device["mac"],
                    device["hostname"],
                    device["vendor"],
                    device["os"],
                    device["status"],
                    device["response_time"]
                )
                self.devices_tree.item(item, values=values)
                break

    def add_port_to_tree(self, port_info):
        """Add port information to the ports tree"""
        values = (
            port_info["ip"],
            port_info["port"],
            port_info["protocol"],
            port_info["status"],
            port_info["service"],
            port_info["version"],
            port_info["security"]
        )
        self.ports_tree.insert("", "end", values=values)

    def add_vulnerability_to_tree(self, vuln_info):
        """Add vulnerability to the vulnerabilities tree"""
        values = (
            vuln_info["ip"],
            vuln_info["port"],
            vuln_info["vulnerability"],
            vuln_info["severity"],
            vuln_info["description"],
            vuln_info["recommendation"]
        )
        
        # Set color based on severity
        severity = vuln_info["severity"].lower()
        item = self.vuln_tree.insert("", "end", values=values)
        if severity in ["critical", "high", "medium", "low"]:
            self.vuln_tree.set(item, "#0", "")
            self.vuln_tree.item(item, tags=(severity,))

    def on_device_double_click(self, event):
        """Handle double-click on device"""
        selection = self.devices_tree.selection()
        if selection:
            item = self.devices_tree.item(selection[0])
            ip = item["values"][0]
            
            # Show detailed device information
            self.show_device_details(ip)

    def show_device_details(self, ip):
        """Show detailed information about a device"""
        details_window = ctk.CTkToplevel(self)
        details_window.title(f"Device Details - {ip}")
        details_window.geometry("600x400")
        
        # Create text widget for details
        details_text = ctk.CTkTextbox(details_window, wrap="word")
        details_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Gather device information
        device_info = None
        for device in self.devices:
            if device["ip"] == ip:
                device_info = device
                break
        
        if device_info:
            details = f"""Device Information for {ip}
{'='*50}

IP Address: {device_info['ip']}
MAC Address: {device_info['mac']}
Hostname: {device_info['hostname']}
Vendor: {device_info['vendor']}
Operating System: {device_info['os']}
Status: {device_info['status']}
Response Time: {device_info['response_time']}

Open Ports:
"""
            
            # Add port information
            for item in self.ports_tree.get_children():
                port_values = self.ports_tree.item(item)["values"]
                if port_values[0] == ip:
                    details += f"  • Port {port_values[1]}/{port_values[2]} - {port_values[4]} ({port_values[5]})\n"
            
            # Add vulnerability information
            vuln_found = False
            for item in self.vuln_tree.get_children():
                vuln_values = self.vuln_tree.item(item)["values"]
                if vuln_values[0] == ip:
                    if not vuln_found:
                        details += "\nVulnerabilities:\n"
                        vuln_found = True
                    details += f"  ⚠️  {vuln_values[2]} (Severity: {vuln_values[3]})\n"
                    details += f"      {vuln_values[4]}\n"
                    details += f"      Recommendation: {vuln_values[5]}\n\n"
            
            details_text.insert("1.0", details)

    def update_status(self, message, progress):
        """Update status and progress"""
        self.after(0, lambda: self.status_label.configure(text=message))
        self.after(0, lambda: self.progress_bar.set(progress))

    def stop_current_scan(self):
        """Stop the current scan"""
        self.stop_scan = True
        self.log_message("Scan", "Scan stopped by user")

    def monitor_scan_thread(self):
        """Monitor scan thread and update UI when complete"""
        if self.scan_thread and self.scan_thread.is_alive():
            self.after(100, self.monitor_scan_thread)
        else:
            self.start_scan_btn.configure(state="normal")
            self.stop_scan_btn.configure(state="disabled")
            self.scan_thread = None

    def clear_results(self):
        """Clear all scan results"""
        self.devices_tree.delete(*self.devices_tree.get_children())
        self.ports_tree.delete(*self.ports_tree.get_children())
        self.vuln_tree.delete(*self.vuln_tree.get_children())
        self.network_summary.delete("1.0", "end")
        self.network_details.delete("1.0", "end")
        self.devices = []
        self.scan_results = {}
        self.progress_bar.set(0)
        self.status_label.configure(text="Ready to scan")
        self.log_message("System", "Results cleared")

    def export_results(self):
        """Export scan results to file"""
        if not self.devices:
            messagebox.showwarning("No Data", "No scan results to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                # Prepare data for export
                export_data = {
                    "scan_timestamp": datetime.now().isoformat(),
                    "devices": self.devices,
                    "ports": [],
                    "vulnerabilities": []
                }
                
                # Add port data
                for item in self.ports_tree.get_children():
                    values = self.ports_tree.item(item)["values"]
                    export_data["ports"].append({
                        "ip": values[0],
                        "port": values[1],
                        "protocol": values[2],
                        "status": values[3],
                        "service": values[4],
                        "version": values[5],
                        "security": values[6]
                    })
                
                # Add vulnerability data
                for item in self.vuln_tree.get_children():
                    values = self.vuln_tree.item(item)["values"]
                    export_data["vulnerabilities"].append({
                        "ip": values[0],
                        "port": values[1],
                        "vulnerability": values[2],
                        "severity": values[3],
                        "description": values[4],
                        "recommendation": values[5]
                    })
                
                # Write to file
                if filename.endswith('.json'):
                    with open(filename, 'w') as f:
                        json.dump(export_data, f, indent=2)
                else:
                    with open(filename, 'w') as f:
                        f.write(f"Network Scan Results\n")
                        f.write(f"Timestamp: {export_data['scan_timestamp']}\n\n")
                        
                        f.write("Devices:\n")
                        for device in export_data['devices']:
                            f.write(f"  {device['ip']} - {device['mac']} ({device['hostname']})\n")
                        
                        f.write("\nOpen Ports:\n")
                        for port in export_data['ports']:
                            f.write(f"  {port['ip']}:{port['port']}/{port['protocol']} - {port['service']}\n")
                        
                        f.write("\nVulnerabilities:\n")
                        for vuln in export_data['vulnerabilities']:
                            f.write(f"  {vuln['ip']}:{vuln['port']} - {vuln['vulnerability']} ({vuln['severity']})\n")
                
                messagebox.showinfo("Export Complete", f"Results exported to {filename}")
                self.log_message("Export", f"Results exported to {filename}")
                
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export results: {str(e)}")
                self.log_message("Error", f"Export failed: {str(e)}")

    def process_chat_input(self):
        """Process user input in the chat interface"""
        if not GENAI_API_KEY:
            self.update_chat_display("System", "AI Assistant is not available. Please set GEMINI_API_KEY environment variable.")
            return
        
        user_input = self.chat_entry.get().strip()
        if not user_input:
            return
        
        self.update_chat_display("You", user_input)
        self.chat_entry.delete(0, "end")
        
        # Disable chat button while processing
        self.chat_button.configure(state="disabled", text="Thinking...")
        
        # Get AI response in a separate thread
        threading.Thread(
            target=self.get_ai_response, args=(user_input,), daemon=True
        ).start()

    def ask_preset_question(self, question):
        """Ask a preset question"""
        self.chat_entry.delete(0, "end")
        self.chat_entry.insert(0, question)
        self.process_chat_input()

    def get_ai_response(self, user_input):
        """Get response from Gemini AI"""
        try:
            # Prepare context with scan results
            context = """You are an expert network security analyst. Provide clear, actionable advice about:
- Network security vulnerabilities and risks
- Port and service analysis
- Network hardening recommendations
- Incident response guidance
- Security best practices

Current scan results context:
"""
            
            # Add scan results to context
            if self.devices:
                context += f"\nDevices found: {len(self.devices)}"
                context += f"\nOpen ports: {len(self.ports_tree.get_children())}"
                context += f"\nVulnerabilities: {len(self.vuln_tree.get_children())}"
                
                # Add device details
                context += "\n\nDevice details:\n"
                for device in self.devices[:5]:  # Limit to first 5 devices
                    context += f"- {device['ip']} ({device['os']}, {device['vendor']})\n"
                
                # Add critical vulnerabilities
                context += "\nCritical vulnerabilities:\n"
                vuln_count = 0
                for item in self.vuln_tree.get_children():
                    if vuln_count >= 5:  # Limit to 5 vulnerabilities
                        break
                    values = self.vuln_tree.item(item)["values"]
                    if values[3] in ["Critical", "High"]:
                        context += f"- {values[0]}:{values[1]} - {values[2]} ({values[3]})\n"
                        vuln_count += 1
            
            # Try different models
            for model_name in models:
                try:
                    model = genai.GenerativeModel(model_name)
                    response = model.generate_content(f"{context}\n\nUser Question: {user_input}")
                    
                    if response and response.candidates:
                        answer = response.candidates[0].content.parts[0].text
                        self.after(0, self.update_chat_display, "AI Assistant", answer)
                        self.after(0, lambda: self.chat_button.configure(state="normal", text="Send"))
                        return
                        
                except Exception as e:
                    print(f"Error with {model_name}: {e}")
                    continue
            
            # If all models fail
            self.after(0, self.update_chat_display, "AI Assistant", 
                      "I apologize, but I'm having trouble processing your request. Please try again.")
            
        except Exception as e:
            self.after(0, self.update_chat_display, "AI Assistant", 
                      f"Error processing request: {str(e)}")
        
        finally:
            self.after(0, lambda: self.chat_button.configure(state="normal", text="Send"))

    def update_chat_display(self, sender, message):
        """Update the chat display with a new message"""
        self.chat_display.configure(state="normal")
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.chat_display.insert("end", f"[{timestamp}] {sender}: {message}\n\n")
        self.chat_display.configure(state="disabled")
        self.chat_display.see("end")

    def log_message(self, category, message):
        """Add a message to the log display"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {category}: {message}\n"
        self.log_display.insert("end", log_entry)
        self.log_display.see("end")

if __name__ == "__main__":
    try:
        app = NetworkScannerApp()
        app.mainloop()
    except Exception as e:
        print(f"Application error: {e}")
        messagebox.showerror("Application Error", f"Failed to start application: {e}")