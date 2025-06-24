import sys
import socket
import threading
import time
import os
import subprocess
import platform
import datetime
from collections import defaultdict
import dns.resolver
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from tkinter import Menu
import psutil
import netifaces
import numpy as np
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from scapy.sendrecv import sr1
import pandas as pd
from PIL import Image, ImageTk

class CyberSecurityTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Accurate Cyber Defense Cyber Drill Advanced Tool")
        self.root.geometry("1200x800")
        self.root.configure(bg='black')
        
        # Theme colors
        self.bg_color = 'black'
        self.fg_color = 'green'
        self.highlight_color = '#00ff00'
        
        # Monitoring flags
        self.monitoring_active = False
        self.ddos_monitoring = False
        self.dos_monitoring = False
        self.portscan_monitoring = False
        
        # Data storage
        self.threat_data = defaultdict(int)
        self.packet_counts = defaultdict(int)
        self.connection_data = []
        self.start_time = time.time()
        
        # Create main containers
        self.create_menu()
        self.create_dashboard()
        self.create_terminal()
        self.create_monitoring_panel()
        self.create_visualization_frame()
        
        # Initialize network monitoring
        self.initialize_network_interfaces()
        
        # Start update thread
        self.update_thread = threading.Thread(target=self.update_data, daemon=True)
        self.update_thread.start()
    
    def create_menu(self):
        # Create menu bar
        menubar = Menu(self.root, bg=self.bg_color, fg=self.fg_color, activebackground=self.bg_color, activeforeground=self.highlight_color)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = Menu(menubar, tearoff=0, bg=self.bg_color, fg=self.fg_color)
        file_menu.add_command(label="Save Log", command=self.save_log)
        file_menu.add_command(label="Export Data", command=self.export_data)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Tools menu
        tools_menu = Menu(menubar, tearoff=0, bg=self.bg_color, fg=self.fg_color)
        tools_menu.add_command(label="Network Scanner", command=self.open_network_scanner)
        tools_menu.add_command(label="Packet Analyzer", command=self.open_packet_analyzer)
        tools_menu.add_command(label="Vulnerability Scanner", command=self.open_vulnerability_scanner)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # View menu
        view_menu = Menu(menubar, tearoff=0, bg=self.bg_color, fg=self.fg_color)
        view_menu.add_command(label="Dashboard", command=self.show_dashboard)
        view_menu.add_command(label="Terminal", command=self.show_terminal)
        view_menu.add_command(label="Monitoring", command=self.show_monitoring)
        view_menu.add_command(label="Visualizations", command=self.show_visualizations)
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Help menu
        help_menu = Menu(menubar, tearoff=0, bg=self.bg_color, fg=self.fg_color)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
    
    def create_dashboard(self):
        self.dashboard_frame = tk.Frame(self.root, bg=self.bg_color)
        self.dashboard_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header = tk.Label(self.dashboard_frame, text="CYBER SECURITY MONITORING DASHBOARD", 
                          font=('Courier', 18, 'bold'), bg=self.bg_color, fg=self.highlight_color)
        header.pack(pady=20)
        
        # Stats frame
        stats_frame = tk.Frame(self.dashboard_frame, bg=self.bg_color)
        stats_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # System info
        sys_info_frame = tk.LabelFrame(stats_frame, text="System Information", bg=self.bg_color, fg=self.fg_color, 
                                      font=('Courier', 10, 'bold'))
        sys_info_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        self.hostname_label = tk.Label(sys_info_frame, text=f"Hostname: {socket.gethostname()}", 
                                      bg=self.bg_color, fg=self.fg_color, anchor='w')
        self.hostname_label.pack(fill=tk.X, padx=5, pady=2)
        
        self.os_label = tk.Label(sys_info_frame, text=f"OS: {platform.platform()}", 
                                bg=self.bg_color, fg=self.fg_color, anchor='w')
        self.os_label.pack(fill=tk.X, padx=5, pady=2)
        
        self.ip_label = tk.Label(sys_info_frame, text="IP Address: Loading...", 
                                bg=self.bg_color, fg=self.fg_color, anchor='w')
        self.ip_label.pack(fill=tk.X, padx=5, pady=2)
        
        # Network stats
        net_stats_frame = tk.LabelFrame(stats_frame, text="Network Statistics", bg=self.bg_color, fg=self.fg_color, 
                                       font=('Courier', 10, 'bold'))
        net_stats_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        self.packets_label = tk.Label(net_stats_frame, text="Packets Analyzed: 0", 
                                     bg=self.bg_color, fg=self.fg_color, anchor='w')
        self.packets_label.pack(fill=tk.X, padx=5, pady=2)
        
        self.connections_label = tk.Label(net_stats_frame, text="Active Connections: 0", 
                                         bg=self.bg_color, fg=self.fg_color, anchor='w')
        self.connections_label.pack(fill=tk.X, padx=5, pady=2)
        
        self.threats_label = tk.Label(net_stats_frame, text="Threats Detected: 0", 
                                      bg=self.bg_color, fg=self.fg_color, anchor='w')
        self.threats_label.pack(fill=tk.X, padx=5, pady=2)
        
        # Threat summary
        threat_frame = tk.LabelFrame(self.dashboard_frame, text="Threat Summary", bg=self.bg_color, fg=self.fg_color, 
                                     font=('Courier', 10, 'bold'))
        threat_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.threat_text = scrolledtext.ScrolledText(threat_frame, height=10, bg='black', fg='green', 
                                                   insertbackground='green', font=('Courier', 10))
        self.threat_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.threat_text.insert(tk.END, "No threats detected yet.\n")
        self.threat_text.config(state=tk.DISABLED)
        
        # Quick actions
        action_frame = tk.Frame(self.dashboard_frame, bg=self.bg_color)
        action_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.start_monitor_btn = tk.Button(action_frame, text="Start Monitoring", command=self.start_monitoring, 
                                          bg=self.bg_color, fg=self.fg_color, activebackground=self.bg_color, 
                                          activeforeground=self.highlight_color)
        self.start_monitor_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_monitor_btn = tk.Button(action_frame, text="Stop Monitoring", command=self.stop_monitoring, 
                                         bg=self.bg_color, fg=self.fg_color, activebackground=self.bg_color, 
                                         activeforeground=self.highlight_color, state=tk.DISABLED)
        self.stop_monitor_btn.pack(side=tk.LEFT, padx=5)
        
        self.terminal_btn = tk.Button(action_frame, text="Open Terminal", command=self.show_terminal, 
                                    bg=self.bg_color, fg=self.fg_color, activebackground=self.bg_color, 
                                    activeforeground=self.highlight_color)
        self.terminal_btn.pack(side=tk.RIGHT, padx=5)
    
    def create_terminal(self):
        self.terminal_frame = tk.Frame(self.root, bg=self.bg_color)
        
        # Terminal header
        terminal_header = tk.Label(self.terminal_frame, text="CYBER SECURITY TERMINAL", 
                                  font=('Courier', 18, 'bold'), bg=self.bg_color, fg=self.highlight_color)
        terminal_header.pack(pady=10)
        
        # Terminal output
        self.terminal_output = scrolledtext.ScrolledText(self.terminal_frame, height=20, bg='black', fg='green', 
                                                        insertbackground='green', font=('Courier', 10))
        self.terminal_output.pack(fill=tk.BOTH, expand=True, padx=20, pady=5)
        self.terminal_output.insert(tk.END, "Cyber Security Terminal - Type 'help' for commands\n")
        self.terminal_output.config(state=tk.DISABLED)
        
        # Terminal input
        input_frame = tk.Frame(self.terminal_frame, bg=self.bg_color)
        input_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.cmd_prompt = tk.Label(input_frame, text=">>", bg=self.bg_color, fg=self.highlight_color)
        self.cmd_prompt.pack(side=tk.LEFT)
        
        self.cmd_entry = tk.Entry(input_frame, bg='black', fg='green', insertbackground='green', 
                                 font=('Courier', 10), width=80)
        self.cmd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.cmd_entry.bind("<Return>", self.execute_command)
        
        # Back to dashboard button
        back_btn = tk.Button(self.terminal_frame, text="Back to Dashboard", command=self.show_dashboard, 
                            bg=self.bg_color, fg=self.fg_color, activebackground=self.bg_color, 
                            activeforeground=self.highlight_color)
        back_btn.pack(pady=10)
    
    def create_monitoring_panel(self):
        self.monitoring_frame = tk.Frame(self.root, bg=self.bg_color)
        
        # Monitoring header
        monitoring_header = tk.Label(self.monitoring_frame, text="REAL-TIME THREAT MONITORING", 
                                    font=('Courier', 18, 'bold'), bg=self.bg_color, fg=self.highlight_color)
        monitoring_header.pack(pady=10)
        
        # Monitoring controls
        controls_frame = tk.Frame(self.monitoring_frame, bg=self.bg_color)
        controls_frame.pack(fill=tk.X, padx=20, pady=10)
        
        # IP Address input
        ip_frame = tk.Frame(controls_frame, bg=self.bg_color)
        ip_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(ip_frame, text="Target IP:", bg=self.bg_color, fg=self.fg_color).pack(side=tk.LEFT)
        self.target_ip = tk.Entry(ip_frame, bg='black', fg='green', insertbackground='green', 
                                 font=('Courier', 10), width=20)
        self.target_ip.pack(side=tk.LEFT, padx=5)
        self.target_ip.insert(0, "127.0.0.1")
        
        # Monitoring options
        options_frame = tk.Frame(controls_frame, bg=self.bg_color)
        options_frame.pack(fill=tk.X, pady=5)
        
        self.ddos_var = tk.IntVar()
        self.dos_var = tk.IntVar()
        self.portscan_var = tk.IntVar()
        
        tk.Checkbutton(options_frame, text="DDoS Monitoring", variable=self.ddos_var, 
                      bg=self.bg_color, fg=self.fg_color, selectcolor=self.bg_color, 
                      activebackground=self.bg_color, activeforeground=self.fg_color).pack(side=tk.LEFT, padx=10)
        
        tk.Checkbutton(options_frame, text="DoS Monitoring", variable=self.dos_var, 
                      bg=self.bg_color, fg=self.fg_color, selectcolor=self.bg_color, 
                      activebackground=self.bg_color, activeforeground=self.fg_color).pack(side=tk.LEFT, padx=10)
        
        tk.Checkbutton(options_frame, text="Port Scan Monitoring", variable=self.portscan_var, 
                      bg=self.bg_color, fg=self.fg_color, selectcolor=self.bg_color, 
                      activebackground=self.bg_color, activeforeground=self.fg_color).pack(side=tk.LEFT, padx=10)
        
        # Start/Stop buttons
        btn_frame = tk.Frame(controls_frame, bg=self.bg_color)
        btn_frame.pack(fill=tk.X, pady=10)
        
        self.start_monitor_btn2 = tk.Button(btn_frame, text="Start Monitoring", command=self.start_specific_monitoring, 
                                          bg=self.bg_color, fg=self.fg_color, activebackground=self.bg_color, 
                                          activeforeground=self.highlight_color)
        self.start_monitor_btn2.pack(side=tk.LEFT, padx=5)
        
        self.stop_monitor_btn2 = tk.Button(btn_frame, text="Stop Monitoring", command=self.stop_specific_monitoring, 
                                         bg=self.bg_color, fg=self.fg_color, activebackground=self.bg_color, 
                                         activeforeground=self.highlight_color, state=tk.DISABLED)
        self.stop_monitor_btn2.pack(side=tk.LEFT, padx=5)
        
        # Monitoring output
        self.monitor_output = scrolledtext.ScrolledText(self.monitoring_frame, height=20, bg='black', fg='green', 
                                                        insertbackground='green', font=('Courier', 10))
        self.monitor_output.pack(fill=tk.BOTH, expand=True, padx=20, pady=5)
        self.monitor_output.insert(tk.END, "Monitoring panel ready. Select options and click Start Monitoring.\n")
        self.monitor_output.config(state=tk.DISABLED)
        
        # Back to dashboard button
        back_btn = tk.Button(self.monitoring_frame, text="Back to Dashboard", command=self.show_dashboard, 
                            bg=self.bg_color, fg=self.fg_color, activebackground=self.bg_color, 
                            activeforeground=self.highlight_color)
        back_btn.pack(pady=10)
    
    def create_visualization_frame(self):
        self.visualization_frame = tk.Frame(self.root, bg=self.bg_color)
        
        # Visualization header
        viz_header = tk.Label(self.visualization_frame, text="THREAT VISUALIZATION", 
                             font=('Courier', 18, 'bold'), bg=self.bg_color, fg=self.highlight_color)
        viz_header.pack(pady=10)
        
        # Visualization controls
        controls_frame = tk.Frame(self.visualization_frame, bg=self.bg_color)
        controls_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Button(controls_frame, text="Update Charts", command=self.update_visualizations, 
                 bg=self.bg_color, fg=self.fg_color, activebackground=self.bg_color, 
                 activeforeground=self.highlight_color).pack(side=tk.LEFT, padx=5)
        
        # Chart frame
        chart_frame = tk.Frame(self.visualization_frame, bg=self.bg_color)
        chart_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Threat type pie chart
        self.pie_frame = tk.Frame(chart_frame, bg=self.bg_color)
        self.pie_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Packet type bar chart
        self.bar_frame = tk.Frame(chart_frame, bg=self.bg_color)
        self.bar_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create initial empty charts
        self.create_empty_charts()
        
        # Back to dashboard button
        back_btn = tk.Button(self.visualization_frame, text="Back to Dashboard", command=self.show_dashboard, 
                            bg=self.bg_color, fg=self.fg_color, activebackground=self.bg_color, 
                            activeforeground=self.highlight_color)
        back_btn.pack(pady=10)
    
    def create_empty_charts(self):
        # Create empty pie chart
        fig1, ax1 = plt.subplots(figsize=(5, 4), facecolor='black')
        ax1.set_title('Threat Distribution', color='green')
        ax1.pie([1], labels=['No Data'], colors=['gray'], textprops={'color': 'green'})
        self.pie_canvas = FigureCanvasTkAgg(fig1, self.pie_frame)
        self.pie_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Create empty bar chart
        fig2, ax2 = plt.subplots(figsize=(5, 4), facecolor='black')
        ax2.set_title('Packet Types', color='green')
        ax2.bar(['No Data'], [1], color='gray')
        ax2.tick_params(axis='x', colors='green')
        ax2.tick_params(axis='y', colors='green')
        ax2.set_facecolor('black')
        self.bar_canvas = FigureCanvasTkAgg(fig2, self.bar_frame)
        self.bar_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def initialize_network_interfaces(self):
        try:
            # Get default network interface
            self.network_interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
            
            # Get IP address
            addrs = netifaces.ifaddresses(self.network_interface)
            self.ip_address = addrs[netifaces.AF_INET][0]['addr']
            
            # Update UI
            self.ip_label.config(text=f"IP Address: {self.ip_address}")
            
        except Exception as e:
            self.log_error(f"Error initializing network: {str(e)}")
            self.ip_address = "127.0.0.1"
            self.ip_label.config(text=f"IP Address: {self.ip_address} (Error)")
    
    def start_monitoring(self):
        if not self.monitoring_active:
            self.monitoring_active = True
            self.start_monitor_btn.config(state=tk.DISABLED)
            self.stop_monitor_btn.config(state=tk.NORMAL)
            self.start_monitor_btn2.config(state=tk.DISABLED)
            self.stop_monitor_btn2.config(state=tk.NORMAL)
            
            # Start all monitoring types
            self.ddos_monitoring = True
            self.dos_monitoring = True
            self.portscan_monitoring = True
            
            # Start packet capture thread
            self.capture_thread = threading.Thread(target=self.start_packet_capture, daemon=True)
            self.capture_thread.start()
            
            self.log_message("Started monitoring all threat types")
            self.update_terminal("Started comprehensive monitoring of all threat types")
        else:
            self.log_message("Monitoring is already active")
    
    def stop_monitoring(self):
        if self.monitoring_active:
            self.monitoring_active = False
            self.ddos_monitoring = False
            self.dos_monitoring = False
            self.portscan_monitoring = False
            
            self.start_monitor_btn.config(state=tk.NORMAL)
            self.stop_monitor_btn.config(state=tk.DISABLED)
            self.start_monitor_btn2.config(state=tk.NORMAL)
            self.stop_monitor_btn2.config(state=tk.DISABLED)
            
            self.log_message("Stopped all monitoring")
            self.update_terminal("Stopped all monitoring activities")
        else:
            self.log_message("No active monitoring to stop")
    
    def start_specific_monitoring(self):
        target_ip = self.target_ip.get()
        if not self.validate_ip(target_ip):
            messagebox.showerror("Invalid IP", "Please enter a valid IP address")
            return
            
        if not self.monitoring_active:
            self.monitoring_active = True
            self.start_monitor_btn.config(state=tk.DISABLED)
            self.stop_monitor_btn.config(state=tk.NORMAL)
            self.start_monitor_btn2.config(state=tk.DISABLED)
            self.stop_monitor_btn2.config(state=tk.NORMAL)
            
            # Set monitoring types based on checkboxes
            self.ddos_monitoring = bool(self.ddos_var.get())
            self.dos_monitoring = bool(self.dos_var.get())
            self.portscan_monitoring = bool(self.portscan_var.get())
            
            # Start packet capture thread
            self.capture_thread = threading.Thread(target=self.start_packet_capture, daemon=True)
            self.capture_thread.start()
            
            monitoring_types = []
            if self.ddos_monitoring:
                monitoring_types.append("DDoS")
            if self.dos_monitoring:
                monitoring_types.append("DoS")
            if self.portscan_monitoring:
                monitoring_types.append("Port Scan")
                
            self.log_message(f"Started monitoring: {', '.join(monitoring_types)} for IP: {target_ip}")
            self.update_terminal(f"Started monitoring: {', '.join(monitoring_types)} for IP: {target_ip}")
        else:
            self.log_message("Monitoring is already active")
    
    def stop_specific_monitoring(self):
        self.stop_monitoring()
    
    def start_packet_capture(self):
        try:
            # Start packet capture on the selected interface
            sniff(prn=self.analyze_packet, filter="ip", store=0, iface=self.network_interface)
        except Exception as e:
            self.log_error(f"Packet capture error: {str(e)}")
    
    def analyze_packet(self, packet):
        if not self.monitoring_active:
            return
            
        try:
            # Count packet types
            if IP in packet:
                self.packet_counts['IP'] += 1
                
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Check if packet is targeting our IP
                target_ip = self.target_ip.get()
                if dst_ip == target_ip or src_ip == target_ip:
                    # Detect DDoS/DoS
                    if self.ddos_monitoring or self.dos_monitoring:
                        self.detect_dos_ddos(packet, src_ip, dst_ip)
                    
                    # Detect port scanning
                    if self.portscan_monitoring and TCP in packet:
                        self.detect_port_scan(packet, src_ip, dst_ip)
                    
                    # Log the packet
                    self.log_packet(packet)
            
            if TCP in packet:
                self.packet_counts['TCP'] += 1
            elif UDP in packet:
                self.packet_counts['UDP'] += 1
            elif ICMP in packet:
                self.packet_counts['ICMP'] += 1
            elif ARP in packet:
                self.packet_counts['ARP'] += 1
            
        except Exception as e:
            self.log_error(f"Packet analysis error: {str(e)}")
    
    def detect_dos_ddos(self, packet, src_ip, dst_ip):
        current_time = time.time()
        
        # Simple threshold-based detection
        packet_count = sum(1 for p in self.connection_data if p['src_ip'] == src_ip and 
                          current_time - p['time'] < 1.0)  # Count packets in last second
        
        if packet_count > 100:  # Threshold for DoS
            self.threat_data['DoS'] += 1
            threat_msg = f"DoS attack detected from {src_ip} to {dst_ip} - {packet_count} packets/sec"
            self.log_threat(threat_msg, "High")
            
        elif packet_count > 1000:  # Threshold for DDoS
            self.threat_data['DDoS'] += 1
            threat_msg = f"DDoS attack detected from {src_ip} to {dst_ip} - {packet_count} packets/sec"
            self.log_threat(threat_msg, "Critical")
    
    def detect_port_scan(self, packet, src_ip, dst_ip):
        current_time = time.time()
        
        # Count unique destination ports from the same source in last minute
        unique_ports = set()
        for p in self.connection_data:
            if p['src_ip'] == src_ip and current_time - p['time'] < 60.0 and 'dport' in p:
                unique_ports.add(p['dport'])
        
        if len(unique_ports) > 50:  # Threshold for port scan
            self.threat_data['PortScan'] += 1
            threat_msg = f"Port scan detected from {src_ip} to {dst_ip} - {len(unique_ports)} ports scanned"
            self.log_threat(threat_msg, "Medium")
    
    def log_packet(self, packet):
        packet_info = {
            'time': time.time(),
            'src_ip': packet[IP].src if IP in packet else '',
            'dst_ip': packet[IP].dst if IP in packet else ''
        }
        
        if TCP in packet:
            packet_info['sport'] = packet[TCP].sport
            packet_info['dport'] = packet[TCP].dport
            packet_info['flags'] = packet[TCP].flags
        elif UDP in packet:
            packet_info['sport'] = packet[UDP].sport
            packet_info['dport'] = packet[UDP].dport
        
        self.connection_data.append(packet_info)
        
        # Keep only last 10,000 packets to manage memory
        if len(self.connection_data) > 10000:
            self.connection_data.pop(0)
    
    def log_message(self, message):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_msg = f"[{timestamp}] {message}\n"
        
        self.monitor_output.config(state=tk.NORMAL)
        self.monitor_output.insert(tk.END, formatted_msg)
        self.monitor_output.see(tk.END)
        self.monitor_output.config(state=tk.DISABLED)
    
    def log_threat(self, message, severity):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_msg = f"[{timestamp}] [{severity}] {message}\n"
        
        # Update threat text
        self.threat_text.config(state=tk.NORMAL)
        self.threat_text.insert(tk.END, formatted_msg)
        self.threat_text.see(tk.END)
        self.threat_text.config(state=tk.DISABLED)
        
        # Update monitoring output
        self.monitor_output.config(state=tk.NORMAL)
        self.monitor_output.insert(tk.END, formatted_msg)
        self.monitor_output.see(tk.END)
        self.monitor_output.config(state=tk.DISABLED)
        
        # Show alert
        if severity in ["High", "Critical"]:
            self.show_alert(f"{severity} Threat Detected", message)
    
    def log_error(self, error):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_msg = f"[{timestamp}] [ERROR] {error}\n"
        
        self.monitor_output.config(state=tk.NORMAL)
        self.monitor_output.insert(tk.END, formatted_msg)
        self.monitor_output.see(tk.END)
        self.monitor_output.config(state=tk.DISABLED)
    
    def show_alert(self, title, message):
        # Show alert in a separate thread to avoid blocking
        threading.Thread(target=lambda: messagebox.showwarning(title, message), daemon=True).start()
    
    def update_data(self):
        while True:
            try:
                # Update stats
                self.packets_label.config(text=f"Packets Analyzed: {sum(self.packet_counts.values())}")
                
                # Get active connections
                connections = psutil.net_connections()
                self.connections_label.config(text=f"Active Connections: {len(connections)}")
                
                # Update threat count
                self.threats_label.config(text=f"Threats Detected: {sum(self.threat_data.values())}")
                
                # Update every second
                time.sleep(1)
            except Exception as e:
                self.log_error(f"Update thread error: {str(e)}")
                time.sleep(5)
    
    def update_visualizations(self):
        try:
            # Update pie chart with threat data
            fig1, ax1 = plt.subplots(figsize=(5, 4), facecolor='black')
            ax1.set_title('Threat Distribution', color='green')
            
            if sum(self.threat_data.values()) > 0:
                labels = list(self.threat_data.keys())
                sizes = list(self.threat_data.values())
                colors = ['#ff0000', '#ff6666', '#ff9999', '#ffcccc']
                
                ax1.pie(sizes, labels=labels, colors=colors[:len(labels)], autopct='%1.1f%%',
                       textprops={'color': 'green'}, shadow=True, startangle=90)
                ax1.axis('equal')
            else:
                ax1.pie([1], labels=['No Threats'], colors=['gray'], textprops={'color': 'green'})
            
            # Clear old pie chart and draw new one
            for widget in self.pie_frame.winfo_children():
                widget.destroy()
            
            self.pie_canvas = FigureCanvasTkAgg(fig1, self.pie_frame)
            self.pie_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
            # Update bar chart with packet data
            fig2, ax2 = plt.subplots(figsize=(5, 4), facecolor='black')
            ax2.set_title('Packet Types', color='green')
            
            if sum(self.packet_counts.values()) > 0:
                labels = list(self.packet_counts.keys())
                values = list(self.packet_counts.values())
                colors = ['#00ff00', '#00cc00', '#009900', '#006600']
                
                ax2.bar(labels, values, color=colors[:len(labels)])
                ax2.tick_params(axis='x', colors='green')
                ax2.tick_params(axis='y', colors='green')
                ax2.set_facecolor('black')
            else:
                ax2.bar(['No Data'], [1], color='gray')
                ax2.tick_params(axis='x', colors='green')
                ax2.tick_params(axis='y', colors='green')
                ax2.set_facecolor('black')
            
            # Clear old bar chart and draw new one
            for widget in self.bar_frame.winfo_children():
                widget.destroy()
            
            self.bar_canvas = FigureCanvasTkAgg(fig2, self.bar_frame)
            self.bar_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
        except Exception as e:
            self.log_error(f"Visualization error: {str(e)}")
    
    def execute_command(self, event=None):
        command = self.cmd_entry.get().strip()
        self.cmd_entry.delete(0, tk.END)
        
        if not command:
            return
            
        self.update_terminal(f">> {command}")
        
        # Process commands
        cmd_parts = command.split()
        base_cmd = cmd_parts[0].lower()
        
        try:
            if base_cmd == "ping" and len(cmd_parts) > 1:
                self.command_ping(cmd_parts[1])
            elif base_cmd == "start" and len(cmd_parts) > 3 and cmd_parts[1].lower() == "monitoring":
                ip = cmd_parts[3]
                if self.validate_ip(ip):
                    self.target_ip.delete(0, tk.END)
                    self.target_ip.insert(0, ip)
                    self.start_specific_monitoring()
                else:
                    self.update_terminal("Invalid IP address format")
            elif base_cmd == "stop" and cmd_parts[1].lower() == "monitoring":
                self.stop_monitoring()
            elif base_cmd == "exit":
                self.root.quit()
            elif base_cmd == "help":
                self.show_help()
            elif base_cmd == "ifconfig" or (len(cmd_parts) > 1 and cmd_parts[1] == "/all"):
                self.command_ifconfig()
            elif base_cmd == "netstat":
                self.command_netstat()
            elif base_cmd == "dnslookup" and len(cmd_parts) > 1:
                self.command_dnslookup(cmd_parts[1])
            elif base_cmd == "traceroute" and len(cmd_parts) > 1:
                self.command_traceroute(cmd_parts[1])
            elif base_cmd == "netsh" and len(cmd_parts) > 4 and cmd_parts[3].lower() == "profile":
                self.command_netsh_wlan()
            else:
                self.update_terminal(f"Unknown command: {command}\nType 'help' for available commands")
        except Exception as e:
            self.update_terminal(f"Error executing command: {str(e)}")
    
    def command_ping(self, ip):
        if not self.validate_ip(ip):
            self.update_terminal("Invalid IP address format")
            return
            
        self.update_terminal(f"Pinging {ip}...")
        
        try:
            # Platform-specific ping command
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            count = '4'
            command = ['ping', param, count, ip]
            
            # Run ping command
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            if process.returncode == 0:
                self.update_terminal(stdout.decode('utf-8', errors='replace'))
            else:
                self.update_terminal(f"Ping failed: {stderr.decode('utf-8', errors='replace')}")
        except Exception as e:
            self.update_terminal(f"Ping error: {str(e)}")
    
    def command_ifconfig(self):
        try:
            if platform.system().lower() == 'windows':
                command = ['ipconfig', '/all']
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                
                if process.returncode == 0:
                    self.update_terminal(stdout.decode('utf-8', errors='replace'))
                else:
                    self.update_terminal(f"ipconfig failed: {stderr.decode('utf-8', errors='replace')}")
            else:
                command = ['ifconfig', '-a']
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = process.communicate()
                
                if process.returncode == 0:
                    self.update_terminal(stdout.decode('utf-8', errors='replace'))
                else:
                    self.update_terminal(f"ifconfig failed: {stderr.decode('utf-8', errors='replace')}")
        except Exception as e:
            self.update_terminal(f"Network config error: {str(e)}")
    
    def command_netstat(self):
        try:
            if platform.system().lower() == 'windows':
                command = ['netstat', '-ano']
            else:
                command = ['netstat', '-tulnp']
                
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            if process.returncode == 0:
                self.update_terminal(stdout.decode('utf-8', errors='replace'))
            else:
                self.update_terminal(f"netstat failed: {stderr.decode('utf-8', errors='replace')}")
        except Exception as e:
            self.update_terminal(f"netstat error: {str(e)}")
    
    def command_dnslookup(self, domain):
        try:
            self.update_terminal(f"DNS Lookup for {domain}")
            
            # Perform DNS lookup
            result = dns.resolver.resolve(domain, 'A')
            
            for ipval in result:
                self.update_terminal(f"IP: {ipval.to_text()}")
        except dns.resolver.NXDOMAIN:
            self.update_terminal(f"Domain {domain} does not exist")
        except dns.resolver.Timeout:
            self.update_terminal("DNS query timed out")
        except dns.resolver.NoAnswer:
            self.update_terminal("No answer for DNS query")
        except Exception as e:
            self.update_terminal(f"DNS lookup error: {str(e)}")
    
    def command_traceroute(self, ip):
        if not self.validate_ip(ip) and not self.validate_domain(ip):
            self.update_terminal("Invalid IP address or domain format")
            return
            
        self.update_terminal(f"Traceroute to {ip}... (this may take a while)")
        
        try:
            if platform.system().lower() == 'windows':
                command = ['tracert', ip]
            else:
                command = ['traceroute', ip]
                
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            if process.returncode == 0:
                self.update_terminal(stdout.decode('utf-8', errors='replace'))
            else:
                self.update_terminal(f"Traceroute failed: {stderr.decode('utf-8', errors='replace')}")
        except Exception as e:
            self.update_terminal(f"Traceroute error: {str(e)}")
    
    def command_netsh_wlan(self):
        if platform.system().lower() != 'windows':
            self.update_terminal("This command is only available on Windows")
            return
            
        try:
            command = ['netsh', 'wlan', 'show', 'network', 'mode=bssid']
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            
            if process.returncode == 0:
                self.update_terminal(stdout.decode('utf-8', errors='replace'))
            else:
                self.update_terminal(f"Command failed: {stderr.decode('utf-8', errors='replace')}")
        except Exception as e:
            self.update_terminal(f"Error: {str(e)}")
    
    def show_help(self):
        help_text = """
Available Commands:
  ping <ip>                - Ping an IP address
  start monitoring <ip>    - Start monitoring threats for specific IP
  stop monitoring          - Stop all monitoring
  exit                     - Exit the application
  help                     - Show this help message
  ifconfig /all            - Show network interface configuration
  netstat                  - Show network statistics and connections
  dnslookup <domain>       - Perform DNS lookup for a domain
  traceroute <ip>          - Perform traceroute to an IP
  netsh wlan show profile  - Show wireless network profiles (Windows only)
"""
        self.update_terminal(help_text)
    
    def update_terminal(self, message):
        self.terminal_output.config(state=tk.NORMAL)
        self.terminal_output.insert(tk.END, message + "\n")
        self.terminal_output.see(tk.END)
        self.terminal_output.config(state=tk.DISABLED)
    
    def validate_ip(self, ip):
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    def validate_domain(self, domain):
        try:
            socket.gethostbyname(domain)
            return True
        except socket.error:
            return False
    
    def show_dashboard(self):
        self.hide_all_frames()
        self.dashboard_frame.pack(fill=tk.BOTH, expand=True)
    
    def show_terminal(self):
        self.hide_all_frames()
        self.terminal_frame.pack(fill=tk.BOTH, expand=True)
        self.cmd_entry.focus_set()
    
    def show_monitoring(self):
        self.hide_all_frames()
        self.monitoring_frame.pack(fill=tk.BOTH, expand=True)
    
    def show_visualizations(self):
        self.hide_all_frames()
        self.visualization_frame.pack(fill=tk.BOTH, expand=True)
        self.update_visualizations()
    
    def hide_all_frames(self):
        for frame in [self.dashboard_frame, self.terminal_frame, 
                     self.monitoring_frame, self.visualization_frame]:
            frame.pack_forget()
    
    def open_network_scanner(self):
        self.update_terminal("Opening network scanner... (feature not fully implemented)")
        # In a full implementation, this would open a network scanning tool
    
    def open_packet_analyzer(self):
        self.update_terminal("Opening packet analyzer... (feature not fully implemented)")
        # In a full implementation, this would open a detailed packet analyzer
    
    def open_vulnerability_scanner(self):
        self.update_terminal("Opening vulnerability scanner... (feature not fully implemented)")
        # In a full implementation, this would open a vulnerability scanning tool
    
    def show_documentation(self):
        doc_window = tk.Toplevel(self.root)
        doc_window.title("Documentation")
        doc_window.geometry("800x600")
        doc_window.configure(bg=self.bg_color)
        
        doc_text = scrolledtext.ScrolledText(doc_window, bg='black', fg='green', 
                                           insertbackground='green', font=('Courier', 10))
        doc_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        documentation = """
Advanced Cyber Security Monitoring Tool Documentation

1. Dashboard:
- Displays system information and network statistics
- Shows threat summary and quick actions

2. Terminal:
- Execute network and security commands
- Type 'help' for available commands

3. Monitoring:
- Configure and monitor for DDoS, DoS, and port scan attacks
- View real-time monitoring output

4. Visualizations:
- View threat distribution and packet types in charts

Commands:
- ping <ip>: Test connectivity to an IP
- start monitoring <ip>: Start monitoring specific threats
- stop monitoring: Stop all monitoring
- ifconfig /all: Show network configuration
- netstat: Show network connections
- dnslookup <domain>: Resolve domain to IP
- traceroute <ip>: Trace route to IP
- netsh wlan show profile: Show WiFi profiles (Windows)
"""
        doc_text.insert(tk.END, documentation)
        doc_text.config(state=tk.DISABLED)
    
    def show_about(self):
        about_window = tk.Toplevel(self.root)
        about_window.title("About")
        about_window.geometry("400x300")
        about_window.configure(bg=self.bg_color)
        
        about_text = tk.Text(about_window, bg='black', fg='green', 
                           insertbackground='green', font=('Courier', 10), wrap=tk.WORD)
        about_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        about_info = """
Accurate Cyber Defense Advanced Cyber Drill Tool
Version 160
Ian Carter Kulani
E-mail:iancarterkulani@gmail.com
Phone:+265(0)988061969


This tool provides real-time monitoring of network threats including:
- DDoS attacks
- DoS attacks
- Port scanning activities

Features:
- Real-time packet analysis
- Threat detection and alerting
- Network diagnostic tools
- Data visualization

Developed for cyber security professionals and network administrators.
"""
        about_text.insert(tk.END, about_info)
        about_text.config(state=tk.DISABLED)
        
        close_btn = tk.Button(about_window, text="Close", command=about_window.destroy, 
                             bg=self.bg_color, fg=self.fg_color, activebackground=self.bg_color, 
                             activeforeground=self.highlight_color)
        close_btn.pack(pady=10)
    
    def save_log(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", 
                                                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    # Save threat log
                    f.write("=== THREAT LOG ===\n")
                    f.write(self.threat_text.get("1.0", tk.END))
                    
                    # Save monitoring log
                    f.write("\n=== MONITORING LOG ===\n")
                    f.write(self.monitor_output.get("1.0", tk.END))
                    
                    # Save terminal output
                    f.write("\n=== TERMINAL LOG ===\n")
                    f.write(self.terminal_output.get("1.0", tk.END))
                
                self.log_message(f"Log saved to {file_path}")
            except Exception as e:
                self.log_error(f"Error saving log: {str(e)}")
                messagebox.showerror("Error", f"Failed to save log: {str(e)}")
    
    def export_data(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", 
                                                filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")])
        if file_path:
            try:
                # Create DataFrame from threat data
                threat_df = pd.DataFrame(list(self.threat_data.items()), columns=['Threat Type', 'Count'])
                
                # Create DataFrame from packet data
                packet_df = pd.DataFrame(list(self.packet_counts.items()), columns=['Packet Type', 'Count'])
                
                # Create DataFrame from connection data
                connection_df = pd.DataFrame(self.connection_data)
                
                # Write to Excel with multiple sheets
                with pd.ExcelWriter(file_path) as writer:
                    threat_df.to_excel(writer, sheet_name='Threats', index=False)
                    packet_df.to_excel(writer, sheet_name='Packets', index=False)
                    connection_df.to_excel(writer, sheet_name='Connections', index=False)
                
                self.log_message(f"Data exported to {file_path}")
            except Exception as e:
                self.log_error(f"Error exporting data: {str(e)}")
                messagebox.showerror("Error", f"Failed to export data: {str(e)}")

def main():
    root = tk.Tk()
    app = CyberSecurityTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()