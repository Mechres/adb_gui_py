import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import subprocess
import threading
import re
from typing import List, Tuple, Dict


class ADBGuiTool:
    def show_network_advanced(self):
        """Show advanced network tools"""
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
        # Create network tools window
        network_window = tk.Toplevel(self.root)
        network_window.title("Advanced Network Tools")
        network_window.geometry("800x600")
        network_window.transient(self.root)

        # Create notebook for different tools
        notebook = ttk.Notebook(network_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Port Scanner
        port_frame = ttk.Frame(notebook, padding=10)
        notebook.add(port_frame, text="Port Scanner")

        # Target frame
        target_frame = ttk.LabelFrame(port_frame, text="Target", padding=10)
        target_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(target_frame, text="Host:").pack(side=tk.LEFT, padx=5)
        host_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(target_frame, textvariable=host_var, width=20).pack(side=tk.LEFT, padx=5)

        ttk.Label(target_frame, text="Port Range:").pack(side=tk.LEFT, padx=5)
        port_start_var = tk.StringVar(value="1")
        port_end_var = tk.StringVar(value="1024")
        ttk.Entry(target_frame, textvariable=port_start_var, width=6).pack(side=tk.LEFT, padx=2)
        ttk.Label(target_frame, text="-").pack(side=tk.LEFT)
        ttk.Entry(target_frame, textvariable=port_end_var, width=6).pack(side=tk.LEFT, padx=2)

        # Results
        port_results = scrolledtext.ScrolledText(port_frame, height=20)
        port_results.pack(fill=tk.BOTH, expand=True, pady=10)

        def scan_ports():
            host = host_var.get().strip()
            try:
                start_port = int(port_start_var.get())
                end_port = int(port_end_var.get())
            except ValueError:
                messagebox.showerror("Error", "Invalid port numbers")
                return

            device = self.connected_device.get()
            port_results.delete(1.0, tk.END)
            port_results.insert(tk.END, f"Scanning {host} ports {start_port}-{end_port}...\n\n")

            def check_port(port):
                try:
                    result = subprocess.run(
                        ["adb", "-s", device, "shell", f"nc -zv -w1 {host} {port} 2>&1"],
                        capture_output=True, text=True
                    )
                    if "open" in result.stderr.lower():
                        port_results.insert(tk.END, f"Port {port}: OPEN\n")
                except Exception:
                    pass

            threading.Thread(target=lambda: [check_port(p) for p in range(start_port, end_port + 1)],
                           daemon=True).start()

        ttk.Button(port_frame, text="Start Scan", command=scan_ports).pack(pady=10)

        # Network Traffic Monitor
        traffic_frame = ttk.Frame(notebook, padding=10)
        notebook.add(traffic_frame, text="Traffic Monitor")

        # Interface selection
        ttk.Label(traffic_frame, text="Interface:").pack(anchor=tk.W, pady=(0, 5))
        interface_var = tk.StringVar(value="all")
        interface_combo = ttk.Combobox(traffic_frame, textvariable=interface_var, 
                                     values=["all", "wlan0", "rmnet0"])
        interface_combo.pack(anchor=tk.W, pady=(0, 10))

        # Traffic display
        traffic_text = scrolledtext.ScrolledText(traffic_frame, height=25)
        traffic_text.pack(fill=tk.BOTH, expand=True)

        traffic_monitor = {"running": False}

        def monitor_traffic():
            if traffic_monitor["running"]:
                traffic_monitor["running"] = False
                monitor_btn.config(text="Start Monitor")
                return

            device = self.connected_device.get()
            interface = interface_var.get()
            traffic_monitor["running"] = True
            monitor_btn.config(text="Stop Monitor")

            def monitor_thread():
                while traffic_monitor["running"]:
                    try:
                        cmd = ["adb", "-s", device, "shell", "tcpdump"]
                        if interface != "all":
                            cmd.extend(["-i", interface])
                        cmd.extend(["-n", "-v"])
                        
                        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                                 stderr=subprocess.PIPE, text=True)
                        
                        while traffic_monitor["running"]:
                            line = process.stdout.readline()
                            if line:
                                traffic_text.insert(tk.END, line)
                                traffic_text.see(tk.END)
                            
                        process.terminate()
                    except Exception as e:
                        traffic_text.insert(tk.END, f"Error: {str(e)}\n")
                        break

            threading.Thread(target=monitor_thread, daemon=True).start()

        monitor_btn = ttk.Button(traffic_frame, text="Start Monitor", command=monitor_traffic)
        monitor_btn.pack(pady=10)

        # TCP/IP Connections
        connections_frame = ttk.Frame(notebook, padding=10)
        notebook.add(connections_frame, text="TCP/IP Connections")

        # Connection list
        columns = ("Protocol", "Local Address", "Remote Address", "State", "PID/Program")
        conn_tree = ttk.Treeview(connections_frame, columns=columns, show="headings")

        for col in columns:
            conn_tree.heading(col, text=col)
            conn_tree.column(col, width=150)

        conn_tree.pack(fill=tk.BOTH, expand=True)

        def refresh_connections():
            device = self.connected_device.get()
            try:
                result = subprocess.run(
                    ["adb", "-s", device, "shell", "netstat -ntlp"],
                    capture_output=True, text=True
                )

                conn_tree.delete(*conn_tree.get_children())
                for line in result.stdout.split('\n')[2:]:  # Skip header lines
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 6:
                            proto = parts[0]
                            local = parts[3]
                            remote = parts[4]
                            state = parts[5]
                            pid_prog = parts[6] if len(parts) > 6 else "-"
                            conn_tree.insert("", tk.END, values=(proto, local, remote, state, pid_prog))

            except Exception as e:
                messagebox.showerror("Error", f"Failed to get connections: {str(e)}")

        ttk.Button(connections_frame, text="Refresh", 
                   command=lambda: threading.Thread(target=refresh_connections, daemon=True).start()
                   ).pack(pady=10)

        # VPN Configuration
        vpn_frame = ttk.Frame(notebook, padding=10)
        notebook.add(vpn_frame, text="VPN Config")

        # VPN status
        ttk.Label(vpn_frame, text="VPN Status:").pack(anchor=tk.W, pady=(0, 5))
        vpn_status_var = tk.StringVar(value="Not Connected")
        ttk.Label(vpn_frame, textvariable=vpn_status_var).pack(anchor=tk.W, pady=(0, 10))

        def check_vpn_status():
            device = self.connected_device.get()
            try:
                result = subprocess.run(
                    ["adb", "-s", device, "shell", "settings get global vpn_state"],
                    capture_output=True, text=True
                )
                state = result.stdout.strip()
                vpn_status_var.set("Connected" if state == "1" else "Not Connected")
            except Exception as e:
                vpn_status_var.set(f"Error: {str(e)}")

        ttk.Button(vpn_frame, text="Check VPN Status", command=check_vpn_status).pack(pady=5)

        # Proxy Settings
        proxy_frame = ttk.Frame(notebook, padding=10)
        notebook.add(proxy_frame, text="Proxy Settings")

        # Current settings
        settings_frame = ttk.LabelFrame(proxy_frame, text="Current Settings", padding=10)
        settings_frame.pack(fill=tk.X, pady=(0, 10))

        proxy_host_var = tk.StringVar()
        proxy_port_var = tk.StringVar()

        ttk.Label(settings_frame, text="Proxy Host:").grid(row=0, column=0, padx=5, pady=5)
        ttk.Entry(settings_frame, textvariable=proxy_host_var).grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(settings_frame, text="Proxy Port:").grid(row=1, column=0, padx=5, pady=5)
        ttk.Entry(settings_frame, textvariable=proxy_port_var).grid(row=1, column=1, padx=5, pady=5)

        def get_proxy_settings():
            device = self.connected_device.get()
            try:
                result = subprocess.run(
                    ["adb", "-s", device, "shell", "settings get global http_proxy"],
                    capture_output=True, text=True
                )
                proxy = result.stdout.strip()
                if ":" in proxy:
                    host, port = proxy.split(":")
                    proxy_host_var.set(host)
                    proxy_port_var.set(port)
                else:
                    proxy_host_var.set("")
                    proxy_port_var.set("")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to get proxy settings: {str(e)}")

        def set_proxy_settings():
            device = self.connected_device.get()
            host = proxy_host_var.get().strip()
            port = proxy_port_var.get().strip()

            if host and port:
                try:
                    subprocess.run(
                        ["adb", "-s", device, "shell", f"settings put global http_proxy {host}:{port}"],
                        check=True
                    )
                    messagebox.showinfo("Success", "Proxy settings updated")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to set proxy: {str(e)}")
            else:
                try:
                    subprocess.run(
                        ["adb", "-s", device, "shell", "settings delete global http_proxy"],
                        check=True
                    )
                    messagebox.showinfo("Success", "Proxy settings cleared")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to clear proxy: {str(e)}")

        buttons_frame = ttk.Frame(settings_frame)
        buttons_frame.grid(row=2, column=0, columnspan=2, pady=10)

        ttk.Button(buttons_frame, text="Get Current", command=get_proxy_settings).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Apply Settings", command=set_proxy_settings).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Clear Proxy", 
                   command=lambda: proxy_host_var.set("") or proxy_port_var.set("") or set_proxy_settings()
                   ).pack(side=tk.LEFT, padx=5)
