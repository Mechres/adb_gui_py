import os
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog
import threading
import re
import time
import adv_network
import testing_tools
import security_tools
import app_manager  # Add this import
import sys_analysis

class ADBGuiTool:
    def __init__(self, root):
        self.root = root
        self.root.title("ADB GUI Tool")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Check if ADB is installed
        self.adb_available = self.check_adb_installed()
        if not self.adb_available:
            messagebox.showerror("Error", "ADB is not installed or not in PATH. Please install ADB and try again.")
        
        # Variables
        self.connected_device = tk.StringVar()
        self.device_list = []
        self.current_path = "/"
        self.status_var = tk.StringVar()  # <-- Move this up before AdvancedAppManager
        
        # Create TestingTools instance
        self.testing_tools = testing_tools.TestingTools(self.root, self.adb_available, self.connected_device)
        
        # Advanced App Manager integration
        self.advanced_app_manager = app_manager.AdvancedAppManager(
            self.root, self.adb_available, self.connected_device, self.status_var
        )
        
        # Create UI
        self.create_menu()
        self.create_ui()
        
        # Initial device refresh
        if self.adb_available:
            self.refresh_devices()
    
    def check_adb_installed(self):
        try:
            subprocess.run(["adb", "version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def create_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Device menu
        device_menu = tk.Menu(menubar, tearoff=0)
        device_menu.add_command(label="Refresh Devices", command=self.refresh_devices)
        device_menu.add_command(label="Device Info", command=self.show_device_info)
        device_menu.add_command(label="Battery Monitor", command=self.show_battery_monitor)
        device_menu.add_separator()
        device_menu.add_command(label="Reboot Device", command=lambda: self.confirm_action("reboot", "Reboot device?"))
        device_menu.add_command(label="Reboot to Recovery", command=lambda: self.confirm_action("reboot recovery", "Reboot to recovery?"))
        device_menu.add_command(label="Reboot to Bootloader", command=lambda: self.confirm_action("reboot bootloader", "Reboot to bootloader?"))
        menubar.add_cascade(label="Device", menu=device_menu)

        # Developer menu (new)
        developer_menu = tk.Menu(menubar, tearoff=0)
        developer_menu.add_command(label="Layout Boundary Viewer", command=self.show_layout_bounds)
        developer_menu.add_command(label="UI Automator Viewer", command=self.show_ui_automator)
        developer_menu.add_command(label="System Properties", command=self.show_system_properties)
        developer_menu.add_separator()
        developer_menu.add_command(label="Database Explorer", command=self.show_database_explorer)
        developer_menu.add_command(label="Shared Preferences", command=self.show_shared_prefs)
        developer_menu.add_command(label="Activity Stack", command=self.show_activity_stack)
        menubar.add_cascade(label="Developer", menu=developer_menu)
        
        # Storage menu
        storage_menu = tk.Menu(menubar, tearoff=0)
        storage_menu.add_command(label="Storage Analysis", command=self.show_storage_analysis)
        storage_menu.add_command(label="Cache Cleaner", command=self.show_cache_cleaner)
        storage_menu.add_command(label="Large File Finder", command=self.show_large_file_finder)
        menubar.add_cascade(label="Storage", menu=storage_menu)
        
        # Apps menu
        apps_menu = tk.Menu(menubar, tearoff=0)
        apps_menu.add_command(label="Install APK", command=self.install_apk)
        apps_menu.add_command(label="List Installed Apps", command=self.list_packages)
        apps_menu.add_command(label="Uninstall App", command=self.uninstall_app)
        apps_menu.add_separator()
        apps_menu.add_command(label="Backup App", command=self.backup_app)
        apps_menu.add_command(label="Restore App", command=self.restore_app)
        menubar.add_cascade(label="Apps", menu=apps_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Take Screenshot", command=self.take_screenshot)
        tools_menu.add_command(label="Screen Recording", command=self.screen_recording)
        tools_menu.add_command(label="Clear App Data", command=self.clear_app_data)
        tools_menu.add_command(label="ADB Wireless Connect", command=self.wireless_connect)
        tools_menu.add_separator()
        tools_menu.add_command(label="View Logcat", command=self.show_logcat)
        tools_menu.add_command(label="Network Tools", command=self.show_network_tools)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Network menu
        network_menu = tk.Menu(menubar, tearoff=0)
        network_menu.add_command(label="Network Diagnostics", command=self.show_network_tools)
        network_menu.add_command(label="Advanced Network Tools", command=lambda: adv_network.ADBGuiTool.show_network_advanced(self))
        menubar.add_cascade(label="Network", menu=network_menu)
        
        # Process menu
        process_menu = tk.Menu(menubar, tearoff=0)
        process_menu.add_command(label="Process Manager", command=self.show_process_manager)
        menubar.add_cascade(label="Process", menu=process_menu)
        
        # Testing menu
        testing_menu = tk.Menu(menubar, tearoff=0)
        testing_menu.add_command(label="Monkey Test", command=self.testing_tools.show_monkey_test)
        testing_menu.add_command(label="UI/Application Exerciser", command=self.testing_tools.show_ui_exerciser)
        testing_menu.add_command(label="Touch Event Recorder/Player", command=self.testing_tools.show_touch_recorder)
        testing_menu.add_command(label="Network Condition Simulator", command=self.testing_tools.show_network_simulator)
        menubar.add_cascade(label="Testing Menu", menu=testing_menu)
        
        # Security menu
        security_menu = tk.Menu(menubar, tearoff=0)
        security_menu.add_command(label="Package Signature Verification", command=lambda: security_tools.SecurityTools(self.root, self.adb_available, self.connected_device).show_signature_verification())
        security_menu.add_command(label="Permission Analyzer", command=lambda: security_tools.SecurityTools(self.root, self.adb_available, self.connected_device).show_permission_analyzer())
        security_menu.add_command(label="Security Settings Viewer", command=lambda: security_tools.SecurityTools(self.root, self.adb_available, self.connected_device).show_security_settings())
        security_menu.add_command(label="Certificate Manager", command=lambda: security_tools.SecurityTools(self.root, self.adb_available, self.connected_device).show_certificate_manager())
        menubar.add_cascade(label="Security", menu=security_menu)
        
        # Advanced App Manager menu
        adv_app_menu = tk.Menu(menubar, tearoff=0)
        adv_app_menu.add_command(label="Batch App Operations", command=self.advanced_app_manager.batch_app_operations)
        adv_app_menu.add_command(label="APK Version Comparison", command=self.advanced_app_manager.apk_version_comparison)
        adv_app_menu.add_command(label="App Permissions Manager", command=self.advanced_app_manager.app_permissions_manager)
        adv_app_menu.add_command(label="Bulk App Manager", command=self.advanced_app_manager.bulk_app_manager)
        menubar.add_cascade(label="Advanced App Manager", menu=adv_app_menu)

        # System Analysis menu
        sys_menu = tk.Menu(menubar, tearoff=0)
        sys_menu.add_command(label="CPU Profiler", command=lambda: sys_analysis.show_cpu_profiler(self.root, self.adb_available, self.connected_device))
        sys_menu.add_command(label="Memory Analyzer", command=lambda: sys_analysis.show_memory_analyzer(self.root, self.adb_available, self.connected_device))
        sys_menu.add_command(label="Battery Usage by App", command=lambda: sys_analysis.show_battery_usage(self.root, self.adb_available, self.connected_device))
        sys_menu.add_command(label="Wakelocks Viewer", command=lambda: sys_analysis.show_wakelocks_viewer(self.root, self.adb_available, self.connected_device))
        sys_menu.add_command(label="System Logs Aggregator", command=lambda: sys_analysis.show_system_logs_aggregator(self.root, self.adb_available, self.connected_device))
        menubar.add_cascade(label="System Analysis", menu=sys_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
    
    def create_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Device selection
        device_frame = ttk.LabelFrame(main_frame, text="Device Selection", padding="10")
        device_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(device_frame, text="Select Device:").pack(side=tk.LEFT, padx=5)
        self.device_dropdown = ttk.Combobox(device_frame, textvariable=self.connected_device, state="readonly")
        self.device_dropdown.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        refresh_button = ttk.Button(device_frame, text="Refresh", command=self.refresh_devices)
        refresh_button.pack(side=tk.LEFT, padx=5)
        
        # Notebook for different sections
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Shell tab
        shell_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(shell_frame, text="Shell Commands")
        
        # Command entry
        cmd_frame = ttk.Frame(shell_frame)
        cmd_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(cmd_frame, text="Command:").pack(side=tk.LEFT, padx=5)
        self.cmd_entry = ttk.Entry(cmd_frame)
        self.cmd_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.cmd_entry.bind("<Return>", lambda event: self.execute_command())
        
        cmd_button = ttk.Button(cmd_frame, text="Run", command=self.execute_command)
        cmd_button.pack(side=tk.LEFT, padx=5)
        
        # Output area
        ttk.Label(shell_frame, text="Output:").pack(anchor=tk.W, pady=(10, 5))
        
        self.output_text = scrolledtext.ScrolledText(shell_frame, height=20, wrap=tk.WORD)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.config(state=tk.DISABLED)
        
        # File Manager tab
        file_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(file_frame, text="File Manager")
        
        # Path navigation
        path_frame = ttk.Frame(file_frame)
        path_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(path_frame, text="Path:").pack(side=tk.LEFT, padx=5)
        self.path_entry = ttk.Entry(path_frame)
        self.path_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.path_entry.insert(0, "/")
        self.path_entry.bind("<Return>", lambda event: self.list_files())
        
        browse_button = ttk.Button(path_frame, text="Go", command=self.list_files)
        browse_button.pack(side=tk.LEFT, padx=5)
        
        # File buttons
        file_buttons_frame = ttk.Frame(file_frame)
        file_buttons_frame.pack(fill=tk.X, pady=5)
        
        upload_button = ttk.Button(file_buttons_frame, text="Upload", command=self.upload_file)
        upload_button.pack(side=tk.LEFT, padx=5)
        
        download_button = ttk.Button(file_buttons_frame, text="Download", command=self.download_file)
        download_button.pack(side=tk.LEFT, padx=5)
        
        delete_button = ttk.Button(file_buttons_frame, text="Delete", command=self.delete_file)
        delete_button.pack(side=tk.LEFT, padx=5)
        
        # File list
        ttk.Label(file_frame, text="Files:").pack(anchor=tk.W, pady=(10, 5))
        
        self.file_listbox = tk.Listbox(file_frame, height=20)
        self.file_listbox.pack(fill=tk.BOTH, expand=True)
        self.file_listbox.bind("<Double-Button-1>", lambda event: self.handle_file_double_click())
        
        # Status bar
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill=tk.X, pady=5)
        
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_label = ttk.Label(status_frame, textvariable=self.status_var)
        status_label.pack(side=tk.LEFT, padx=5)
    
    def refresh_devices(self):
        if not self.adb_available:
            return
            
        self.status_var.set("Refreshing devices...")
        self.root.update_idletasks()
        
        try:
            result = subprocess.run(["adb", "devices"], capture_output=True, text=True)
            lines = result.stdout.strip().split('\n')[1:]  # Skip the first line which is the header
            
            self.device_list = []
            for line in lines:
                if line.strip():
                    parts = line.strip().split('\t')
                    if len(parts) >= 2:
                        self.device_list.append(parts[0])
            
            self.device_dropdown['values'] = self.device_list
            
            if self.device_list:
                self.device_dropdown.current(0)
                self.connected_device.set(self.device_list[0])
                self.status_var.set(f"Found {len(self.device_list)} device(s)")
            else:
                self.status_var.set("No devices found")
        except Exception as e:
            self.status_var.set(f"Error: {str(e)}")
            messagebox.showerror("Error", f"Failed to refresh devices: {str(e)}")
    
    def execute_command(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        command = self.cmd_entry.get().strip()
        if not command:
            return
            
        self.status_var.set(f"Executing: {command}")
        self.root.update_idletasks()
        
        # Clear previous output
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        
        threading.Thread(target=self._execute_command_thread, args=(command,), daemon=True).start()
    
    def _execute_command_thread(self, command):
        try:
            device = self.connected_device.get()
            result = subprocess.run(["adb", "-s", device, "shell", command], 
                                    capture_output=True, text=True)
            
            self.output_text.config(state=tk.NORMAL)
            
            # Add command as header
            self.output_text.insert(tk.END, f"$ {command}\n\n", "cmd")
            
            # Add stdout
            if result.stdout:
                self.output_text.insert(tk.END, result.stdout)
            
            # Add stderr if there's an error
            if result.stderr:
                self.output_text.insert(tk.END, f"\nError:\n{result.stderr}", "error")
                
            self.output_text.config(state=tk.DISABLED)
            self.status_var.set("Command completed")
        except Exception as e:
            self.output_text.config(state=tk.NORMAL)
            self.output_text.insert(tk.END, f"Error executing command: {str(e)}", "error")
            self.output_text.config(state=tk.DISABLED)
            self.status_var.set("Command failed")
    
    def list_files(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        path = self.path_entry.get().strip()
        if not path:
            path = "/"
        
        self.current_path = path
        self.status_var.set(f"Listing files in: {path}")
        self.root.update_idletasks()
        
        threading.Thread(target=self._list_files_thread, args=(path,), daemon=True).start()
    
    def _list_files_thread(self, path):
        try:
            device = self.connected_device.get()
            result = subprocess.run(["adb", "-s", device, "shell", f"ls -la {path}"], 
                                   capture_output=True, text=True)
            
            self.file_listbox.delete(0, tk.END)
            
            # Add parent directory for navigation
            if path != "/":
                self.file_listbox.insert(tk.END, "../")
            
            if result.stdout:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    if line.strip():
                        # Parse the ls -la output to extract file/directory names
                        parts = line.split()
                        if len(parts) >= 8:
                            file_name = " ".join(parts[8:])
                            permissions = parts[0]
                            
                            # Add trailing slash for directories
                            if permissions.startswith("d"):
                                self.file_listbox.insert(tk.END, f"{file_name}/")
                            else:
                                self.file_listbox.insert(tk.END, file_name)
            
            self.status_var.set(f"Listed files in {path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to list files: {str(e)}")
            self.status_var.set("File listing failed")
    
    def handle_file_double_click(self):
        if not self.file_listbox.curselection():
            return
            
        selected_item = self.file_listbox.get(self.file_listbox.curselection()[0])
        
        # Handle navigation
        if selected_item == "../":
            # Go up one directory
            parent_path = os.path.dirname(self.current_path.rstrip('/'))
            if not parent_path:
                parent_path = "/"
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, parent_path)
            self.list_files()
        elif selected_item.endswith("/"):
            # Enter directory
            new_path = os.path.join(self.current_path.rstrip('/'), selected_item.rstrip('/'))
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, new_path)
            self.list_files()
    
    def upload_file(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        file_path = filedialog.askopenfilename(title="Select File to Upload")
        if not file_path:
            return
            
        destination = self.current_path
        if destination == "/":
            destination = "/sdcard/"
            
        threading.Thread(target=self._upload_file_thread, 
                        args=(file_path, destination), daemon=True).start()
    
    def _upload_file_thread(self, file_path, destination):
        try:
            self.status_var.set(f"Uploading {os.path.basename(file_path)}...")
            self.root.update_idletasks()
            
            device = self.connected_device.get()
            destination_path = os.path.join(destination, os.path.basename(file_path))
            
            result = subprocess.run(
                ["adb", "-s", device, "push", file_path, destination_path],
                capture_output=True, text=True
            )
            
            if "error" in result.stderr.lower() or "failed" in result.stderr.lower():
                raise Exception(result.stderr)
                
            self.status_var.set(f"Uploaded {os.path.basename(file_path)}")
            self.list_files()  # Refresh file list
        except Exception as e:
            messagebox.showerror("Error", f"Failed to upload file: {str(e)}")
            self.status_var.set("Upload failed")
    
    def download_file(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        if not self.file_listbox.curselection():
            messagebox.showwarning("Warning", "No file selected")
            return
            
        selected_item = self.file_listbox.get(self.file_listbox.curselection()[0])
        if selected_item.endswith("/") or selected_item == "../":
            messagebox.showwarning("Warning", "Cannot download directories")
            return
            
        save_path = filedialog.asksaveasfilename(
            title="Save File As",
            initialfile=selected_item
        )
        if not save_path:
            return
            
        source_path = os.path.join(self.current_path, selected_item)
        threading.Thread(target=self._download_file_thread, 
                        args=(source_path, save_path), daemon=True).start()
    
    def _download_file_thread(self, source_path, save_path):
        try:
            self.status_var.set(f"Downloading {os.path.basename(source_path)}...")
            self.root.update_idletasks()
            
            device = self.connected_device.get()
            
            # Pull file from device
            result = subprocess.run(
                ["adb", "-s", device, "pull", source_path, save_path],
                capture_output=True, text=True
            )
            
            if "error" in result.stderr.lower() or "failed" in result.stderr.lower():
                raise Exception(result.stderr)
                
            self.status_var.set(f"Downloaded {os.path.basename(source_path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to download file: {str(e)}")
            self.status_var.set("Download failed")
    
    def delete_file(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        if not self.file_listbox.curselection():
            messagebox.showwarning("Warning", "No file selected")
            return
            
        selected_item = self.file_listbox.get(self.file_listbox.curselection()[0])
        if selected_item == "../":
            return
            
        if not messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete {selected_item}?"):
            return
            
        file_path = os.path.join(self.current_path, selected_item.rstrip('/'))
        threading.Thread(target=self._delete_file_thread, args=(file_path, selected_item), daemon=True).start()
    
    def _delete_file_thread(self, file_path, file_name):
        try:
            self.status_var.set(f"Deleting {file_name}...")
            self.root.update_idletasks()
            
            device = self.connected_device.get()
            command = f"rm -rf {file_path}"
            
            result = subprocess.run(
                ["adb", "-s", device, "shell", command],
                capture_output=True, text=True
            )
            
            if result.stderr and ("error" in result.stderr.lower() or "failed" in result.stderr.lower()):
                raise Exception(result.stderr)
                
            self.status_var.set(f"Deleted {file_name}")
            self.list_files()  # Refresh file list
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete: {str(e)}")
            self.status_var.set("Delete failed")
    
    def install_apk(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        apk_path = filedialog.askopenfilename(
            title="Select APK to Install",
            filetypes=[("APK Files", "*.apk"), ("All Files", "*.*")]
        )
        if not apk_path:
            return
            
        threading.Thread(target=self._install_apk_thread, args=(apk_path,), daemon=True).start()
    
    def _install_apk_thread(self, apk_path):
        try:
            apk_name = os.path.basename(apk_path)
            self.status_var.set(f"Installing {apk_name}...")
            self.root.update_idletasks()
            
            device = self.connected_device.get()
            
            result = subprocess.run(
                ["adb", "-s", device, "install", "-r", apk_path],
                capture_output=True, text=True
            )
            
            if "Success" in result.stdout:
                self.status_var.set(f"Installed {apk_name}")
                messagebox.showinfo("Success", f"{apk_name} installed successfully")
            else:
                error_msg = result.stderr if result.stderr else "Unknown error"
                raise Exception(error_msg)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to install APK: {str(e)}")
            self.status_var.set("Installation failed")
    
    def list_packages(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        self.cmd_entry.delete(0, tk.END)
        self.cmd_entry.insert(0, "pm list packages -3")  # List third-party packages
        self.notebook.select(0)  # Switch to shell tab
        self.execute_command()
    
    def uninstall_app(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        package_name = simpledialog.askstring("Uninstall App", "Enter package name:")
        if not package_name:
            return
            
        if not messagebox.askyesno("Confirm Uninstall", f"Are you sure you want to uninstall {package_name}?"):
            return
            
        threading.Thread(target=self._uninstall_app_thread, args=(package_name,), daemon=True).start()
    
    def _uninstall_app_thread(self, package_name):
        try:
            self.status_var.set(f"Uninstalling {package_name}...")
            self.root.update_idletasks()
            
            device = self.connected_device.get()
            
            result = subprocess.run(
                ["adb", "-s", device, "uninstall", package_name],
                capture_output=True, text=True
            )
            
            if "Success" in result.stdout:
                self.status_var.set(f"Uninstalled {package_name}")
                messagebox.showinfo("Success", f"{package_name} uninstalled successfully")
            else:
                error_msg = result.stderr if result.stderr else "Unknown error"
                raise Exception(error_msg)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to uninstall app: {str(e)}")
            self.status_var.set("Uninstallation failed")
    
    def take_screenshot(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        save_path = filedialog.asksaveasfilename(
            title="Save Screenshot As",
            defaultextension=".png",
            filetypes=[("PNG Files", "*.png"), ("All Files", "*.*")]
        )
        if not save_path:
            return
            
        threading.Thread(target=self._take_screenshot_thread, args=(save_path,), daemon=True).start()
    
    def _take_screenshot_thread(self, save_path):
        try:
            self.status_var.set("Taking screenshot...")
            self.root.update_idletasks()
            
            device = self.connected_device.get()
            temp_path = "/sdcard/screenshot.png"
            
            # Take screenshot
            subprocess.run(["adb", "-s", device, "shell", "screencap", "-p", temp_path], check=True)
            
            # Pull screenshot
            subprocess.run(["adb", "-s", device, "pull", temp_path, save_path], check=True)
            
            # Remove temp file
            subprocess.run(["adb", "-s", device, "shell", "rm", temp_path], check=True)
            
            self.status_var.set("Screenshot saved")
            messagebox.showinfo("Success", f"Screenshot saved to {save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to take screenshot: {str(e)}")
            self.status_var.set("Screenshot failed")
    
    def screen_recording(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        # Create screen recording dialog
        recording_window = tk.Toplevel(self.root)
        recording_window.title("Screen Recording")
        recording_window.geometry("400x200")
        recording_window.resizable(False, False)
        recording_window.transient(self.root)
        recording_window.grab_set()
        
        ttk.Label(recording_window, text="Screen Recording", font=("Default", 12, "bold")).pack(pady=10)
        
        # Duration frame
        duration_frame = ttk.Frame(recording_window)
        duration_frame.pack(fill=tk.X, pady=5, padx=20)
        
        ttk.Label(duration_frame, text="Duration (seconds):").pack(side=tk.LEFT, padx=5)
        duration_var = tk.StringVar(value="30")
        duration_entry = ttk.Entry(duration_frame, textvariable=duration_var, width=10)
        duration_entry.pack(side=tk.LEFT, padx=5)
        
        # Buttons
        buttons_frame = ttk.Frame(recording_window)
        buttons_frame.pack(fill=tk.X, pady=20, padx=20)
        
        def start_recording():
            try:
                duration = int(duration_var.get())
                if duration <= 0 or duration > 180:
                    messagebox.showwarning("Warning", "Duration must be between 1 and 180 seconds")
                    return
                    
                save_path = filedialog.asksaveasfilename(
                    title="Save Recording As",
                    defaultextension=".mp4",
                    filetypes=[("MP4 Files", "*.mp4"), ("All Files", "*.*")]
                )
                if not save_path:
                    return
                
                recording_window.destroy()
                threading.Thread(target=self._screen_recording_thread, 
                                args=(save_path, duration), daemon=True).start()
            except ValueError:
                messagebox.showwarning("Warning", "Duration must be a number")
        
        start_button = ttk.Button(buttons_frame, text="Start Recording", command=start_recording)
        start_button.pack(side=tk.LEFT, padx=5, expand=True)
        
        cancel_button = ttk.Button(buttons_frame, text="Cancel", command=recording_window.destroy)
        cancel_button.pack(side=tk.LEFT, padx=5, expand=True)
    
    def _screen_recording_thread(self, save_path, duration):
        try:
            self.status_var.set(f"Recording screen for {duration} seconds...")
            self.root.update_idletasks()
            
            device = self.connected_device.get()
            temp_path = "/sdcard/recording.mp4"
            
            # Start recording
            process = subprocess.Popen(
                ["adb", "-s", device, "shell", "screenrecord", "--time-limit", str(duration), temp_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            
            # Wait for recording to complete
            process.wait()
            
            self.status_var.set("Processing recording...")
            self.root.update_idletasks()
            
            # Pull recording
            subprocess.run(["adb", "-s", device, "pull", temp_path, save_path], check=True)
            
            # Remove temp file
            subprocess.run(["adb", "-s", device, "shell", "rm", temp_path], check=True)
            
            self.status_var.set("Recording saved")
            messagebox.showinfo("Success", f"Screen recording saved to {save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to record screen: {str(e)}")
            self.status_var.set("Recording failed")
    
    def clear_app_data(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        package_name = simpledialog.askstring("Clear App Data", "Enter package name:")
        if not package_name:
            return
            
        if not messagebox.askyesno("Confirm", f"Are you sure you want to clear data for {package_name}?"):
            return
            
        threading.Thread(target=self._clear_app_data_thread, args=(package_name,), daemon=True).start()
    
    def _clear_app_data_thread(self, package_name):
        try:
            self.status_var.set(f"Clearing data for {package_name}...")
            self.root.update_idletasks()
            
            device = self.connected_device.get()
            
            result = subprocess.run(
                ["adb", "-s", device, "shell", "pm", "clear", package_name],
                capture_output=True, text=True
            )
            
            if "Success" in result.stdout:
                self.status_var.set(f"Cleared data for {package_name}")
                messagebox.showinfo("Success", f"Data cleared for {package_name}")
            else:
                error_msg = result.stderr if result.stderr else "Unknown error"
                raise Exception(error_msg)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to clear app data: {str(e)}")
            self.status_var.set("Operation failed")
    
    def wireless_connect(self):
        if not self.adb_available:
            messagebox.showwarning("Warning", "ADB not available")
            return
            
        # Create wireless connect dialog
        wireless_window = tk.Toplevel(self.root)
        wireless_window.title("ADB Wireless Connect")
        wireless_window.geometry("400x200")
        wireless_window.resizable(False, False)
        wireless_window.transient(self.root)
        wireless_window.grab_set()
        
        ttk.Label(wireless_window, text="ADB Wireless Connect", font=("Default", 12, "bold")).pack(pady=10)
        
        # IP and port frame
        conn_frame = ttk.Frame(wireless_window)
        conn_frame.pack(fill=tk.X, pady=5, padx=20)
        
        ip_frame = ttk.Frame(conn_frame)
        ip_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(ip_frame, text="IP Address:").pack(side=tk.LEFT, padx=5)
        ip_var = tk.StringVar()
        ip_entry = ttk.Entry(ip_frame, textvariable=ip_var, width=20)
        ip_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        port_frame = ttk.Frame(conn_frame)
        port_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(port_frame, text="Port:").pack(side=tk.LEFT, padx=5)
        port_var = tk.StringVar(value="5555")
        port_entry = ttk.Entry(port_frame, textvariable=port_var, width=10)
        port_entry.pack(side=tk.LEFT, padx=5)
        
        # Buttons
        buttons_frame = ttk.Frame(wireless_window)
        buttons_frame.pack(fill=tk.X, pady=20, padx=20)
        
        def connect_wireless():
            ip = ip_var.get().strip()
            port = port_var.get().strip()
            
            if not ip:
                messagebox.showwarning("Warning", "IP address is required")
                return
                
            try:
                port_num = int(port)
                if port_num <= 0 or port_num > 65535:
                    messagebox.showwarning("Warning", "Port must be between 1 and 65535")
                    return
            except ValueError:
                messagebox.showwarning("Warning", "Port must be a number")
                return
                
            wireless_window.destroy()
            threading.Thread(target=self._wireless_connect_thread, 
                            args=(ip, port), daemon=True).start()
        
        connect_button = ttk.Button(buttons_frame, text="Connect", command=connect_wireless)
        connect_button.pack(side=tk.LEFT, padx=5, expand=True)
        
        cancel_button = ttk.Button(buttons_frame, text="Cancel", command=wireless_window.destroy)
        cancel_button.pack(side=tk.LEFT, padx=5, expand=True)
    
    def _wireless_connect_thread(self, ip, port):
        try:
            address = f"{ip}:{port}"
            self.status_var.set(f"Connecting to {address}...")
            self.root.update_idletasks()
            
            result = subprocess.run(
                ["adb", "connect", address],
                capture_output=True, text=True
            )
            
            if "connected" in result.stdout.lower():
                self.status_var.set(f"Connected to {address}")
                messagebox.showinfo("Success", f"Connected to {address}")
                self.refresh_devices()
            else:
                error_msg = result.stderr if result.stderr else "Unknown error"
                raise Exception(error_msg)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect: {str(e)}")
            self.status_var.set("Connection failed")
    
    def show_device_info(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        threading.Thread(target=self._show_device_info_thread, daemon=True).start()
    
    def _show_device_info_thread(self):
        try:
            device = self.connected_device.get()
            self.status_var.set("Getting device info...")
            self.root.update_idletasks()

            info = {}
            # Basic device info
            model_cmd = subprocess.run([
                "adb", "-s", device, "shell", "getprop", "ro.product.model"],
                capture_output=True, text=True
            )
            info["Model"] = model_cmd.stdout.strip()
            android_ver_cmd = subprocess.run([
                "adb", "-s", device, "shell", "getprop", "ro.build.version.release"],
                capture_output=True, text=True
            )
            info["Android Version"] = android_ver_cmd.stdout.strip()
            sdk_cmd = subprocess.run([
                "adb", "-s", device, "shell", "getprop", "ro.build.version.sdk"],
                capture_output=True, text=True
            )
            info["SDK Version"] = sdk_cmd.stdout.strip()
            manufacturer_cmd = subprocess.run([
                "adb", "-s", device, "shell", "getprop", "ro.product.manufacturer"],
                capture_output=True, text=True
            )
            info["Manufacturer"] = manufacturer_cmd.stdout.strip()

            # Detailed hardware info
            cpu_cmd = subprocess.run([
                "adb", "-s", device, "shell", "cat", "/proc/cpuinfo"],
                capture_output=True, text=True
            )
            cpu_info = ""
            for line in cpu_cmd.stdout.split('\n'):
                if any(k in line for k in ["Hardware", "Processor", "model name"]):
                    cpu_info += line + "\n"
            info["CPU Info"] = cpu_info.strip()
            ram_cmd = subprocess.run([
                "adb", "-s", device, "shell", "cat", "/proc/meminfo"],
                capture_output=True, text=True
            )
            mem_total = ""
            for line in ram_cmd.stdout.split('\n'):
                if "MemTotal" in line:
                    mem_total = line.strip()
            info["RAM"] = mem_total
            board_cmd = subprocess.run([
                "adb", "-s", device, "shell", "getprop", "ro.product.board"],
                capture_output=True, text=True
            )
            info["Board"] = board_cmd.stdout.strip()
            device_cmd = subprocess.run([
                "adb", "-s", device, "shell", "getprop", "ro.product.device"],
                capture_output=True, text=True
            )
            info["Device"] = device_cmd.stdout.strip()
            hardware_cmd = subprocess.run([
                "adb", "-s", device, "shell", "getprop", "ro.hardware"],
                capture_output=True, text=True
            )
            info["Hardware"] = hardware_cmd.stdout.strip()

            # Battery info (extended)
            battery_cmd = subprocess.run([
                "adb", "-s", device, "shell", "dumpsys", "battery"],
                capture_output=True, text=True
            )
            battery_output = battery_cmd.stdout.strip()
            battery_level_match = re.search(r"level: (\d+)", battery_output)
            if battery_level_match:
                info["Battery Level"] = f"{battery_level_match.group(1)}%"
            battery_health_match = re.search(r"health: (\d+)", battery_output)
            if battery_health_match:
                health_map = {1: "Unknown", 2: "Good", 3: "Overheat", 4: "Dead", 5: "Over voltage", 6: "Unspecified failure", 7: "Cold"}
                health_val = int(battery_health_match.group(1))
                info["Battery Health"] = health_map.get(health_val, str(health_val))
            tech_match = re.search(r"technology: (.+)", battery_output)
            if tech_match:
                info["Battery Tech"] = tech_match.group(1)
            voltage_match = re.search(r"voltage: (\d+)", battery_output)
            if voltage_match:
                info["Battery Voltage"] = f"{int(voltage_match.group(1))/1000:.3f} V"
            temp_match = re.search(r"temperature: (\d+)", battery_output)
            if temp_match:
                info["Battery Temp"] = f"{int(temp_match.group(1))/10:.1f} °C"

            # Screen resolution
            display_cmd = subprocess.run([
                "adb", "-s", device, "shell", "wm", "size"],
                capture_output=True, text=True
            )
            display_output = display_cmd.stdout.strip()
            resolution_match = re.search(r"Physical size: (\d+x\d+)", display_output)
            if resolution_match:
                info["Screen Resolution"] = resolution_match.group(1)

            # Radio info
            radio_cmd = subprocess.run([
                "adb", "-s", device, "shell", "dumpsys", "telephony.registry"],
                capture_output=True, text=True
            )
            radio_info = ""
            for line in radio_cmd.stdout.split('\n'):
                if any(k in line for k in ["mServiceState", "mDataConnectionState", "mSignalStrength"]):
                    radio_info += line.strip() + "\n"
            info["Radio Info"] = radio_info.strip()

            # Thermal status
            thermal_cmd = subprocess.run([
                "adb", "-s", device, "shell", "dumpsys", "thermalservice"],
                capture_output=True, text=True
            )
            thermal_info = ""
            for line in thermal_cmd.stdout.split('\n'):
                if line.strip():
                    thermal_info += line.strip() + "\n"
            info["Thermal Status"] = thermal_info.strip()

            # Sensor data
            sensor_cmd = subprocess.run([
                "adb", "-s", device, "shell", "dumpsys", "sensorservice"],
                capture_output=True, text=True
            )
            sensors = []
            for line in sensor_cmd.stdout.split('\n'):
                if "Sensor " in line or "handle:" in line:
                    sensors.append(line.strip())
            info["Sensors"] = "\n".join(sensors)

            # Create info window
            self.root.update_idletasks()
            info_window = tk.Toplevel(self.root)
            info_window.title(f"Device Info: {device}")
            info_window.geometry("700x700")
            info_window.transient(self.root)
            info_window.grab_set()

            # Notebook for sections
            notebook = ttk.Notebook(info_window)
            notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            # General tab
            general_frame = ttk.Frame(notebook, padding="10")
            notebook.add(general_frame, text="General")
            row = 0
            for key in ["Model", "Manufacturer", "Android Version", "SDK Version", "Screen Resolution", "Board", "Device", "Hardware", "CPU Info", "RAM"]:
                if key in info:
                    ttk.Label(general_frame, text=key+":", font=("Default", 10, "bold")).grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
                    ttk.Label(general_frame, text=info[key]).grid(row=row, column=1, sticky=tk.W, padx=5, pady=5)
                    row += 1

            # Battery tab
            battery_frame = ttk.Frame(notebook, padding="10")
            notebook.add(battery_frame, text="Battery")
            row = 0
            for key in ["Battery Level", "Battery Health", "Battery Tech", "Battery Voltage", "Battery Temp"]:
                if key in info:
                    ttk.Label(battery_frame, text=key+":", font=("Default", 10, "bold")).grid(row=row, column=0, sticky=tk.W, padx=5, pady=5)
                    ttk.Label(battery_frame, text=info[key]).grid(row=row, column=1, sticky=tk.W, padx=5, pady=5)
                    row += 1

            # Radio tab
            radio_frame = ttk.Frame(notebook, padding="10")
            notebook.add(radio_frame, text="Radio")
            # Organize radio info in a table
            radio_tree = ttk.Treeview(radio_frame, columns=("key", "value"), show="headings", height=8)
            radio_tree.heading("key", text="Property")
            radio_tree.heading("value", text="Value")
            radio_tree.column("key", width=200)
            radio_tree.column("value", width=400)
            radio_tree.pack(fill=tk.BOTH, expand=True)
            # Parse radio info
            radio_lines = info.get("Radio Info", "").split("\n")
            for line in radio_lines:
                if ":" in line:
                    k, v = line.split(":", 1)
                    radio_tree.insert("", tk.END, values=(k.strip(), v.strip()))
                elif line.strip():
                    radio_tree.insert("", tk.END, values=(line.strip(), ""))

            # Thermal tab
            thermal_frame = ttk.Frame(notebook, padding="10")
            notebook.add(thermal_frame, text="Thermal")
            # Organize thermal info in a table
            thermal_tree = ttk.Treeview(thermal_frame, columns=("sensor", "value"), show="headings", height=8)
            thermal_tree.heading("sensor", text="Sensor")
            thermal_tree.heading("value", text="Value")
            thermal_tree.column("sensor", width=250)
            thermal_tree.column("value", width=350)
            thermal_tree.pack(fill=tk.BOTH, expand=True)
            # Parse thermal info
            thermal_lines = info.get("Thermal Status", "").split("\n")
            for line in thermal_lines:
                if ":" in line:
                    k, v = line.split(":", 1)
                    thermal_tree.insert("", tk.END, values=(k.strip(), v.strip()))
                elif line.strip():
                    thermal_tree.insert("", tk.END, values=(line.strip(), ""))

            # Sensors tab
            sensor_frame = ttk.Frame(notebook, padding="10")
            notebook.add(sensor_frame, text="Sensors")
            # Organize sensors in a table
            sensor_tree = ttk.Treeview(sensor_frame, columns=("name", "handle"), show="headings", height=12)
            sensor_tree.heading("name", text="Sensor Name/Type")
            sensor_tree.heading("handle", text="Handle/Details")
            sensor_tree.column("name", width=350)
            sensor_tree.column("handle", width=300)
            sensor_tree.pack(fill=tk.BOTH, expand=True)
            # Parse sensor info
            sensor_lines = info.get("Sensors", "").split("\n")
            for line in sensor_lines:
                if "handle:" in line:
                    parts = line.split("handle:")
                    sensor_tree.insert("", tk.END, values=(parts[0].strip(), "handle:" + parts[1].strip()))
                else:
                    sensor_tree.insert("", tk.END, values=(line.strip(), ""))

            # Buttons
            button_frame = ttk.Frame(info_window)
            button_frame.pack(fill=tk.X, pady=10)
            refresh_button = ttk.Button(button_frame, text="Refresh", 
                                        command=lambda: [info_window.destroy(), self.show_device_info()])
            refresh_button.pack(side=tk.LEFT, padx=5)
            close_button = ttk.Button(button_frame, text="Close", command=info_window.destroy)
            close_button.pack(side=tk.RIGHT, padx=5)
            self.status_var.set("Device info displayed")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get device info: {str(e)}")
            self.status_var.set("Operation failed")
    
    def confirm_action(self, action, message):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        if not messagebox.askyesno("Confirm", message):
            return
            
        threading.Thread(target=self._confirm_action_thread, args=(action,), daemon=True).start()
    
    def _confirm_action_thread(self, action):
        try:
            device = self.connected_device.get()
            self.status_var.set(f"Executing {action}...")
            self.root.update_idletasks()
            
            cmd_parts = action.split()
            command = ["adb", "-s", device]
            command.extend(cmd_parts)
            
            subprocess.run(command, check=True)
            
            self.status_var.set(f"Executed {action}")
            messagebox.showinfo("Success", f"{action.capitalize()} command sent successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to execute {action}: {str(e)}")
            self.status_var.set("Operation failed")
    
    def show_about(self):
        about_window = tk.Toplevel(self.root)
        about_window.title("About ADB GUI Tool")
        about_window.geometry("400x300")
        about_window.resizable(False, False)
        about_window.transient(self.root)
        about_window.grab_set()
        
        ttk.Label(about_window, text="ADB GUI Tool", font=("Default", 16, "bold")).pack(pady=(20, 10))
        ttk.Label(about_window, text="Version 1.0").pack()
        
        ttk.Separator(about_window, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=20, pady=20)
        
        info_text = (
            "A graphical interface for Android Debug Bridge (ADB) commands.\n\n"
            "This tool provides easy access to common ADB functions like:\n"
            "• Device management\n"
            "• App installation and management\n"
            "• File transfers\n"
            "• Shell command execution\n"
            "• And more"
        )
        
        ttk.Label(about_window, text=info_text, justify=tk.CENTER, wraplength=350).pack(pady=10)
        
        ttk.Button(about_window, text="Close", command=about_window.destroy).pack(pady=20)
    
    def show_battery_monitor(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        # Create battery monitor window
        battery_window = tk.Toplevel(self.root)
        battery_window.title("Battery Monitor")
        battery_window.geometry("400x300")
        battery_window.transient(self.root)
        
        # Battery info frame
        info_frame = ttk.Frame(battery_window, padding="20")
        info_frame.pack(fill=tk.BOTH, expand=True)
        
        # Battery level
        level_var = tk.StringVar(value="0%")
        ttk.Label(info_frame, text="Battery Level:", font=("Default", 12, "bold")).pack(anchor=tk.W, pady=5)
        level_label = ttk.Label(info_frame, textvariable=level_var, font=("Default", 24))
        level_label.pack(anchor=tk.W, pady=5)
        
        # Battery status
        status_var = tk.StringVar(value="Unknown")
        ttk.Label(info_frame, text="Status:", font=("Default", 12, "bold")).pack(anchor=tk.W, pady=5)
        status_label = ttk.Label(info_frame, textvariable=status_var)
        status_label.pack(anchor=tk.W, pady=5)
        
        # Temperature
        temp_var = tk.StringVar(value="--°C")
        ttk.Label(info_frame, text="Temperature:", font=("Default", 12, "bold")).pack(anchor=tk.W, pady=5)
        temp_label = ttk.Label(info_frame, textvariable=temp_var)
        temp_label.pack(anchor=tk.W, pady=5)
        
        def update_battery_info():
            if not battery_window.winfo_exists():
                return
                
            try:
                device = self.connected_device.get()
                result = subprocess.run(
                    ["adb", "-s", device, "shell", "dumpsys", "battery"],
                    capture_output=True, text=True
                )
                
                output = result.stdout
                
                # Update battery level
                level_match = re.search(r"level: (\d+)", output)
                if level_match:
                    level_var.set(f"{level_match.group(1)}%")
                
                # Update status
                status_match = re.search(r"status: (\d+)", output)
                if status_match:
                    status = int(status_match.group(1))
                    status_text = {
                        1: "Unknown",
                        2: "Charging",
                        3: "Discharging",
                        4: "Not charging",
                        5: "Full"
                    }.get(status, "Unknown")
                    status_var.set(status_text)
                
                # Update temperature
                temp_match = re.search(r"temperature: (\d+)", output)
                if temp_match:
                    temp_c = int(temp_match.group(1)) / 10.0
                    temp_var.set(f"{temp_c}°C")
                
                # Schedule next update
                battery_window.after(2000, update_battery_info)
            except Exception as e:
                status_var.set(f"Error: {str(e)}")
        
        # Start updating
        update_battery_info()
        
        # Close button
        ttk.Button(battery_window, text="Close", command=battery_window.destroy).pack(pady=20)
    
    def show_logcat(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        # Create logcat window
        logcat_window = tk.Toplevel(self.root)
        logcat_window.title("Logcat Viewer")
        logcat_window.geometry("800x600")
        
        # Main frame
        main_frame = ttk.Frame(logcat_window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Filter frame
        filter_frame = ttk.Frame(main_frame)
        filter_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Log level filter
        ttk.Label(filter_frame, text="Log Level:").pack(side=tk.LEFT, padx=5)
        level_var = tk.StringVar(value="All")
        level_combo = ttk.Combobox(filter_frame, textvariable=level_var, values=["All", "Verbose", "Debug", "Info", "Warning", "Error"], state="readonly", width=10)
        level_combo.pack(side=tk.LEFT, padx=5)
        
        # Tag filter
        ttk.Label(filter_frame, text="Tag:").pack(side=tk.LEFT, padx=5)
        tag_var = tk.StringVar()
        tag_entry = ttk.Entry(filter_frame, textvariable=tag_var)
        tag_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Clear button
        clear_button = ttk.Button(filter_frame, text="Clear", command=lambda: log_text.delete(1.0, tk.END))
        clear_button.pack(side=tk.RIGHT, padx=5)
        
        # Log text area
        log_text = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD)
        log_text.pack(fill=tk.BOTH, expand=True)
        
        # Tag colors
        tag_colors = {
            "V": "#808080",  # Gray
            "D": "#0000FF",  # Blue
            "I": "#008000",  # Green
            "W": "#FFA500",  # Orange
            "E": "#FF0000",  # Red
        }
        
        for level, color in tag_colors.items():
            log_text.tag_configure(level, foreground=color)
        
        # Add stop flag and process variable
        logcat_process = {'process': None, 'running': False}
        
        def start_logcat():
            if logcat_process['running']:
                return
                
            device = self.connected_device.get()
            level_filter = level_var.get()
            tag_filter = tag_var.get()
            
            # Build logcat command
            cmd = ["adb", "-s", device, "logcat"]
            
            if level_filter != "All":
                cmd.extend([f"*:{level_filter[0]}"])
            
            if tag_filter:
                cmd.extend([f"{tag_filter}:V"])
            
            # Start logcat process
            try:
                logcat_process['process'] = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                logcat_process['running'] = True
                start_button.config(state=tk.DISABLED)
                stop_button.config(state=tk.NORMAL)
                
                def read_output():
                    while logcat_process['running']:
                        if not logcat_window.winfo_exists():
                            logcat_process['process'].terminate()
                            break
                            
                        line = logcat_process['process'].stdout.readline()
                        if not line:
                            break
                            
                        log_text.config(state=tk.NORMAL)
                        log_text.insert(tk.END, line)
                        
                        # Apply color based on log level
                        for level in tag_colors:
                            if f"/{level}/" in line:
                                pos = log_text.index("end-1c linestart")
                                log_text.tag_add(level, pos, log_text.index("end-1c"))
                                break
                        
                        log_text.see(tk.END)
                        log_text.config(state=tk.DISABLED)
                
                threading.Thread(target=read_output, daemon=True).start()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to start logcat: {str(e)}")
        
        def stop_logcat():
            if logcat_process['running']:
                logcat_process['running'] = False
                if logcat_process['process']:
                    logcat_process['process'].terminate()
                    logcat_process['process'] = None
                start_button.config(state=tk.NORMAL)
                stop_button.config(state=tk.DISABLED)
        
        # Update buttons frame
        buttons_frame = ttk.Frame(filter_frame)
        buttons_frame.pack(side=tk.RIGHT, padx=5)
        
        start_button = ttk.Button(buttons_frame, text="Start", command=start_logcat)
        start_button.pack(side=tk.LEFT, padx=5)
        
        stop_button = ttk.Button(buttons_frame, text="Stop", command=stop_logcat, state=tk.DISABLED)
        stop_button.pack(side=tk.LEFT, padx=5)
        
        # Add window close handler
        def on_window_close():
            stop_logcat()
            logcat_window.destroy()
        
        logcat_window.protocol("WM_DELETE_WINDOW", on_window_close)
    
    def show_network_tools(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        # Create network tools window
        network_window = tk.Toplevel(self.root)
        network_window.title("Network Tools")
        network_window.geometry("600x500")
        network_window.transient(self.root)
        
        # Main frame
        main_frame = ttk.Frame(network_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Network info frame
        info_frame = ttk.LabelFrame(main_frame, text="Network Information", padding="10")
        info_frame.pack(fill=tk.X, pady=(0, 20))
        
        # IP address
        ip_var = tk.StringVar()
        ttk.Label(info_frame, text="IP Address:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Label(info_frame, textvariable=ip_var).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # WiFi info
        wifi_var = tk.StringVar()
        ttk.Label(info_frame, text="WiFi Status:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Label(info_frame, textvariable=wifi_var).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        def update_network_info():
            device = self.connected_device.get()
            
            # Get IP address
            ip_result = subprocess.run(
                ["adb", "-s", device, "shell", "ip", "route"],
                capture_output=True, text=True
            )
            
            ip_match = re.search(r"src (\d+\.\d+\.\d+\.\d+)", ip_result.stdout)
            if ip_match:
                ip_var.set(ip_match.group(1))
            else:
                ip_var.set("Not available")
            
            # Get WiFi info
            wifi_result = subprocess.run(
                ["adb", "-s", device, "shell", "dumpsys", "wifi"],
                capture_output=True, text=True
            )
            
            if "Wi-Fi is enabled" in wifi_result.stdout:
                ssid_match = re.search(r'SSID: "(.*?)"', wifi_result.stdout)
                if ssid_match:
                    wifi_var.set(f"Connected to {ssid_match.group(1)}")
                else:
                    wifi_var.set("WiFi enabled but not connected")
            else:
                wifi_var.set("WiFi disabled")
        
        # Network test frame
        test_frame = ttk.LabelFrame(main_frame, text="Network Tests", padding="10")
        test_frame.pack(fill=tk.BOTH, expand=True)
        
        # Ping test
        ping_frame = ttk.Frame(test_frame)
        ping_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(ping_frame, text="Ping Host:").pack(side=tk.LEFT, padx=5)
        ping_host = ttk.Entry(ping_frame)
        ping_host.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        ping_host.insert(0, "8.8.8.8")
        
        def run_ping_test():
            host = ping_host.get().strip()
            if not host:
                return
                
            device = self.connected_device.get()
            result_text.config(state=tk.NORMAL)
            result_text.insert(tk.END, f"\nPinging {host}...\n")
            
            try:
                result = subprocess.run(
                    ["adb", "-s", device, "shell", f"ping -c 4 {host}"],
                    capture_output=True, text=True
                )
                result_text.insert(tk.END, result.stdout)
            except Exception as e:
                result_text.insert(tk.END, f"Error: {str(e)}\n")
            
            result_text.see(tk.END)
            result_text.config(state=tk.DISABLED)
        
        ttk.Button(ping_frame, text="Ping", command=run_ping_test).pack(side=tk.LEFT, padx=5)
        
        # DNS test
        dns_frame = ttk.Frame(test_frame)
        dns_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(dns_frame, text="DNS Lookup:").pack(side=tk.LEFT, padx=5)
        dns_host = ttk.Entry(dns_frame)
        dns_host.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        dns_host.insert(0, "google.com")
        
        def run_dns_test():
            host = dns_host.get().strip()
            if not host:
                return
                
            device = self.connected_device.get()
            result_text.config(state=tk.NORMAL)
            result_text.insert(tk.END, f"\nLooking up {host}...\n")
            
            try:
                result = subprocess.run(
                    ["adb", "-s", device, "shell", f"nslookup {host}"],
                    capture_output=True, text=True
                )
                result_text.insert(tk.END, result.stdout)
            except Exception as e:
                result_text.insert(tk.END, f"Error: {str(e)}\n")
            
            result_text.see(tk.END)
            result_text.config(state=tk.DISABLED)
        
        ttk.Button(dns_frame, text="Lookup", command=run_dns_test).pack(side=tk.LEFT, padx=5)
        
        # Results
        ttk.Label(test_frame, text="Results:").pack(anchor=tk.W, pady=(10, 5))
        result_text = scrolledtext.ScrolledText(test_frame, height=10, wrap=tk.WORD)
        result_text.pack(fill=tk.BOTH, expand=True)
        result_text.config(state=tk.DISABLED)
        
        # Update network info initially
        update_network_info()
        
        # Refresh button
        ttk.Button(main_frame, text="Refresh Info", command=update_network_info).pack(pady=10)
    
    def backup_app(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        # Get package name
        package_name = simpledialog.askstring("Backup App", "Enter package name:")
        if not package_name:
            return
            
        # Get backup location
        backup_path = filedialog.asksaveasfilename(
            title="Save Backup As",
            defaultextension=".ab",
            initialfile=f"{package_name}_backup.ab",
            filetypes=[("Android Backup", "*.ab"), ("All Files", "*.*")]
        )
        if not backup_path:
            return
            
        threading.Thread(target=self._backup_app_thread, 
                        args=(package_name, backup_path), daemon=True).start()
    
    def _backup_app_thread(self, package_name, backup_path):
        try:
            device = self.connected_device.get()
            self.status_var.set(f"Backing up {package_name}...")
            self.root.update_idletasks()
            
            # Run backup command
            result = subprocess.run(
                ["adb", "-s", device, "backup", "-f", backup_path, package_name],
                capture_output=True, text=True
            )
            
            if os.path.exists(backup_path) and os.path.getsize(backup_path) > 0:
                self.status_var.set(f"Backup saved to {backup_path}")
                messagebox.showinfo("Success", f"App backup saved to {backup_path}")
            else:
                raise Exception("Backup file was not created or is empty")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to backup app: {str(e)}")
            self.status_var.set("Backup failed")
    
    def restore_app(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        # Get backup file
        backup_path = filedialog.askopenfilename(
            title="Select Backup File",
            filetypes=[("Android Backup", "*.ab"), ("All Files", "*.*")]
        )
        if not backup_path:
            return
            
        if not messagebox.askyesno("Confirm Restore", 
                                  "Are you sure you want to restore this backup? "
                                  "This will replace the current app data."):
            return
            
        threading.Thread(target=self._restore_app_thread, 
                        args=(backup_path,), daemon=True).start()
    
    def _restore_app_thread(self, backup_path):
        try:
            device = self.connected_device.get()
            self.status_var.set("Restoring backup...")
            self.root.update_idletasks()
            
            # Run restore command
            result = subprocess.run(
                ["adb", "-s", device, "restore", backup_path],
                capture_output=True, text=True
            )
            
            if "done" in result.stdout.lower():
                self.status_var.set("Backup restored successfully")
                messagebox.showinfo("Success", "App backup restored successfully")
            else:
                raise Exception(result.stderr or "Unknown error during restore")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to restore backup: {str(e)}")
            self.status_var.set("Restore failed")
    
    def show_process_manager(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        # Create process manager window
        process_window = tk.Toplevel(self.root)
        process_window.title("Process Manager")
        process_window.geometry("800x600")
        process_window.transient(self.root)
        
        # Main frame
        main_frame = ttk.Frame(process_window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Notebook for different sections
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Processes tab
        processes_frame = ttk.Frame(notebook, padding="10")
        notebook.add(processes_frame, text="Processes")
        
        # Add total memory and process summary label
        total_mem_label = ttk.Label(processes_frame, text="Total Memory Usage: --")
        total_mem_label.pack(anchor=tk.W, pady=(0, 5))
        
        # Filter frame
        filter_frame = ttk.Frame(processes_frame)
        filter_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=5)
        filter_var = tk.StringVar()
        filter_entry = ttk.Entry(filter_frame, textvariable=filter_var)
        filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Process list
        process_frame = ttk.Frame(processes_frame)
        process_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview for processes
        columns = ("PID", "User", "Name", "CPU%", "Memory")
        process_tree = ttk.Treeview(process_frame, columns=columns, show="headings")
        
        for col in columns:
            process_tree.heading(col, text=col)
            process_tree.column(col, width=100)
        
        process_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Scrollbar for process list
        process_scroll = ttk.Scrollbar(process_frame, orient=tk.VERTICAL, command=process_tree.yview)
        process_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        process_tree.configure(yscrollcommand=process_scroll.set)
        
        # Process actions frame
        action_frame = ttk.Frame(processes_frame)
        action_frame.pack(fill=tk.X, pady=10)
        
        def force_stop_app():
            selected = process_tree.selection()
            if not selected:
                messagebox.showwarning("Warning", "Please select a process")
                return
                
            item = process_tree.item(selected[0])
            package_name = item['values'][2]  # Process name column
            
            if messagebox.askyesno("Confirm", f"Force stop {package_name}?"):
                device = self.connected_device.get()
                try:
                    subprocess.run(["adb", "-s", device, "shell", "am", "force-stop", package_name], check=True)
                    refresh_processes()
                    messagebox.showinfo("Success", f"Forced stop {package_name}")
                except subprocess.CalledProcessError as e:
                    messagebox.showerror("Error", f"Failed to force stop: {str(e)}")
        
        refresh_scheduled = False
        last_refresh = 0
        MIN_REFRESH_INTERVAL = 2000  # Minimum time between refreshes in milliseconds
        
        def schedule_refresh():
            nonlocal refresh_scheduled
            if not refresh_scheduled:
                refresh_scheduled = True
                process_window.after(MIN_REFRESH_INTERVAL, do_refresh)
        
        def do_refresh():
            nonlocal refresh_scheduled, last_refresh
            refresh_scheduled = False
            current_time = int(time.time() * 1000)
            
            if current_time - last_refresh < MIN_REFRESH_INTERVAL:
                schedule_refresh()
                return
                
            refresh_processes()
            last_refresh = current_time
        
        def refresh_processes():
            if not process_window.winfo_exists():
                return
                
            device = self.connected_device.get()
            filter_text = filter_var.get().lower()
            
            try:
                # Get all process info in one top command
                top_result = subprocess.run(
                    ["adb", "-s", device, "shell", "top -b -n 1"],
                    capture_output=True, text=True
                )
                
                # Parse memory info from top header
                mem_info = {}
                for line in top_result.stdout.split('\n'):
                    if 'Mem:' in line:
                        parts = line.split()
                        # Handle K suffix in memory values
                        total_ram = float(parts[1].rstrip('K')) / 1024  # Convert K to MB
                        used_ram = float(parts[3].rstrip('K')) / 1024   # Convert K to MB
                        break
                
                # Count total processes
                total_processes = len([l for l in top_result.stdout.split('\n') if l.strip() and not l.startswith('User')])
                
                # Update the process summary and memory label
                total_mem_label.config(
                    text=f"Tasks: {total_processes} total, {used_ram:.1f}MB / {total_ram:.1f}MB RAM used"
                )
                
                process_tree.delete(*process_tree.get_children())
                
                # Process each line from top output
                lines = top_result.stdout.split('\n')
                for line in lines:
                    if not line.strip() or line.startswith('User') or 'PID' in line or 'Mem:' in line:
                        continue
                        
                    parts = line.split()
                    if len(parts) >= 9:
                        try:
                            pid = parts[1]
                            user = parts[0]
                            cpu = parts[8].rstrip('%')  # CPU percentage
                            # Handle K suffix in memory values
                            mem = float(parts[6].rstrip('K')) / 1024  # Convert K to MB
                            name = parts[-1]  # Process name is the last part
                            
                            # Apply filter if any
                            if filter_text and filter_text not in name.lower():
                                continue
                                
                            process_tree.insert("", tk.END, values=(pid, user, name, cpu, f"{mem:.1f}MB"))
                        except (ValueError, IndexError):
                            continue
            except Exception as e:
                messagebox.showerror("Error", f"Failed to get process list: {str(e)}")
        
        # Setup auto-refresh and filter
        filter_var.trace('w', lambda *args: schedule_refresh())
        
        ttk.Button(action_frame, text="Force Stop", command=force_stop_app).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Refresh", command=do_refresh).pack(side=tk.LEFT, padx=5)
        
        # Rest of the tabs...
        # ...existing code...

    def show_storage_analysis(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        # Create storage analysis window
        storage_window = tk.Toplevel(self.root)
        storage_window.title("Storage Analysis")
        storage_window.geometry("600x500")
        storage_window.transient(self.root)
        
        # Main frame
        main_frame = ttk.Frame(storage_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Storage info frame
        info_frame = ttk.LabelFrame(main_frame, text="Storage Information", padding="10")
        info_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Storage summary labels
        internal_var = tk.StringVar(value="Analyzing...")
        sdcard_var = tk.StringVar(value="Analyzing...")
        system_var = tk.StringVar(value="Analyzing...")
        
        ttk.Label(info_frame, text="Internal Storage:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Label(info_frame, textvariable=internal_var).grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(info_frame, text="SD Card:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Label(info_frame, textvariable=sdcard_var).grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(info_frame, text="System:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Label(info_frame, textvariable=system_var).grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Storage usage breakdown
        usage_frame = ttk.LabelFrame(main_frame, text="Storage Usage Breakdown", padding="10")
        usage_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview for storage usage
        columns = ("Category", "Size", "Path")
        usage_tree = ttk.Treeview(usage_frame, columns=columns, show="headings")
        
        for col in columns:
            usage_tree.heading(col, text=col)
            if col == "Path":
                usage_tree.column(col, width=250)
            else:
                usage_tree.column(col, width=100)
        
        usage_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Scrollbar for usage tree
        usage_scroll = ttk.Scrollbar(usage_frame, orient=tk.VERTICAL, command=usage_tree.yview)
        usage_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        usage_tree.configure(yscrollcommand=usage_scroll.set)
        
        def get_storage_size(size_str):
            try:
                size = float(size_str.strip())
                if "G" in size_str:
                    return size * 1024 * 1024 * 1024
                elif "M" in size_str:
                    return size * 1024 * 1024
                elif "K" in size_str:
                    return size * 1024
                else:
                    return size
            except:
                return 0
        
        def format_size(size_bytes):
            if size_bytes >= 1024 * 1024 * 1024:
                return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
            elif size_bytes >= 1024 * 1024:
                return f"{size_bytes / (1024 * 1024):.2f} MB"
            elif size_bytes >= 1024:
                return f"{size_bytes / 1024:.2f} KB"
            else:
                return f"{size_bytes} B"
        
        def analyze_storage():
            device = self.connected_device.get()
            try:
                # Get storage info
                df_result = subprocess.run(
                    ["adb", "-s", device, "shell", "df"],
                    capture_output=True, text=True
                )
                
                for line in df_result.stdout.split('\n'):
                    if "/data" in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            total = get_storage_size(parts[1])
                            used = get_storage_size(parts[2])
                            internal_var.set(f"{format_size(used)} / {format_size(total)}")
                    elif "/sdcard" in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            total = get_storage_size(parts[1])
                            used = get_storage_size(parts[2])
                            sdcard_var.set(f"{format_size(used)} / {format_size(total)}")
                    elif "/system" in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            total = get_storage_size(parts[1])
                            used = get_storage_size(parts[2])
                            system_var.set(f"{format_size(used)} / {format_size(total)}")
                
                # Clear previous entries
                usage_tree.delete(*usage_tree.get_children())
                
                # Analyze app data sizes
                du_result = subprocess.run(
                    ["adb", "-s", device, "shell", "du -h /data/data"],
                    capture_output=True, text=True
                )
                
                for line in du_result.stdout.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            size_str = parts[0]
                            path = parts[1]
                            if "/data/data/" in path:
                                app_name = path.split("/")[-1]
                                usage_tree.insert("", tk.END, values=("App Data", size_str, app_name))
                
                # Analyze media sizes
                media_dirs = ["/sdcard/DCIM", "/sdcard/Pictures", "/sdcard/Download", "/sdcard/Movies", "/sdcard/Music"]
                for dir_path in media_dirs:
                    du_result = subprocess.run(
                        ["adb", "-s", device, "shell", f"du -h {dir_path}"],
                        capture_output=True, text=True
                    )
                    
                    if du_result.stdout.strip():
                        parts = du_result.stdout.split('\n')[0].split()
                        if len(parts) >= 2:
                            size_str = parts[0]
                            category = dir_path.split("/")[-1]
                            usage_tree.insert("", tk.END, values=("Media", size_str, category))
            
            except Exception as e:
                messagebox.showerror("Error", f"Failed to analyze storage: {str(e)}")
        
        # Start analysis
        threading.Thread(target=analyze_storage, daemon=True).start()
        
        # Refresh button
        ttk.Button(main_frame, text="Refresh", command=lambda: threading.Thread(target=analyze_storage, daemon=True).start()).pack(pady=10)

    def show_cache_cleaner(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        # Create cache cleaner window
        cache_window = tk.Toplevel(self.root)
        cache_window.title("Cache Cleaner")
        cache_window.geometry("600x500")
        cache_window.transient(self.root)
        
        # Main frame
        main_frame = ttk.Frame(cache_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Info label
        ttk.Label(main_frame, text="Select apps to clear cache:").pack(anchor=tk.W, pady=(0, 10))
        
        # Apps list frame
        list_frame = ttk.Frame(main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview for apps
        columns = ("Package Name", "Cache Size")
        apps_tree = ttk.Treeview(list_frame, columns=columns, show="headings")
        
        for col in columns:
            apps_tree.heading(col, text=col)
            apps_tree.column(col, width=200)
        
        apps_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Scrollbar
        apps_scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=apps_tree.yview)
        apps_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        apps_tree.configure(yscrollcommand=apps_scroll.set)
        
        def scan_cache():
            device = self.connected_device.get()
            try:
                # Clear previous entries
                apps_tree.delete(*apps_tree.get_children())
                
                # Get list of packages
                result = subprocess.run(
                    ["adb", "-s", device, "shell", "pm list packages"],
                    capture_output=True, text=True
                )
                
                packages = [line.split(":")[-1].strip() for line in result.stdout.split('\n') if line.strip()]
                
                # Check cache size for each package
                for package in packages:
                    try:
                        cache_result = subprocess.run(
                            ["adb", "-s", device, "shell", f"du -h /data/data/{package}/cache"],
                            capture_output=True, text=True
                        )
                        
                        if cache_result.stdout.strip():
                            size = cache_result.stdout.split()[0]
                            apps_tree.insert("", tk.END, values=(package, size))
                    except:
                        continue
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to scan cache: {str(e)}")
        
        def clear_selected_cache():
            selected = apps_tree.selection()
            if not selected:
                messagebox.showwarning("Warning", "Please select apps to clear cache")
                return
                
            if not messagebox.askyesno("Confirm", "Clear cache for selected apps?"):
                return
                
            device = self.connected_device.get()
            cleared = 0
            
            try:
                for item in selected:
                    package = apps_tree.item(item)['values'][0]
                    subprocess.run(
                        ["adb", "-s", device, "shell", f"rm -rf /data/data/{package}/cache/*"],
                        capture_output=True, text=True
                    )
                    cleared += 1
                
                messagebox.showinfo("Success", f"Cleared cache for {cleared} app(s)")
                scan_cache()  # Refresh the list
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear cache: {str(e)}")
        
        def clear_all_cache():
            if not messagebox.askyesno("Confirm", "Clear cache for all listed apps?"):
                return
                
            device = self.connected_device.get()
            cleared = 0
            
            try:
                for item in apps_tree.get_children():
                    package = apps_tree.item(item)['values'][0]
                    subprocess.run(
                        ["adb", "-s", device, "shell", f"rm -rf /data/data/{package}/cache/*"],
                        capture_output=True, text=True
                    )
                    cleared += 1
                
                messagebox.showinfo("Success", f"Cleared cache for {cleared} app(s)")
                scan_cache()  # Refresh the list
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear cache: {str(e)}")
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(buttons_frame, text="Scan Cache", command=lambda: threading.Thread(target=scan_cache, daemon=True).start()).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Clear Selected", command=clear_selected_cache).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Clear All", command=clear_all_cache).pack(side=tk.LEFT, padx=5)
        
        # Initial scan
        threading.Thread(target=scan_cache, daemon=True).start()

    def show_large_file_finder(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        # Create large file finder window
        finder_window = tk.Toplevel(self.root)
        finder_window.title("Large File Finder")
        finder_window.geometry("800x600")
        finder_window.transient(self.root)
        
        # Main frame
        main_frame = ttk.Frame(finder_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Search options frame
        options_frame = ttk.LabelFrame(main_frame, text="Search Options", padding="10")
        options_frame.pack(fill=tk.X, pady=(0, 20))
        
        # Minimum size frame
        size_frame = ttk.Frame(options_frame)
        size_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(size_frame, text="Minimum Size:").pack(side=tk.LEFT, padx=5)
        size_var = tk.StringVar(value="100")
        size_entry = ttk.Entry(size_frame, textvariable=size_var, width=10)
        size_entry.pack(side=tk.LEFT, padx=5)
        
        size_unit = ttk.Combobox(size_frame, values=["MB", "GB"], width=5, state="readonly")
        size_unit.set("MB")
        size_unit.pack(side=tk.LEFT, padx=5)
        
        # Search path frame
        path_frame = ttk.Frame(options_frame)
        path_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(path_frame, text="Search Path:").pack(side=tk.LEFT, padx=5)
        path_var = tk.StringVar(value="/sdcard")
        path_entry = ttk.Entry(path_frame, textvariable=path_var)
        path_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="Large Files", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview for files
        columns = ("Size", "Path", "Modified")
        files_tree = ttk.Treeview(results_frame, columns=columns, show="headings")
        
        for col in columns:
            files_tree.heading(col, text=col)
            if col == "Path":
                files_tree.column(col, width=400)
            else:
                files_tree.column(col, width=100)
        
        files_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Scrollbar
        files_scroll = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=files_tree.yview)
        files_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        files_tree.configure(yscrollcommand=files_scroll.set)
        
        def format_size(size_bytes):
            if size_bytes >= 1024 * 1024 * 1024:
                return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
            elif size_bytes >= 1024 * 1024:
                return f"{size_bytes / (1024 * 1024):.2f} MB"
            else:
                return f"{size_bytes / 1024:.2f} KB"
        
        def search_files():
            device = self.connected_device.get()
            try:
                # Clear previous results
                files_tree.delete(*files_tree.get_children())
                
                # Get minimum size in bytes
                try:
                    min_size = float(size_var.get())
                    if size_unit.get() == "GB":
                        min_size *= 1024 * 1024 * 1024
                    else:  # MB
                        min_size *= 1024 * 1024
                except ValueError:
                    messagebox.showerror("Error", "Invalid minimum size")
                    return
                
                search_path = path_var.get().strip()
                if not search_path:
                    messagebox.showerror("Error", "Invalid search path")
                    return
                
                # Find large files
                find_cmd = f'find "{search_path}" -type f -size +{int(min_size)}c -exec ls -l {{}} \\;'
                result = subprocess.run(
                    ["adb", "-s", device, "shell", find_cmd],
                    capture_output=True, text=True
                )
                
                for line in result.stdout.split('\n'):
                    if not line.strip():
                        continue
                        
                    try:
                        parts = line.split()
                        if len(parts) >= 8:
                            size = int(parts[4])
                            path = " ".join(parts[7:])
                            date = " ".join(parts[5:7])
                            
                            if size >= min_size:
                                files_tree.insert("", tk.END, values=(format_size(size), path, date))
                    except:
                        continue
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to search files: {str(e)}")
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(buttons_frame, text="Search", command=lambda: threading.Thread(target=search_files, daemon=True).start()).pack(side=tk.LEFT, padx=5)
        
        # Initial search
        threading.Thread(target=search_files, daemon=True).start()

    def show_layout_bounds(self):
        """Enable/disable layout boundary viewer"""
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        device = self.connected_device.get()
        try:
            # Get current state
            result = subprocess.run(
                ["adb", "-s", device, "shell", "getprop", "debug.layout"],
                capture_output=True, text=True
            )
            current_state = result.stdout.strip()
            
            # Toggle state
            new_state = "false" if current_state == "true" else "true"
            subprocess.run(
                ["adb", "-s", device, "shell", "setprop", "debug.layout", new_state],
                check=True
            )
            
            # Force refresh
            subprocess.run(
                ["adb", "-s", device, "shell", "service call activity 1599295570"],
                check=True
            )
            
            state_text = "enabled" if new_state == "true" else "disabled"
            messagebox.showinfo("Success", f"Layout bounds {state_text}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def show_ui_automator(self):
        """Launch UI Automator Viewer"""
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        try:
            # Take a UI hierarchy snapshot
            device = self.connected_device.get()
            subprocess.run(
                ["adb", "-s", device, "shell", "uiautomator", "dump", "/sdcard/window_dump.xml"],
                check=True
            )
            
            # Pull the dump file
            save_path = filedialog.asksaveasfilename(
                title="Save UI Hierarchy As",
                defaultextension=".xml",
                filetypes=[("XML Files", "*.xml"), ("All Files", "*.*")]
            )
            if not save_path:
                return
                
            subprocess.run(
                ["adb", "-s", device, "pull", "/sdcard/window_dump.xml", save_path],
                check=True
            )
            
            # Clean up
            subprocess.run(
                ["adb", "-s", device, "shell", "rm", "/sdcard/window_dump.xml"],
                check=True
            )
            
            messagebox.showinfo("Success", f"UI hierarchy saved to {save_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def show_system_properties(self):
        """Show system property viewer/editor"""
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        # Create system properties window
        props_window = tk.Toplevel(self.root)
        props_window.title("System Properties")
        props_window.geometry("800x600")
        props_window.transient(self.root)
        
        # Main frame
        main_frame = ttk.Frame(props_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Filter frame
        filter_frame = ttk.Frame(main_frame)
        filter_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=5)
        filter_var = tk.StringVar()
        filter_entry = ttk.Entry(filter_frame, textvariable=filter_var)
        filter_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Properties list
        list_frame = ttk.Frame(main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ("Property", "Value")
        props_tree = ttk.Treeview(list_frame, columns=columns, show="headings")
        
        for col in columns:
            props_tree.heading(col, text=col)
            props_tree.column(col, width=300)
        
        props_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Scrollbar
        props_scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=props_tree.yview)
        props_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        props_tree.configure(yscrollcommand=props_scroll.set)
        
        def load_properties():
            device = self.connected_device.get()
            filter_text = filter_var.get().lower()
            
            try:
                # Clear previous entries
                props_tree.delete(*props_tree.get_children())
                
                # Get all properties
                result = subprocess.run(
                    ["adb", "-s", device, "shell", "getprop"],
                    capture_output=True, text=True
                )
                
                for line in result.stdout.split('\n'):
                    if line.strip():
                        # Parse property line [prop]: [value]
                        match = re.match(r'\[([^\]]+)\]:\s*\[([^\]]*)\]', line)
                        if match:
                            prop = match.group(1)
                            value = match.group(2)
                            
                            # Apply filter
                            if filter_text and filter_text not in prop.lower():
                                continue
                                
                            props_tree.insert("", tk.END, values=(prop, value))
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load properties: {str(e)}")
        
        def edit_property():
            selected = props_tree.selection()
            if not selected:
                messagebox.showwarning("Warning", "Please select a property")
                return
                
            item = props_tree.item(selected[0])
            prop = item['values'][0]
            current_value = item['values'][1]
            
            new_value = simpledialog.askstring(
                "Edit Property",
                f"Enter new value for {prop}:",
                initialvalue=current_value
            )
            
            if new_value is not None:
                device = self.connected_device.get()
                try:
                    subprocess.run(
                        ["adb", "-s", device, "shell", "setprop", prop, new_value],
                        check=True
                    )
                    load_properties()
                    messagebox.showinfo("Success", f"Property {prop} updated")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to update property: {str(e)}")
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(buttons_frame, text="Refresh", 
                   command=load_properties).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Edit Selected", 
                   command=edit_property).pack(side=tk.LEFT, padx=5)
        
        # Apply filter on input
        filter_var.trace('w', lambda *args: load_properties())
        
        # Initial load
        load_properties()
    
    def show_database_explorer(self):
        """Show database explorer for app databases"""
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        # Create database explorer window
        db_window = tk.Toplevel(self.root)
        db_window.title("Database Explorer")
        db_window.geometry("1000x700")
        db_window.transient(self.root)
        
        # Main frame
        main_frame = ttk.Frame(db_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Package selection frame
        package_frame = ttk.LabelFrame(main_frame, text="Select App", padding="10")
        package_frame.pack(fill=tk.X, pady=(0, 10))
        
        package_var = tk.StringVar()
        ttk.Entry(package_frame, textvariable=package_var, width=50).pack(side=tk.LEFT, padx=5)
        ttk.Button(package_frame, text="Browse", 
                   command=lambda: package_var.set(self._select_installed_package())).pack(side=tk.LEFT, padx=5)
        
        # Database list frame
        list_frame = ttk.LabelFrame(main_frame, text="Databases", padding="10")
        list_frame.pack(fill=tk.X, pady=(0, 10))
        
        db_listbox = tk.Listbox(list_frame, height=5)
        db_listbox.pack(fill=tk.X)
        
        # Query frame
        query_frame = ttk.LabelFrame(main_frame, text="SQL Query", padding="10")
        query_frame.pack(fill=tk.X, pady=(0, 10))
        
        query_text = scrolledtext.ScrolledText(query_frame, height=5)
        query_text.pack(fill=tk.X)
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        results_tree = ttk.Treeview(results_frame)
        results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        results_scroll = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=results_tree.yview)
        results_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        results_tree.configure(yscrollcommand=results_scroll.set)
        
        def list_databases():
            package = package_var.get().strip()
            if not package:
                messagebox.showwarning("Warning", "Please select an app")
                return
                
            device = self.connected_device.get()
            try:
                # Clear previous entries
                db_listbox.delete(0, tk.END)
                
                # List databases in package's data directory
                result = subprocess.run(
                    ["adb", "-s", device, "shell", f"run-as {package} ls databases/"],
                    capture_output=True, text=True
                )
                
                for line in result.stdout.split('\n'):
                    if line.strip() and line.endswith('.db'):
                        db_listbox.insert(tk.END, line.strip())
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to list databases: {str(e)}")
        
        def execute_query():
            if not db_listbox.curselection():
                messagebox.showwarning("Warning", "Please select a database")
                return
                
            package = package_var.get().strip()
            db_name = db_listbox.get(db_listbox.curselection()[0])
            query = query_text.get("1.0", tk.END).strip()
            
            if not query:
                messagebox.showwarning("Warning", "Please enter a query")
                return
                
            device = self.connected_device.get()
            try:
                # Execute query using sqlite3
                cmd = f"run-as {package} sqlite3 databases/{db_name} '{query}'"
                result = subprocess.run(
                    ["adb", "-s", device, "shell", cmd],
                    capture_output=True, text=True
                )
                
                # Clear previous results
                for col in results_tree["columns"]:
                    results_tree.heading(col, text="")
                results_tree["columns"] = ()
                results_tree.delete(*results_tree.get_children())
                
                # Parse results
                rows = [line.split('|') for line in result.stdout.split('\n') if line.strip()]
                if rows:
                    # Set up columns (assuming first row is data)
                    num_cols = len(rows[0])
                    cols = tuple([f"Column {i+1}" for i in range(num_cols)])
                    results_tree["columns"] = cols
                    
                    for i, col in enumerate(cols):
                        results_tree.heading(col, text=col)
                        results_tree.column(col, width=100)
                    
                    # Add rows
                    for row in rows:
                        results_tree.insert("", tk.END, values=row)
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to execute query: {str(e)}")
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(buttons_frame, text="List Databases", 
                   command=list_databases).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Execute Query", 
                   command=execute_query).pack(side=tk.LEFT, padx=5)
    
    def show_shared_prefs(self):
        """Show shared preferences viewer/editor"""
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        # Create shared preferences window
        prefs_window = tk.Toplevel(self.root)
        prefs_window.title("Shared Preferences")
        prefs_window.geometry("800x600")
        prefs_window.transient(self.root)
        
        # Main frame
        main_frame = ttk.Frame(prefs_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Package selection frame
        package_frame = ttk.LabelFrame(main_frame, text="Select App", padding="10")
        package_frame.pack(fill=tk.X, pady=(0, 10))
        
        package_var = tk.StringVar()
        ttk.Entry(package_frame, textvariable=package_var, width=50).pack(side=tk.LEFT, padx=5)
        ttk.Button(package_frame, text="Browse", 
                   command=lambda: package_var.set(self._select_installed_package())).pack(side=tk.LEFT, padx=5)
        
        # Preferences file list
        list_frame = ttk.LabelFrame(main_frame, text="Preference Files", padding="10")
        list_frame.pack(fill=tk.X, pady=(0, 10))
        
        pref_listbox = tk.Listbox(list_frame, height=5)
        pref_listbox.pack(fill=tk.X)
        
        # Preferences content
        content_frame = ttk.LabelFrame(main_frame, text="Preferences", padding="10")
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ("Key", "Value", "Type")
        prefs_tree = ttk.Treeview(content_frame, columns=columns, show="headings")
        
        for col in columns:
            prefs_tree.heading(col, text=col)
            if col == "Key":
                prefs_tree.column(col, width=200)
            else:
                prefs_tree.column(col, width=150)
        
        prefs_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        prefs_scroll = ttk.Scrollbar(content_frame, orient=tk.VERTICAL, command=prefs_tree.yview)
        prefs_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        prefs_tree.configure(yscrollcommand=prefs_scroll.set)
        
        def list_pref_files():
            package = package_var.get().strip()
            if not package:
                messagebox.showwarning("Warning", "Please select an app")
                return
                
            device = self.connected_device.get()
            try:
                # Clear previous entries
                pref_listbox.delete(0, tk.END)
                
                # List shared_prefs directory
                result = subprocess.run(
                    ["adb", "-s", device, "shell", f"run-as {package} ls shared_prefs/"],
                    capture_output=True, text=True
                )
                
                for line in result.stdout.split('\n'):
                    if line.strip() and line.endswith('.xml'):
                        pref_listbox.insert(tk.END, line.strip())
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to list preference files: {str(e)}")
        
        def load_preferences():
            if not pref_listbox.curselection():
                messagebox.showwarning("Warning", "Please select a preferences file")
                return
                
            package = package_var.get().strip()
            pref_file = pref_listbox.get(pref_listbox.curselection()[0])
            
            device = self.connected_device.get()
            try:
                # Clear previous entries
                prefs_tree.delete(*prefs_tree.get_children())
                
                # Get preferences content
                result = subprocess.run(
                    ["adb", "-s", device, "shell", f"run-as {package} cat shared_prefs/{pref_file}"],
                    capture_output=True, text=True
                )
                
                # Parse XML
                import xml.etree.ElementTree as ET
                root = ET.fromstring(result.stdout)
                
                # Add entries
                for child in root:
                    key = child.get('name', '')
                    value = child.text or ''
                    type_name = child.tag
                    prefs_tree.insert("", tk.END, values=(key, value, type_name))
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load preferences: {str(e)}")
        
        def edit_preference():
            selected = prefs_tree.selection()
            if not selected or not pref_listbox.curselection():
                messagebox.showwarning("Warning", "Please select a preference")
                return
                
            item = prefs_tree.item(selected[0])
            key = item['values'][0]
            current_value = item['values'][1]
            pref_type = item['values'][2]
            
            new_value = simpledialog.askstring(
                "Edit Preference",
                f"Enter new value for {key}:",
                initialvalue=current_value
            )
            
            if new_value is not None:
                package = package_var.get().strip()
                pref_file = pref_listbox.get(pref_listbox.curselection()[0])
                
                try:
                    device = self.connected_device.get()
                    # Create a temporary file with the edited value
                    temp_file = f"/data/local/tmp/{package}_prefs_temp.xml"
                    
                    # Read current preferences
                    result = subprocess.run(
                        ["adb", "-s", device, "shell", f"run-as {package} cat shared_prefs/{pref_file}"],
                        capture_output=True, text=True
                    )
                    
                    # Parse and modify XML
                    import xml.etree.ElementTree as ET
                    root = ET.fromstring(result.stdout)
                    
                    for elem in root.findall(f".//{pref_type}[@name='{key}']"):
                        elem.text = new_value
                    
                    # Write modified XML
                    xml_str = ET.tostring(root, encoding='utf-8', method='xml')
                    with open("temp_prefs.xml", "wb") as f:
                        f.write(xml_str)
                    
                    # Push modified file
                    subprocess.run(
                        ["adb", "-s", device, "push", "temp_prefs.xml", temp_file],
                        check=True
                    )
                    
                    # Replace original file
                    subprocess.run(
                        ["adb", "-s", device, "shell", f"run-as {package} cp {temp_file} shared_prefs/{pref_file}"],
                        check=True
                    )
                    
                    # Clean up
                    os.remove("temp_prefs.xml")
                    subprocess.run(
                        ["adb", "-s", device, "shell", f"rm {temp_file}"],
                        check=True
                    )
                    
                    load_preferences()
                    messagebox.showinfo("Success", f"Preference {key} updated")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to update preference: {str(e)}")
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(buttons_frame, text="List Files", 
                   command=list_pref_files).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Load Preferences", 
                   command=load_preferences).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Edit Selected", 
                   command=edit_preference).pack(side=tk.LEFT, padx=5)
    
    def show_activity_stack(self):
        """Show activity stack viewer"""
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
            
        # Create activity stack window
        stack_window = tk.Toplevel(self.root)
        stack_window.title("Activity Stack")
        stack_window.geometry("800x600")
        stack_window.transient(self.root)
        
        # Main frame
        main_frame = ttk.Frame(stack_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Stack view
        list_frame = ttk.LabelFrame(main_frame, text="Activity Stack", padding="10")
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ("Task", "Activity", "State")
        stack_tree = ttk.Treeview(list_frame, columns=columns, show="headings")
        
        for col in columns:
            stack_tree.heading(col, text=col)
            stack_tree.column(col, width=200)
        
        stack_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        stack_scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=stack_tree.yview)
        stack_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        stack_tree.configure(yscrollcommand=stack_scroll.set)
        
        def refresh_stack():
            device = self.connected_device.get()
            try:
                # Clear previous entries
                stack_tree.delete(*stack_tree.get_children())
                
                # Get activity stack
                result = subprocess.run(
                    ["adb", "-s", device, "shell", "dumpsys", "activity", "activities"],
                    capture_output=True, text=True
                )
                
                current_task = ""
                for line in result.stdout.split('\n'):
                    # Parse task
                    task_match = re.search(r'TaskRecord{[^}]*} #\d+ [A-Za-z=]* ([\w.]+)', line)
                    if task_match:
                        current_task = task_match.group(1)
                        continue
                    
                    # Parse activity
                    activity_match = re.search(r'\* Hist #\d+: ActivityRecord{[^}]*} ([\w.]+/[\w.]+)', line)
                    if activity_match and current_task:
                        activity = activity_match.group(1)
                        state = "Active" if "*" in line else "Background"
                        stack_tree.insert("", 0, values=(current_task, activity, state))
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to get activity stack: {str(e)}")
        
        def kill_activity():
            selected = stack_tree.selection()
            if not selected:
                messagebox.showwarning("Warning", "Please select an activity")
                return
                
            item = stack_tree.item(selected[0])
            activity = item['values'][1]
            
            if messagebox.askyesno("Confirm", f"Force stop {activity}?"):
                device = self.connected_device.get()
                try:
                    package = activity.split('/')[0]
                    subprocess.run(
                        ["adb", "-s", device, "shell", "am", "force-stop", package],
                        check=True
                    )
                    refresh_stack()
                    messagebox.showinfo("Success", f"Stopped {activity}")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to stop activity: {str(e)}")
        
        # Auto-refresh
        def auto_refresh():
            if stack_window.winfo_exists():
                refresh_stack()
                stack_window.after(2000, auto_refresh)
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(buttons_frame, text="Refresh Now", 
                   command=refresh_stack).pack(side=tk.LEFT, padx=5)
        ttk.Button(buttons_frame, text="Kill Selected", 
                   command=kill_activity).pack(side=tk.LEFT, padx=5)
        
        # Start auto-refresh
        auto_refresh()

    def _select_installed_package(self) -> str:
        """Show a dialog to select an installed package"""
        device = self.connected_device.get()
        result = subprocess.run(
            ["adb", "-s", device, "shell", "pm list packages -3"],
            capture_output=True, text=True
        )
        
        packages = [line.split(":")[-1].strip() for line in result.stdout.split('\n') if line.strip()]
        
        if not packages:
            messagebox.showwarning("Warning", "No installed packages found")
            return ""
        
        # Create package selection dialog
        select_window = tk.Toplevel(self.root)
        select_window.title("Select Package")
        select_window.geometry("400x500")
        select_window.transient(self.root)
        
        # Main frame
        main_frame = ttk.Frame(select_window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Filter
        filter_var = tk.StringVar()
        filter_entry = ttk.Entry(main_frame, textvariable=filter_var)
        filter_entry.pack(fill=tk.X, pady=(0, 10))
        
        # Package list
        package_list = tk.Listbox(main_frame)
        package_list.pack(fill=tk.BOTH, expand=True)
        
        selected_package = ['']  # Use list to store value from dialog
        
        def filter_packages():
            filter_text = filter_var.get().lower()
            package_list.delete(0, tk.END)
            for package in packages:
                if filter_text in package.lower():
                    package_list.insert(tk.END, package)
        
        def on_select():
            selection = package_list.curselection()
            if selection:
                selected_package[0] = package_list.get(selection[0])
                select_window.destroy()
        
        # Apply filter on input
        filter_var.trace('w', lambda *args: filter_packages())
        
        # Select button
        ttk.Button(main_frame, text="Select", command=on_select).pack(pady=10)
        
        # Initial package list
        filter_packages()
        
        # Wait for dialog
        select_window.wait_window()
        
        return selected_package[0]

    def show_network_advanced(self):
        """Show advanced network tools with proper integration"""
        adv_network_tool = adv_network.ADBGuiTool(self.root)
        adv_network_tool.adb_available = self.adb_available
        adv_network_tool.connected_device = self.connected_device
        adv_network_tool.show_network_advanced()

def main():
    root = tk.Tk()
    app = ADBGuiTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()