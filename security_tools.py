import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import subprocess
import threading
import re

class SecurityTools:
    def __init__(self, root, adb_available, connected_device):
        self.root = root
        self.adb_available = adb_available
        self.connected_device = connected_device

    def show_signature_verification(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
        win = tk.Toplevel(self.root)
        win.title("Package Signature Verification")
        win.geometry("600x400")
        win.transient(self.root)
        ttk.Label(win, text="Enter package name:").pack(pady=5)
        pkg_var = tk.StringVar()
        ttk.Entry(win, textvariable=pkg_var).pack(fill=tk.X, padx=20)
        output = scrolledtext.ScrolledText(win, height=15)
        output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        def verify():
            package = pkg_var.get().strip()
            if not package:
                messagebox.showwarning("Warning", "Please enter a package name")
                return
            device = self.connected_device.get()
            try:
                # Get APK path
                result = subprocess.run([
                    "adb", "-s", device, "shell", f"pm path {package}"
                ], capture_output=True, text=True)
                apk_path = ""
                for line in result.stdout.split('\n'):
                    if line.startswith("package:"):
                        apk_path = line.split(":", 1)[1].strip()
                        break
                if not apk_path:
                    output.insert(tk.END, "Could not find APK path.\n")
                    return
                # Pull APK
                local_apk = f"{package}.apk"
                subprocess.run([
                    "adb", "-s", device, "pull", apk_path, local_apk
                ], capture_output=True, text=True)
                # Get signature info using keytool (if available)
                try:
                    sig_result = subprocess.run([
                        "keytool", "-printcert", "-jarfile", local_apk
                    ], capture_output=True, text=True)
                    output.insert(tk.END, sig_result.stdout or sig_result.stderr)
                except Exception as e:
                    output.insert(tk.END, f"Error running keytool: {e}\n")
                # Clean up
                try:
                    import os
                    os.remove(local_apk)
                except Exception:
                    pass
            except Exception as e:
                output.insert(tk.END, f"Error: {e}\n")
        ttk.Button(win, text="Verify", command=verify).pack(pady=5)

    def show_permission_analyzer(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
        win = tk.Toplevel(self.root)
        win.title("Permission Analyzer")
        win.geometry("600x400")
        win.transient(self.root)
        ttk.Label(win, text="Enter package name:").pack(pady=5)
        pkg_var = tk.StringVar()
        ttk.Entry(win, textvariable=pkg_var).pack(fill=tk.X, padx=20)
        output = scrolledtext.ScrolledText(win, height=15)
        output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        def analyze():
            package = pkg_var.get().strip()
            if not package:
                messagebox.showwarning("Warning", "Please enter a package name")
                return
            device = self.connected_device.get()
            try:
                result = subprocess.run([
                    "adb", "-s", device, "shell", f"dumpsys package {package}"
                ], capture_output=True, text=True)
                perms = re.findall(r'grantedPermissions:\\n((?:\s+\S+\n)+)', result.stdout)
                if perms:
                    output.insert(tk.END, "Granted Permissions:\n" + perms[0])
                else:
                    output.insert(tk.END, "No granted permissions found.\n")
            except Exception as e:
                output.insert(tk.END, f"Error: {e}\n")
        ttk.Button(win, text="Analyze", command=analyze).pack(pady=5)

    def show_security_settings(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
        win = tk.Toplevel(self.root)
        win.title("Security Settings Viewer")
        win.geometry("600x400")
        win.transient(self.root)
        output = scrolledtext.ScrolledText(win, height=20)
        output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        def load_settings():
            device = self.connected_device.get()
            try:
                result = subprocess.run([
                    "adb", "-s", device, "shell", "settings list secure"
                ], capture_output=True, text=True)
                output.delete(1.0, tk.END)
                output.insert(tk.END, result.stdout)
            except Exception as e:
                output.insert(tk.END, f"Error: {e}\n")
        ttk.Button(win, text="Load Security Settings", command=load_settings).pack(pady=5)
        load_settings()

    def show_certificate_manager(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
        win = tk.Toplevel(self.root)
        win.title("Certificate Manager")
        win.geometry("700x500")
        win.transient(self.root)
        output = scrolledtext.ScrolledText(win, height=25)
        output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        def list_certs():
            device = self.connected_device.get()
            try:
                # List user certificates (Android 7+)
                result = subprocess.run([
                    "adb", "-s", device, "shell", "ls /data/misc/user/0/cacerts-added/"
                ], capture_output=True, text=True)
                output.delete(1.0, tk.END)
                output.insert(tk.END, "User Certificates (cacerts-added):\n" + result.stdout)
                # List system certificates
                result2 = subprocess.run([
                    "adb", "-s", device, "shell", "ls /system/etc/security/cacerts/"
                ], capture_output=True, text=True)
                output.insert(tk.END, "\nSystem Certificates (cacerts):\n" + result2.stdout)
            except Exception as e:
                output.insert(tk.END, f"Error: {e}\n")
        ttk.Button(win, text="List Certificates", command=list_certs).pack(pady=5)
        list_certs()
