import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import subprocess
import re

def show_cpu_profiler(root, adb_available, connected_device):
    if not adb_available or not connected_device.get():
        messagebox.showwarning("Warning", "No device selected or ADB not available")
        return
    win = tk.Toplevel(root)
    win.title("CPU Profiler")
    win.geometry("700x500")
    frame = ttk.Frame(win, padding="10")
    frame.pack(fill=tk.BOTH, expand=True)
    text = scrolledtext.ScrolledText(frame, height=25)
    text.pack(fill=tk.BOTH, expand=True)
    text.config(state=tk.DISABLED)
    def run_cpu_profiler():
        device = connected_device.get()
        try:
            result = subprocess.run(["adb", "-s", device, "shell", "top -n 1"], capture_output=True, text=True)
            text.config(state=tk.NORMAL)
            text.delete(1.0, tk.END)
            text.insert(tk.END, result.stdout)
            text.config(state=tk.DISABLED)
        except Exception as e:
            text.config(state=tk.NORMAL)
            text.insert(tk.END, f"Error: {str(e)}")
            text.config(state=tk.DISABLED)
    threading.Thread(target=run_cpu_profiler, daemon=True).start()

def show_memory_analyzer(root, adb_available, connected_device):
    if not adb_available or not connected_device.get():
        messagebox.showwarning("Warning", "No device selected or ADB not available")
        return
    win = tk.Toplevel(root)
    win.title("Memory Analyzer")
    win.geometry("700x500")
    frame = ttk.Frame(win, padding="10")
    frame.pack(fill=tk.BOTH, expand=True)
    text = scrolledtext.ScrolledText(frame, height=25)
    text.pack(fill=tk.BOTH, expand=True)
    text.config(state=tk.DISABLED)
    def run_memory_analyzer():
        device = connected_device.get()
        try:
            result = subprocess.run(["adb", "-s", device, "shell", "cat /proc/meminfo"], capture_output=True, text=True)
            text.config(state=tk.NORMAL)
            text.delete(1.0, tk.END)
            text.insert(tk.END, result.stdout)
            text.config(state=tk.DISABLED)
        except Exception as e:
            text.config(state=tk.NORMAL)
            text.insert(tk.END, f"Error: {str(e)}")
            text.config(state=tk.DISABLED)
    threading.Thread(target=run_memory_analyzer, daemon=True).start()

def show_battery_usage(root, adb_available, connected_device):
    if not adb_available or not connected_device.get():
        messagebox.showwarning("Warning", "No device selected or ADB not available")
        return
    win = tk.Toplevel(root)
    win.title("Battery Usage by App")
    win.geometry("700x500")
    frame = ttk.Frame(win, padding="10")
    frame.pack(fill=tk.BOTH, expand=True)
    text = scrolledtext.ScrolledText(frame, height=25)
    text.pack(fill=tk.BOTH, expand=True)
    text.config(state=tk.DISABLED)
    def run_battery_usage():
        device = connected_device.get()
        try:
            result = subprocess.run(["adb", "-s", device, "shell", "dumpsys batterystats"], capture_output=True, text=True)
            text.config(state=tk.NORMAL)
            text.delete(1.0, tk.END)
            text.insert(tk.END, result.stdout)
            text.config(state=tk.DISABLED)
        except Exception as e:
            text.config(state=tk.NORMAL)
            text.insert(tk.END, f"Error: {str(e)}")
            text.config(state=tk.DISABLED)
    threading.Thread(target=run_battery_usage, daemon=True).start()

def show_wakelocks_viewer(root, adb_available, connected_device):
    if not adb_available or not connected_device.get():
        messagebox.showwarning("Warning", "No device selected or ADB not available")
        return
    win = tk.Toplevel(root)
    win.title("Wakelocks Viewer")
    win.geometry("700x500")
    frame = ttk.Frame(win, padding="10")
    frame.pack(fill=tk.BOTH, expand=True)
    text = scrolledtext.ScrolledText(frame, height=25)
    text.pack(fill=tk.BOTH, expand=True)
    text.config(state=tk.DISABLED)
    def run_wakelocks():
        device = connected_device.get()
        try:
            result = subprocess.run(["adb", "-s", device, "shell", "dumpsys power"], capture_output=True, text=True)
            wakelocks = []
            for line in result.stdout.splitlines():
                if "Wake Locks" in line or "WakeLock" in line or "held" in line:
                    wakelocks.append(line)
            text.config(state=tk.NORMAL)
            text.delete(1.0, tk.END)
            if wakelocks:
                text.insert(tk.END, "\n".join(wakelocks))
            else:
                text.insert(tk.END, result.stdout)
            text.config(state=tk.DISABLED)
        except Exception as e:
            text.config(state=tk.NORMAL)
            text.insert(tk.END, f"Error: {str(e)}")
            text.config(state=tk.DISABLED)
    threading.Thread(target=run_wakelocks, daemon=True).start()

def show_system_logs_aggregator(root, adb_available, connected_device):
    if not adb_available or not connected_device.get():
        messagebox.showwarning("Warning", "No device selected or ADB not available")
        return
    win = tk.Toplevel(root)
    win.title("System Logs Aggregator")
    win.geometry("900x600")
    frame = ttk.Frame(win, padding="10")
    frame.pack(fill=tk.BOTH, expand=True)
    text = scrolledtext.ScrolledText(frame, height=35)
    text.pack(fill=tk.BOTH, expand=True)
    text.config(state=tk.DISABLED)
    def run_logs_aggregator():
        device = connected_device.get()
        try:
            logs = []
            # logcat
            logcat = subprocess.run(["adb", "-s", device, "logcat", "-d", "-v", "time"], capture_output=True, text=True)
            logs.append("=== Logcat ===\n" + (logcat.stdout or ""))
            # dmesg
            dmesg = subprocess.run(["adb", "-s", device, "shell", "dmesg"], capture_output=True, text=True)
            logs.append("\n=== dmesg ===\n" + (dmesg.stdout or ""))
            # last_kmsg (if available)
            last_kmsg = subprocess.run(["adb", "-s", device, "shell", "cat /proc/last_kmsg"], capture_output=True, text=True)
            if last_kmsg.stdout:
                logs.append("\n=== last_kmsg ===\n" + (last_kmsg.stdout or ""))
            # events log
            events = subprocess.run(["adb", "-s", device, "shell", "logcat -b events -d -v time"], capture_output=True, text=True)
            logs.append("\n=== Events Log ===\n" + (events.stdout or ""))
            # radio log
            radio = subprocess.run(["adb", "-s", device, "shell", "logcat -b radio -d -v time"], capture_output=True, text=True)
            logs.append("\n=== Radio Log ===\n" + (radio.stdout or ""))
            text.config(state=tk.NORMAL)
            text.delete(1.0, tk.END)
            text.insert(tk.END, "\n".join(logs))
            text.config(state=tk.DISABLED)
        except Exception as e:
            text.config(state=tk.NORMAL)
            text.insert(tk.END, f"Error: {str(e)}")
            text.config(state=tk.DISABLED)
    threading.Thread(target=run_logs_aggregator, daemon=True).start()
