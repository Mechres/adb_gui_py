import os
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog, scrolledtext
import time

class TestingTools:
    def __init__(self, root, adb_available, connected_device):
        self.root = root
        self.adb_available = adb_available
        self.connected_device = connected_device

    def show_monkey_test(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
        # Dialog for package and event count
        win = tk.Toplevel(self.root)
        win.title("Monkey Test Runner")
        win.geometry("400x200")
        win.transient(self.root)
        win.grab_set()
        ttk.Label(win, text="Package Name:").pack(pady=5)
        pkg_var = tk.StringVar()
        ttk.Entry(win, textvariable=pkg_var).pack(fill=tk.X, padx=20)
        ttk.Label(win, text="Event Count:").pack(pady=5)
        count_var = tk.StringVar(value="1000")
        ttk.Entry(win, textvariable=count_var).pack(fill=tk.X, padx=20)
        output = scrolledtext.ScrolledText(win, height=6)
        output.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        def run_monkey():
            pkg = pkg_var.get().strip()
            try:
                count = int(count_var.get())
            except ValueError:
                messagebox.showerror("Error", "Invalid event count")
                return
            if not pkg or count <= 0:
                messagebox.showerror("Error", "Enter valid package and count")
                return
            win.grab_release()
            win.destroy()
            threading.Thread(target=self._run_monkey_thread, args=(pkg, count), daemon=True).start()
        ttk.Button(win, text="Run", command=run_monkey).pack(pady=10)
    def _run_monkey_thread(self, pkg, count):
        device = self.connected_device.get()
        cmd = ["adb", "-s", device, "shell", "monkey", "-p", pkg, "-v", str(count)]
        result = subprocess.run(cmd, capture_output=True, text=True)
        self._show_output_window("Monkey Test Output", result.stdout + "\n" + result.stderr)

    def show_ui_exerciser(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
        win = tk.Toplevel(self.root)
        win.title("UI/Application Exerciser")
        win.geometry("400x200")
        win.transient(self.root)
        win.grab_set()
        ttk.Label(win, text="Package Name:").pack(pady=5)
        pkg_var = tk.StringVar()
        ttk.Entry(win, textvariable=pkg_var).pack(fill=tk.X, padx=20)
        ttk.Label(win, text="Duration (seconds):").pack(pady=5)
        dur_var = tk.StringVar(value="30")
        ttk.Entry(win, textvariable=dur_var).pack(fill=tk.X, padx=20)
        output = scrolledtext.ScrolledText(win, height=6)
        output.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        def run_exerciser():
            pkg = pkg_var.get().strip()
            try:
                dur = int(dur_var.get())
            except ValueError:
                messagebox.showerror("Error", "Invalid duration")
                return
            if not pkg or dur <= 0:
                messagebox.showerror("Error", "Enter valid package and duration")
                return
            win.grab_release()
            win.destroy()
            threading.Thread(target=self._run_exerciser_thread, args=(pkg, dur), daemon=True).start()
        ttk.Button(win, text="Run", command=run_exerciser).pack(pady=10)
    def _run_exerciser_thread(self, pkg, dur):
        device = self.connected_device.get()
        # Use monkey with throttle for duration
        cmd = ["adb", "-s", device, "shell", "monkey", "-p", pkg, "--throttle", "500", "-v", str(dur*2)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=dur+10)
        self._show_output_window("UI Exerciser Output", result.stdout + "\n" + result.stderr)

    def show_touch_recorder(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
        win = tk.Toplevel(self.root)
        win.title("Touch Event Recorder/Player")
        win.geometry("400x250")
        win.transient(self.root)
        win.grab_set()
        ttk.Label(win, text="Record or Play Touch Events").pack(pady=5)
        file_var = tk.StringVar(value="/sdcard/touch_record.txt")
        ttk.Label(win, text="File on device:").pack()
        ttk.Entry(win, textvariable=file_var).pack(fill=tk.X, padx=20)
        output = scrolledtext.ScrolledText(win, height=6)
        output.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        def record():
            win.grab_release()
            win.destroy()
            threading.Thread(target=self._record_touch_thread, args=(file_var.get(),), daemon=True).start()
        def play():
            win.grab_release()
            win.destroy()
            threading.Thread(target=self._play_touch_thread, args=(file_var.get(),), daemon=True).start()
        btn_frame = ttk.Frame(win)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Record", command=record).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Play", command=play).pack(side=tk.LEFT, padx=10)
    def _record_touch_thread(self, file_path):
        device = self.connected_device.get()
        # Use getevent to record
        cmd = ["adb", "-s", device, "shell", f"getevent -t > {file_path}"]
        # User must stop manually (Ctrl+C), so show info
        self._show_output_window("Touch Recorder", "Recording started. Stop manually in terminal or kill process. File: " + file_path)
        # Optionally, could launch a terminal for this
    def _play_touch_thread(self, file_path):
        device = self.connected_device.get()
        # Use sendevent to play (requires script conversion)
        # For demo, just cat file
        cmd = ["adb", "-s", device, "shell", f"cat {file_path}"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        self._show_output_window("Touch Player Output", result.stdout + "\n" + result.stderr)

    def show_network_simulator(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return
        win = tk.Toplevel(self.root)
        win.title("Network Condition Simulator")
        win.geometry("400x250")
        win.transient(self.root)
        win.grab_set()
        ttk.Label(win, text="Simulate Network Conditions").pack(pady=5)
        ttk.Label(win, text="Type:").pack()
        type_var = tk.StringVar(value="none")
        types = ["none", "gsm", "edge", "umts", "lte", "hspa", "hsdpa", "evdo", "1xrtt", "gprs", "hspap", "lte_ca", "nr"]
        ttk.Combobox(win, textvariable=type_var, values=types, state="readonly").pack(fill=tk.X, padx=20)
        ttk.Label(win, text="Delay (ms):").pack()
        delay_var = tk.StringVar(value="0")
        ttk.Entry(win, textvariable=delay_var).pack(fill=tk.X, padx=20)
        ttk.Label(win, text="Loss (%):").pack()
        loss_var = tk.StringVar(value="0")
        ttk.Entry(win, textvariable=loss_var).pack(fill=tk.X, padx=20)
        def apply():
            try:
                delay = int(delay_var.get())
                loss = int(loss_var.get())
            except ValueError:
                messagebox.showerror("Error", "Invalid delay or loss")
                return
            win.grab_release()
            win.destroy()
            threading.Thread(target=self._network_sim_thread, args=(type_var.get(), delay, loss), daemon=True).start()
        ttk.Button(win, text="Apply", command=apply).pack(pady=10)
    def _network_sim_thread(self, net_type, delay, loss):
        device = self.connected_device.get()
        cmds = []
        # Set network type
        if net_type != "none":
            cmds.append(["adb", "-s", device, "shell", f"svc data disable; svc data enable; setprop gsm.network.type {net_type}"])
        # Set delay and loss using tc (if available)
        if delay > 0 or loss > 0:
            tc_cmd = f"tc qdisc add dev rmnet0 root netem"
            if delay > 0:
                tc_cmd += f" delay {delay}ms"
            if loss > 0:
                tc_cmd += f" loss {loss}%"
            cmds.append(["adb", "-s", device, "shell", tc_cmd])
        output = ""
        for cmd in cmds:
            result = subprocess.run(cmd, capture_output=True, text=True)
            output += result.stdout + "\n" + result.stderr
        self._show_output_window("Network Simulator Output", output)

    def _show_output_window(self, title, text):
        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry("700x400")
        scrolled = scrolledtext.ScrolledText(win, wrap=tk.WORD)
        scrolled.pack(fill=tk.BOTH, expand=True)
        scrolled.insert(tk.END, text)
        scrolled.config(state=tk.DISABLED)
        ttk.Button(win, text="Close", command=win.destroy).pack(pady=10)
