import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import threading
import re
from typing import List, Tuple, Dict

class AdvancedAppManager:
    def __init__(self, root, adb_available: bool, connected_device: tk.StringVar, status_var: tk.StringVar):
        self.root = root
        self.adb_available = adb_available
        self.connected_device = connected_device
        self.status_var = status_var

    def batch_app_operations(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return

        batch_window = tk.Toplevel(self.root)
        batch_window.title("Batch App Operations")
        batch_window.geometry("800x600")
        batch_window.transient(self.root)

        main_frame = ttk.Frame(batch_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Operation selection
        op_frame = ttk.LabelFrame(main_frame, text="Operation", padding="10")
        op_frame.pack(fill=tk.X, pady=(0, 10))

        op_var = tk.StringVar(value="install")
        ttk.Radiobutton(op_frame, text="Install APKs", variable=op_var, value="install").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(op_frame, text="Uninstall Apps", variable=op_var, value="uninstall").pack(side=tk.LEFT, padx=10)

        # List frame
        list_frame = ttk.Frame(main_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)

        # Items list
        items_list = tk.Listbox(list_frame, selectmode=tk.MULTIPLE)
        items_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=items_list.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        items_list.configure(yscrollcommand=scroll.set)

        def add_items():
            if op_var.get() == "install":
                files = filedialog.askopenfilenames(
                    title="Select APK files",
                    filetypes=[("APK files", "*.apk"), ("All files", "*.*")]
                )
                for file in files:
                    items_list.insert(tk.END, file)
            else:
                package = messagebox.askstring("Add Package", "Enter package name:")
                if package:
                    items_list.insert(tk.END, package)

        def remove_selected():
            selected = items_list.curselection()
            for index in reversed(selected):
                items_list.delete(index)

        def process_batch():
            items = items_list.get(0, tk.END)
            if not items:
                messagebox.showwarning("Warning", "No items selected")
                return

            device = self.connected_device.get()
            success = 0
            failed = 0

            for item in items:
                try:
                    if op_var.get() == "install":
                        result = subprocess.run(
                            ["adb", "-s", device, "install", "-r", item],
                            capture_output=True, text=True, check=True
                        )
                        success += 1
                    else:
                        result = subprocess.run(
                            ["adb", "-s", device, "uninstall", item],
                            capture_output=True, text=True, check=True
                        )
                        success += 1
                except Exception as e:
                    failed += 1

            messagebox.showinfo("Complete", 
                              f"Operation completed\nSuccess: {success}\nFailed: {failed}")

        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(btn_frame, text="Add", command=add_items).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Remove Selected", command=remove_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Process", command=lambda: 
                  threading.Thread(target=process_batch, daemon=True).start()).pack(side=tk.RIGHT, padx=5)

    def apk_version_comparison(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return

        compare_window = tk.Toplevel(self.root)
        compare_window.title("APK Version Comparison")
        compare_window.geometry("800x600")
        compare_window.transient(self.root)

        main_frame = ttk.Frame(compare_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # APK selection frame
        apk_frame = ttk.LabelFrame(main_frame, text="APK Selection", padding="10")
        apk_frame.pack(fill=tk.X, pady=(0, 10))

        installed_var = tk.StringVar()
        local_var = tk.StringVar()

        def select_installed():
            package = self._select_installed_package()
            if package:
                installed_var.set(package)

        def select_local():
            file = filedialog.askopenfilename(
                title="Select APK file",
                filetypes=[("APK files", "*.apk"), ("All files", "*.*")]
            )
            if file:
                local_var.set(file)

        ttk.Label(apk_frame, text="Installed APK:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(apk_frame, textvariable=installed_var, width=50).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(apk_frame, text="Select", command=select_installed).grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(apk_frame, text="Local APK:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        ttk.Entry(apk_frame, textvariable=local_var, width=50).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(apk_frame, text="Browse", command=select_local).grid(row=1, column=2, padx=5, pady=5)

        # Comparison results
        results_frame = ttk.LabelFrame(main_frame, text="Comparison Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("Property", "Installed APK", "Local APK")
        results_tree = ttk.Treeview(results_frame, columns=columns, show="headings")

        for col in columns:
            results_tree.heading(col, text=col)
            results_tree.column(col, width=200)

        results_tree.pack(fill=tk.BOTH, expand=True)

        def compare_apks():
            device = self.connected_device.get()
            installed = installed_var.get()
            local = local_var.get()

            if not installed or not local:
                messagebox.showwarning("Warning", "Please select both APKs")
                return

            results_tree.delete(*results_tree.get_children())

            try:
                # Get installed APK info
                installed_info = self._get_apk_info(device, installed, True)

                # Get local APK info
                local_info = self._get_apk_info(device, local, False)

                # Compare and display results
                for key in ["Package", "Version Name", "Version Code", "Min SDK", "Target SDK", 
                          "Permissions", "Features", "Native Code"]:
                    installed_val = installed_info.get(key, "N/A")
                    local_val = local_info.get(key, "N/A")
                    results_tree.insert("", tk.END, values=(key, installed_val, local_val))

            except Exception as e:
                messagebox.showerror("Error", str(e))

        ttk.Button(main_frame, text="Compare", 
                  command=lambda: threading.Thread(target=compare_apks, daemon=True).start()).pack(pady=10)

    def app_permissions_manager(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return

        perms_window = tk.Toplevel(self.root)
        perms_window.title("App Permissions Manager")
        perms_window.geometry("800x600")
        perms_window.transient(self.root)

        main_frame = ttk.Frame(perms_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # App selection frame
        app_frame = ttk.LabelFrame(main_frame, text="Select App", padding="10")
        app_frame.pack(fill=tk.X, pady=(0, 10))

        package_var = tk.StringVar()
        ttk.Entry(app_frame, textvariable=package_var, width=50).pack(side=tk.LEFT, padx=5)
        ttk.Button(app_frame, text="Select", 
                   command=lambda: package_var.set(self._select_installed_package())).pack(side=tk.LEFT, padx=5)

        # Permissions list
        perms_frame = ttk.LabelFrame(main_frame, text="Permissions", padding="10")
        perms_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("Permission", "Status")
        perms_tree = ttk.Treeview(perms_frame, columns=columns, show="headings")
        for col in columns:
            perms_tree.heading(col, text=col)
            perms_tree.column(col, width=350)

        perms_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll = ttk.Scrollbar(perms_frame, orient=tk.VERTICAL, command=perms_tree.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        perms_tree.configure(yscrollcommand=scroll.set)

        def load_permissions():
            package = package_var.get()
            if not package:
                messagebox.showwarning("Warning", "Please select an app")
                return

            device = self.connected_device.get()
            perms_tree.delete(*perms_tree.get_children())

            try:
                # Get app permissions
                result = subprocess.run(
                    ["adb", "-s", device, "shell", f"dumpsys package {package} | grep permission"],
                    capture_output=True, text=True
                )

                for line in result.stdout.split('\n'):
                    if "permission" in line:
                        perm = line.strip()
                        if "granted=true" in perm:
                            status = "Granted"
                        elif "granted=false" in perm:
                            status = "Denied"
                        else:
                            continue

                        perm_name = re.search(r"android\.permission\.([^:]+)", perm)
                        if perm_name:
                            perms_tree.insert("", tk.END, values=(perm_name.group(1), status))

            except Exception as e:
                messagebox.showerror("Error", str(e))

        def toggle_permission():
            selected = perms_tree.selection()
            if not selected:
                messagebox.showwarning("Warning", "Please select a permission")
                return

            package = package_var.get()
            device = self.connected_device.get()
            
            for item in selected:
                perm = perms_tree.item(item)['values'][0]
                current_status = perms_tree.item(item)['values'][1]
                
                action = "grant" if current_status == "Denied" else "revoke"
                try:
                    subprocess.run(
                        ["adb", "-s", device, "shell", f"pm {action} {package} android.permission.{perm}"],
                        capture_output=True, text=True, check=True
                    )
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to {action} permission: {str(e)}")
                    return

            load_permissions()  # Refresh the list

        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(btn_frame, text="Load Permissions", 
                   command=lambda: threading.Thread(target=load_permissions, daemon=True).start()).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Toggle Selected", command=toggle_permission).pack(side=tk.LEFT, padx=5)

    def bulk_app_manager(self):
        if not self.adb_available or not self.connected_device.get():
            messagebox.showwarning("Warning", "No device selected or ADB not available")
            return

        bulk_window = tk.Toplevel(self.root)
        bulk_window.title("Bulk App Manager")
        bulk_window.geometry("800x600")
        bulk_window.transient(self.root)

        main_frame = ttk.Frame(bulk_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Apps list
        list_frame = ttk.LabelFrame(main_frame, text="Installed Apps", padding="10")
        list_frame.pack(fill=tk.BOTH, expand=True)

        # Filter
        filter_frame = ttk.Frame(list_frame)
        filter_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=5)
        filter_var = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=filter_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        show_system_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(filter_frame, text="Show System Apps", 
                       variable=show_system_var, command=lambda: refresh_apps()).pack(side=tk.RIGHT, padx=5)

        # Apps list
        columns = ("Package", "App Name", "Size")
        apps_tree = ttk.Treeview(list_frame, columns=columns, show="headings", selectmode="extended")
        for col in columns:
            apps_tree.heading(col, text=col)
            apps_tree.column(col, width=200)

        apps_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=apps_tree.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        apps_tree.configure(yscrollcommand=scroll.set)

        def refresh_apps():
            device = self.connected_device.get()
            filter_text = filter_var.get().lower()
            show_system = show_system_var.get()

            try:
                apps_tree.delete(*apps_tree.get_children())

                # Get list of packages
                if show_system:
                    cmd = ["adb", "-s", device, "shell", "pm list packages -f"]
                else:
                    cmd = ["adb", "-s", device, "shell", "pm list packages -f -3"]

                result = subprocess.run(cmd, capture_output=True, text=True)
                
                for line in result.stdout.split('\n'):
                    if not line.strip():
                        continue

                    # Parse package info
                    path_pkg = line.split(":")[-1].strip()
                    path = path_pkg[:path_pkg.rindex("=")]
                    package = path_pkg[path_pkg.rindex("=")+1:]

                    if filter_text and filter_text not in package.lower():
                        continue

                    # Get app name using aapt
                    try:
                        name_cmd = f"aapt dump badging {path} | grep application-label:"
                        name_result = subprocess.run(
                            ["adb", "-s", device, "shell", name_cmd],
                            capture_output=True, text=True
                        )
                        app_name = package
                        if name_result.stdout:
                            name_match = re.search(r"'([^']+)'", name_result.stdout)
                            if name_match:
                                app_name = name_match.group(1)
                    except:
                        app_name = package

                    # Get app size
                    try:
                        size_cmd = f"du -sh /data/data/{package}"
                        size_result = subprocess.run(
                            ["adb", "-s", device, "shell", size_cmd],
                            capture_output=True, text=True
                        )
                        size = size_result.stdout.split()[0] if size_result.stdout else "N/A"
                    except:
                        size = "N/A"

                    apps_tree.insert("", tk.END, values=(package, app_name, size))

            except Exception as e:
                messagebox.showerror("Error", f"Failed to get app list: {str(e)}")

        def force_stop_selected():
            selected = apps_tree.selection()
            if not selected:
                messagebox.showwarning("Warning", "Please select apps")
                return

            if not messagebox.askyesno("Confirm", "Force stop selected apps?"):
                return

            device = self.connected_device.get()
            success = 0
            failed = 0

            for item in selected:
                package = apps_tree.item(item)['values'][0]
                try:
                    subprocess.run(
                        ["adb", "-s", device, "shell", f"am force-stop {package}"],
                        capture_output=True, text=True, check=True
                    )
                    success += 1
                except:
                    failed += 1

            messagebox.showinfo("Complete", 
                              f"Force stopped {success} app(s)\nFailed: {failed}")

        def clear_data_selected():
            selected = apps_tree.selection()
            if not selected:
                messagebox.showwarning("Warning", "Please select apps")
                return

            if not messagebox.askyesno("Confirm", "Clear data for selected apps?"):
                return

            device = self.connected_device.get()
            success = 0
            failed = 0

            for item in selected:
                package = apps_tree.item(item)['values'][0]
                try:
                    subprocess.run(
                        ["adb", "-s", device, "shell", f"pm clear {package}"],
                        capture_output=True, text=True, check=True
                    )
                    success += 1
                except:
                    failed += 1

            messagebox.showinfo("Complete", 
                              f"Cleared data for {success} app(s)\nFailed: {failed}")
            refresh_apps()

        # Filter on input
        filter_var.trace('w', lambda *args: refresh_apps())

        # Buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(btn_frame, text="Refresh", 
                   command=lambda: threading.Thread(target=refresh_apps, daemon=True).start()).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Force Stop Selected", command=force_stop_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Clear Data", command=clear_data_selected).pack(side=tk.LEFT, padx=5)

        # Initial load
        threading.Thread(target=refresh_apps, daemon=True).start()

    def _get_apk_info(self, device: str, apk: str, is_installed: bool) -> Dict[str, str]:
        """Get APK information using aapt"""
        if is_installed:
            # Get APK path for installed package
            path_cmd = f"pm path {apk}"
            path_result = subprocess.run(
                ["adb", "-s", device, "shell", path_cmd],
                capture_output=True, text=True
            )
            if not path_result.stdout:
                raise Exception(f"Could not find installed package {apk}")
            apk_path = path_result.stdout.split(":")[1].strip()
        else:
            apk_path = apk

        # Use aapt to dump APK info
        if is_installed:
            dump_cmd = f"aapt dump badging {apk_path}"
            result = subprocess.run(
                ["adb", "-s", device, "shell", dump_cmd],
                capture_output=True, text=True
            )
        else:
            result = subprocess.run(
                ["aapt", "dump", "badging", apk_path],
                capture_output=True, text=True
            )

        info = {}
        for line in result.stdout.split('\n'):
            if line.startswith('package:'):
                match = re.search(r"name='([^']+)'", line)
                if match:
                    info['Package'] = match.group(1)
                
                match = re.search(r"versionName='([^']+)'", line)
                if match:
                    info['Version Name'] = match.group(1)
                
                match = re.search(r"versionCode='([^']+)'", line)
                if match:
                    info['Version Code'] = match.group(1)

            elif line.startswith('sdkVersion:'):
                info['Min SDK'] = line.split("'")[1]
            
            elif line.startswith('targetSdkVersion:'):
                info['Target SDK'] = line.split("'")[1]
            
            elif line.startswith('uses-permission:'):
                if 'Permissions' not in info:
                    info['Permissions'] = []
                match = re.search(r"name='([^']+)'", line)
                if match:
                    info['Permissions'].append(match.group(1))
            
            elif line.startswith('uses-feature:'):
                if 'Features' not in info:
                    info['Features'] = []
                match = re.search(r"name='([^']+)'", line)
                if match:
                    info['Features'].append(match.group(1))

            elif line.startswith('native-code:'):
                info['Native Code'] = line.split(":")[1].strip()

        # Convert lists to strings
        for key in ['Permissions', 'Features']:
            if key in info and isinstance(info[key], list):
                info[key] = ', '.join(info[key])

        return info

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
        
        select_window = tk.Toplevel(self.root)
        select_window.title("Select Package")
        select_window.geometry("400x500")
        select_window.transient(self.root)
        
        main_frame = ttk.Frame(select_window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Filter
        filter_var = tk.StringVar()
        filter_var.trace('w', lambda *args: filter_packages())
        ttk.Entry(main_frame, textvariable=filter_var).pack(fill=tk.X, pady=(0, 10))
        
        # Package list
        package_list = tk.Listbox(main_frame)
        package_list.pack(fill=tk.BOTH, expand=True)
        
        selected_package = ['']  # Use list to store selected package
        
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
        
        ttk.Button(main_frame, text="Select", command=on_select).pack(pady=10)
        
        filter_packages()
        select_window.wait_window()
        
        return selected_package[0]