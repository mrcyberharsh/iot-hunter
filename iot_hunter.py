#!/usr/bin/env python3
import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk

from modules.discovery import scan_target_network
from modules.fingerprint import run_fingerprint


class IoTHunterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("IoT Hunter - Security Scanner")
        self.root.geometry("960x700")
        self.root.minsize(720, 500)

        self.target_var = tk.StringVar(value="192.168.1.0/24")

        top = ttk.Frame(root, padding=12)
        top.pack(fill="x")

        ttk.Label(top, text="Target IP range:").pack(side="left", padx=(0, 8))
        self.target_entry = ttk.Entry(top, textvariable=self.target_var, width=30)
        self.target_entry.pack(side="left", fill="x", expand=True)

        self.start_button = ttk.Button(top, text="Start Scan", command=self.start_scan)
        self.start_button.pack(side="left", padx=(8, 0))

        self.export_button = ttk.Button(top, text="Export Report", command=self.export_report)
        self.export_button.pack(side="left", padx=(8, 0))

        self.output = scrolledtext.ScrolledText(root, wrap=tk.WORD, state="disabled")
        self.output.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self.output.tag_config("info", foreground="#333333")
        self.output.tag_config("ok", foreground="#0b6b35")
        self.output.tag_config("warn", foreground="#a65a00")
        self.output.tag_config("error", foreground="#b92d2d")

    def append_output(self, text, tag="info"):
        self.output.configure(state="normal")
        self.output.insert(tk.END, text + "\n", tag)
        self.output.see(tk.END)
        self.output.configure(state="disabled")

    def export_report(self):
        report = self.output.get("1.0", tk.END).strip()
        if not report:
            self.append_output("[!] No scan results to export.", "warn")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile="iot_hunter_report.txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
        )
        if not save_path:
            return

        with open(save_path, "w", encoding="utf-8") as fh:
            fh.write(report)
        self.append_output(f"[+] Report exported to: {save_path}", "ok")

    def start_scan(self):
        target = self.target_var.get().strip()
        if not target:
            self.append_output("[!] Please provide a target IP range such as 192.168.1.0/24.", "error")
            return

        self.output.configure(state="normal")
        self.output.delete("1.0", tk.END)
        self.output.configure(state="disabled")
        self.append_output(f"[*] Starting scan on {target}...", "info")

        def worker():
            try:
                live_hosts = scan_target_network(target)
                if not live_hosts:
                    self.append_output("[!] No active hosts with open ports were found.", "warn")
                    return

                for host in live_hosts:
                    self.append_output(f"[+] Host {host['ip']} open ports: {host['open_ports']}", "ok")

                devices = run_fingerprint(live_hosts)
                for device in devices:
                    self.append_output(
                        f"[+] {device['ip']} | MAC: {device.get('mac', 'N/A')} | Vendor: {device.get('vendor', 'Unknown')} | Type: {device.get('device_type', 'unknown')}",
                        "info",
                    )
                    if device.get("cves"):
                        for cve in device["cves"]:
                            self.append_output(
                                f"    Port {cve['port']}: {cve['service']} {cve['version'] or 'unknown'} | CVEs: {len(cve['cves'])}",
                                "warn",
                            )
                            for entry in cve["cves"][:3]:
                                self.append_output(f"      - {entry['id']}: {entry['description'][:120]}", "warn")

                self.append_output("[+] Scan complete.", "ok")
            except Exception as exc:  # pragma: no cover
                self.append_output(f"[!] Scan failed: {exc}", "error")

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()


def main():
    root = tk.Tk()
    app = IoTHunterGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

