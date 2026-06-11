import os
import socket
import subprocess
import threading
import time
import tkinter as tk
from datetime import datetime

import psutil


BG = "#000000"
PANEL = "#eef3f9"
CARD = "#000000"
BORDER = "#d8e0ea"
TEXT = "#EEF1F7"
MUTED = "#ffffff"
ACCENT = "#0f62fe"
ACCENT_DARK = "#05a7ad"
WARN = "#e09201"
DANGER = "#ff0000"
OK = "#75A527"

FONT_TITLE = ("Segoe UI", 14, "bold")
FONT_LABEL = ("Segoe UI", 9)
FONT_VALUE = ("Segoe UI", 18, "bold")
FONT_SMALL = ("Segoe UI", 8)
FONT_HEADER = ("Segoe UI", 10, "bold")

REFRESH_MS = 1500
NET_SAMPLES = 2
DISK_SAMPLES = 1


def color_for(pct):
    if pct >= 85:
        return DANGER
    if pct >= 60:
        return WARN
    return OK


def bytes_human(n):
    try:
        n = max(0.0, float(n))
    except (TypeError, ValueError):
        n = 0.0

    for unit in ("B/s", "KB/s", "MB/s", "GB/s"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB/s"


def speed_pair_human(read_speed, write_speed):
    return f"R {bytes_human(read_speed)}   W {bytes_human(write_speed)}"


def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "N/A"


def get_failed_logins():
    system_name = os.name
    try:
        if system_name == "posix":
            result = subprocess.run(
                ["grep", "-c", "Failed password", "/var/log/auth.log"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            value = result.stdout.strip()
            return int(value) if result.returncode == 0 and value.isdigit() else 0

        if system_name == "nt":
            command = (
                "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} "
                "-MaxEvents 50 -ErrorAction SilentlyContinue | "
                "Measure-Object | Select-Object -ExpandProperty Count"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", command],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            value = result.stdout.strip()
            return int(value) if value.isdigit() else 0
    except (subprocess.SubprocessError, OSError, ValueError):
        pass
    return 0


def get_suspicious_processes():
    suspicious_keywords = [
        "miner",
        "xmrig",
        "cryptonight",
        "keylog",
        "rat",
        "njrat",
        "darkcomet",
        "netbus",
        "backdoor",
        "payload",
    ]
    hits = []
    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "username"]):
        try:
            name = proc.info.get("name") or ""
            if any(keyword in name.lower() for keyword in suspicious_keywords):
                hits.append(f"WARNING {name} (PID {proc.info.get('pid', 'N/A')})")
        except (psutil.Error, OSError):
            continue
    return hits if hits else ["None detected"]


def get_recent_processes(n=8):
    procs = []
    for proc in psutil.process_iter(["pid", "name", "create_time"]):
        try:
            create_time = proc.info.get("create_time")
            if not create_time:
                continue
            name = proc.info.get("name") or "<unknown>"
            procs.append((create_time, name, proc.info.get("pid")))
        except (psutil.Error, OSError):
            continue

    procs.sort(reverse=True)
    result = []
    for create_time, name, _pid in procs[:n]:
        try:
            age = datetime.now() - datetime.fromtimestamp(create_time)
            minutes = max(0, int(age.total_seconds() // 60))
            label = f"{minutes}m ago" if minutes < 60 else f"{minutes // 60}h ago"
        except (OSError, ValueError):
            label = "unknown"
        result.append(f"{name[:28]:<28}  {label}")
    return result or ["No processes found"]


def get_connection_count():
    try:
        return str(len(psutil.net_connections(kind="inet")))
    except (psutil.Error, OSError):
        return "N/A"


class GaugeBar(tk.Canvas):
    """Thin horizontal progress bar."""

    def __init__(self, parent, width=220, height=6, **kw):
        super().__init__(parent, width=width, height=height, bg=CARD, highlightthickness=0, **kw)
        self._bar_width = width
        self._bar_height = height
        self._pct = 0
        self._draw()

    def set(self, pct):
        self._pct = max(0, min(100, float(pct)))
        self._draw()

    def _draw(self):
        self.delete("all")
        radius = self._bar_height // 2
        self.create_rounded_rect(0, 0, self._bar_width, self._bar_height, radius, fill=PANEL, outline="")
        fill_w = int(self._bar_width * self._pct / 100)
        if fill_w > 0:
            self.create_rounded_rect(
                0,
                0,
                fill_w,
                self._bar_height,
                radius,
                fill=color_for(self._pct),
                outline="",
            )

    def create_rounded_rect(self, x1, y1, x2, y2, radius, **kw):
        points = [
            x1 + radius,
            y1,
            x2 - radius,
            y1,
            x2,
            y1,
            x2,
            y1 + radius,
            x2,
            y2 - radius,
            x2,
            y2,
            x2 - radius,
            y2,
            x1 + radius,
            y2,
            x1,
            y2,
            x1,
            y2 - radius,
            x1,
            y1 + radius,
            x1,
            y1,
        ]
        return self.create_polygon(points, smooth=True, **kw)


class Card(tk.Frame):
    """Light card with a clean enterprise dashboard treatment."""

    def __init__(self, parent, title="", icon="", **kw):
        super().__init__(parent, bg=CARD, highlightbackground=BORDER, highlightthickness=1, **kw)
        if title:
            hdr = tk.Frame(self, bg=CARD)
            hdr.pack(fill="x", padx=16, pady=(14, 4))
            tk.Label(
                hdr,
                text=f"{icon}  {title}" if icon else title,
                font=FONT_HEADER,
                fg=TEXT,
                bg=CARD,
                anchor="w",
            ).pack(side="left")
        self.body = tk.Frame(self, bg=CARD)
        self.body.pack(fill="both", expand=True, padx=16, pady=(6, 14))


class MetricRow(tk.Frame):
    """Label + big value + gauge in one row."""

    def __init__(self, parent, label):
        super().__init__(parent, bg=CARD)
        tk.Label(self, text=label, font=FONT_LABEL, fg=MUTED, bg=CARD, width=5, anchor="w").pack(
            side="left"
        )
        self._val_lbl = tk.Label(
            self,
            text="---%",
            font=FONT_VALUE,
            fg=TEXT,
            bg=CARD,
            width=7,
            anchor="e",
        )
        self._val_lbl.pack(side="left", padx=(6, 10))
        self._bar = GaugeBar(self)
        self._bar.pack(side="left")

    def update(self, pct):
        pct = max(0, min(100, float(pct)))
        self._val_lbl.config(text=f"{pct:.1f}%", fg=color_for(pct))
        self._bar.set(pct)


class SpeedMetricRow(tk.Frame):
    """Label + disk read/write speed in one row."""

    def __init__(self, parent, label):
        super().__init__(parent, bg=CARD)
        tk.Label(self, text=label, font=FONT_LABEL, fg=MUTED, bg=CARD, width=5, anchor="w").pack(
            side="left"
        )
        self._val_lbl = tk.Label(
            self,
            text="R --   W --",
            font=("Segoe UI", 12, "bold"),
            fg=TEXT,
            bg=CARD,
            width=24,
            anchor="w",
        )
        self._val_lbl.pack(side="left", padx=(6, 0))

    def update(self, read_speed, write_speed):
        self._val_lbl.config(text=speed_pair_human(read_speed, write_speed), fg=ACCENT_DARK)


class SysMonitor(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SYS MONITOR")
        self.configure(bg=BG)
        self.resizable(False, False)

        self._net_prev = psutil.net_io_counters()
        self._net_time = time.time()
        self._up_speed = 0.0
        self._down_speed = 0.0
        self._net_thread_running = True
        threading.Thread(target=self._net_loop, daemon=True).start()

        self._disk_prev = psutil.disk_io_counters()
        self._disk_time = time.time()
        self._disk_read_speed = 0.0
        self._disk_write_speed = 0.0
        self._disk_thread_running = True
        threading.Thread(target=self._disk_loop, daemon=True).start()

        self._build_ui()
        self._tick()

    def _build_ui(self):
        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=20, pady=(18, 0))
        tk.Label(bar, text="Enterprise System Monitor", font=FONT_TITLE, fg=TEXT, bg=BG).pack(
            side="left"
        )
        tk.Label(
            bar,
            text="Live operations dashboard",
            font=FONT_SMALL,
            fg=MUTED,
            bg=BG,
        ).pack(side="left", padx=(12, 0), pady=(4, 0))
        self._clock_lbl = tk.Label(bar, text="", font=FONT_SMALL, fg=MUTED, bg=BG)
        self._clock_lbl.pack(side="right")

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", padx=20, pady=12)

        cols = tk.Frame(self, bg=BG)
        cols.pack(padx=20, pady=0, fill="both", expand=True)

        left = tk.Frame(cols, bg=BG)
        right = tk.Frame(cols, bg=BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 6))
        right.pack(side="left", fill="both", expand=True, padx=(6, 0))

        sys_card = Card(left, "System Health", "SYS")
        sys_card.pack(fill="x", pady=(0, 10))
        self._cpu_row = MetricRow(sys_card.body, "CPU")
        self._cpu_row.pack(fill="x", pady=3)
        self._ram_row = MetricRow(sys_card.body, "RAM")
        self._ram_row.pack(fill="x", pady=3)
        self._disk_row = SpeedMetricRow(sys_card.body, "Disk")
        self._disk_row.pack(fill="x", pady=3)

        net_card = Card(left, "Network Activity", "NET")
        net_card.pack(fill="x", pady=(0, 10))

        def net_row(label):
            frame = tk.Frame(net_card.body, bg=CARD)
            frame.pack(fill="x", pady=2)
            tk.Label(
                frame,
                text=label,
                font=FONT_LABEL,
                fg=MUTED,
                bg=CARD,
                width=16,
                anchor="w",
            ).pack(side="left")
            value = tk.Label(frame, text="--", font=FONT_LABEL, fg=TEXT, bg=CARD, anchor="w")
            value.pack(side="left")
            return value

        self._up_lbl = net_row("Upload")
        self._down_lbl = net_row("Download")
        self._conn_lbl = net_row("Connections")
        self._ip_lbl = net_row("Local IP")
        self._ip_lbl.config(fg=ACCENT)

        sec_card = Card(right, "Security Posture", "SEC")
        sec_card.pack(fill="x", pady=(0, 10))

        def sec_row(label):
            frame = tk.Frame(sec_card.body, bg=CARD)
            frame.pack(fill="x", pady=2)
            tk.Label(
                frame,
                text=label,
                font=FONT_LABEL,
                fg=MUTED,
                bg=CARD,
                width=18,
                anchor="nw",
            ).pack(side="left")
            value = tk.Label(
                frame,
                text="--",
                font=FONT_LABEL,
                fg=TEXT,
                bg=CARD,
                anchor="nw",
                justify="left",
                wraplength=180,
            )
            value.pack(side="left")
            return value

        self._fail_lbl = sec_row("Failed logins")
        self._suspicious_lbl = tk.Label(
            sec_card.body,
            text="",
            font=FONT_SMALL,
            fg=WARN,
            bg=CARD,
            anchor="w",
            justify="left",
        )
        self._suspicious_lbl.pack(fill="x", pady=(0, 2))

        proc_card = Card(right, "Recent Processes", "PROC")
        proc_card.pack(fill="x", pady=(0, 10))
        self._proc_text = tk.Text(
            proc_card.body,
            font=("Consolas", 8),
            fg=TEXT,
            bg=CARD,
            insertbackground=ACCENT,
            relief="flat",
            height=10,
            state="disabled",
            highlightthickness=0,
        )
        self._proc_text.pack(fill="x")

        tk.Frame(self, bg=BG, height=16).pack()

    def _net_loop(self):
        while self._net_thread_running:
            time.sleep(NET_SAMPLES)
            try:
                now = time.time()
                current = psutil.net_io_counters()
                elapsed = max(0.001, now - self._net_time)
                self._up_speed = (current.bytes_sent - self._net_prev.bytes_sent) / elapsed
                self._down_speed = (current.bytes_recv - self._net_prev.bytes_recv) / elapsed
                self._net_prev = current
                self._net_time = now
            except (psutil.Error, OSError):
                self._up_speed = 0.0
                self._down_speed = 0.0

    def _disk_loop(self):
        while self._disk_thread_running:
            time.sleep(DISK_SAMPLES)
            try:
                now = time.time()
                current = psutil.disk_io_counters()
                elapsed = max(0.001, now - self._disk_time)
                if self._disk_prev and current:
                    self._disk_read_speed = (current.read_bytes - self._disk_prev.read_bytes) / elapsed
                    self._disk_write_speed = (current.write_bytes - self._disk_prev.write_bytes) / elapsed
                self._disk_prev = current
                self._disk_time = now
            except (psutil.Error, OSError):
                self._disk_read_speed = 0.0
                self._disk_write_speed = 0.0

    def _tick(self):
        self._clock_lbl.config(text=datetime.now().strftime("%H:%M:%S"))

        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory().percent

        self._cpu_row.update(cpu)
        self._ram_row.update(ram)
        self._disk_row.update(self._disk_read_speed, self._disk_write_speed)

        self._up_lbl.config(text=bytes_human(self._up_speed), fg=OK)
        self._down_lbl.config(text=bytes_human(self._down_speed), fg=ACCENT)
        self._conn_lbl.config(text=get_connection_count())
        self._ip_lbl.config(text=get_local_ip())

        if not hasattr(self, "_sec_tick"):
            self._sec_tick = 0
        self._sec_tick += 1
        if self._sec_tick % 10 == 1:
            fails = get_failed_logins()
            self._fail_lbl.config(
                text=f"{fails} attempt{'s' if fails != 1 else ''}",
                fg=DANGER if fails > 0 else OK,
            )
            suspicious = get_suspicious_processes()
            clear = suspicious == ["None detected"]
            self._suspicious_lbl.config(
                text="Suspicious: " + ("None detected" if clear else ", ".join(suspicious)),
                fg=OK if clear else WARN,
            )

        procs = get_recent_processes()
        self._proc_text.config(state="normal")
        self._proc_text.delete("1.0", "end")
        self._proc_text.insert("end", "\n".join(procs))
        self._proc_text.config(state="disabled")

        self.after(REFRESH_MS, self._tick)

    def destroy(self):
        self._net_thread_running = False
        self._disk_thread_running = False
        super().destroy()


if __name__ == "__main__":
    app = SysMonitor()
    app.mainloop()

