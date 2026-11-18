#!/usr/bin/env python3
"""P2 capture orchestration: background tshark + netstat PID poller.

Usage:
  python capture.py list
  python capture.py watch [--host 192.168.1.20] --out session.pcapng [--duration 3600]
  python capture.py ports  --host 192.168.1.20 --ports 502,1200,2455,6626,1210,1211
"""
import argparse
import os
import socket
import subprocess
import threading
import time


def tshark_path():
    candidates = [
        os.environ.get("PROTOCOL_AGENT_TSHARK", ""),
        r"C:\Program Files\Wireshark\tshark.exe",
        "tshark",
    ]
    for p in candidates:
        if not p:
            continue
        try:
            subprocess.run([p, "-v"], capture_output=True)
            return p
        except OSError:
            continue
    raise SystemExit("tshark not found")


def parse_tshark_interfaces(text):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        ident, name = line, line
        if "." in line:
            head, rest = line.split(".", 1)
            if head.strip().isdigit():
                ident, name = head.strip(), rest.strip()
        out.append({"id": ident, "name": name})
    return out


def list_interfaces(ts=None):
    ts = ts or tshark_path()
    p = subprocess.run([ts, "-D"], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if p.returncode != 0:
        raise SystemExit((p.stderr or p.stdout or "tshark -D failed").strip())
    return parse_tshark_interfaces(p.stdout)


def default_interfaces(ts=None):
    items = list_interfaces(ts)
    usable = [x for x in items if not any(
        word in x["name"].lower() for word in ("loopback", "etwdump", "event tracing"))]
    return usable or items


class NetstatPoller(threading.Thread):
    def __init__(self, host, interval=1.0, logfile="netstat_poll.log"):
        super().__init__(daemon=True)
        self.host, self.interval, self.logfile = host, interval, logfile
        self.stop_evt = threading.Event()
        self._fh = open(logfile, "w", encoding="utf-8")

    def run(self):
        while not self.stop_evt.is_set():
            self._fh.write(f"=== {time.strftime('%H:%M:%S')} ===\n")
            out = subprocess.run(["netstat", "-ano"], capture_output=True,
                                 text=True, encoding="utf-8",
                                 errors="replace").stdout or ""
            for ln in out.splitlines():
                if f"{self.host}:" in ln:
                    self._fh.write(ln + "\n")
            self._fh.flush()
            self.stop_evt.wait(self.interval)

    def stop(self):
        self.stop_evt.set()
        self.join(timeout=3)
        self._fh.close()


def local_egress_ip(host):
    """Best-effort local IP used to reach host, to help pick the right NIC."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)
        sock.connect((host, 9))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except OSError:
        return ""


def print_interfaces():
    for item in list_interfaces():
        print(f"{item['id']}\t{item['name']}")


def watch(host, out, duration, interfaces=None, extra_filter="not arp and not icmp"):
    ts = tshark_path()
    if not interfaces:
        interfaces = [x["id"] for x in default_interfaces(ts)]
    os.makedirs(os.path.dirname(os.path.abspath(out)) or ".", exist_ok=True)  # pitfall #14
    if host:
        egress = local_egress_ip(host)
        if egress:
            print(f"local egress ip for {host}: {egress} (pick the matching --interface if capture stays empty)")
    poller = NetstatPoller(host) if host else None
    if poller:
        poller.start()
    cap_filter = f"host {host} and {extra_filter}" if host else extra_filter
    print(f"capturing [{cap_filter}] on {','.join(interfaces)} -> {out}  (Ctrl+C to stop early)")
    args = [ts]
    for iface in interfaces:
        args.extend(["-i", iface])
    args.extend(["-f", cap_filter, "-a", f"duration:{duration}", "-w", out])
    try:
        subprocess.run(args, check=False)
    except KeyboardInterrupt:
        print("\nstopping (tshark may need a second Ctrl+C on Windows)...")
    finally:
        if poller:
            poller.stop()
    if poller:
        print(f"netstat log -> {poller.logfile}")


def ports(host, ports_csv, timeout=2.0):
    print(f"probing {host}")
    for p in [int(x) for x in ports_csv.split(",")]:
        s = socket.socket()
        s.settimeout(timeout)
        try:
            s.connect((host, p))
            state = "OPEN"
        except socket.timeout:
            state = "closed/filtered (timeout)"
        except OSError as e:
            state = f"refused ({e.errno})"
        finally:
            s.close()
        print(f"  {p:>5}/TCP  {state}")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("watch")
    w.add_argument("--host", default="", help="device IP filter; omit to capture all traffic (filter by port/session afterwards)")
    w.add_argument("--out", required=True)
    w.add_argument("--duration", type=int, default=3600)
    w.add_argument("--interface", action="append", default=[], help="tshark interface id; repeatable; default auto")
    p = sub.add_parser("ports")
    p.add_argument("--host", required=True)
    p.add_argument("--ports", default="502,1200,1210,1211,2455,6626")
    sub.add_parser("list", help="list capture interfaces (id + name)")
    args = ap.parse_args()
    if args.cmd == "watch":
        watch(args.host, args.out, args.duration, args.interface)
    elif args.cmd == "ports":
        ports(args.host, args.ports)
    else:
        print_interfaces()


if __name__ == "__main__":
    main()
