#!/usr/bin/env python3
"""
Total Phase Data Center & Beagle USB 12 Automation Utility for Antigravity.

Supports:
  1. `devices`   - List attached Total Phase analyzers (e.g. Beagle USB 12).
  2. `capture`   - Timed or command-wrapped capture using stdio console (-c),
                   saving both .tdc and .csv and printing a protocol summary.
  3. `start`     - Start a persistent background capture session via TCP remote
                   console (-r) so the user or agent can perform interactive tests.
  4. `stop`      - Stop the active background capture, export .tdc + .csv, and
                   print a protocol summary.
  5. `cmd`       - Send an arbitrary Data Center CLI command to a running session.
  6. `analyze`   - Convert a .tdc file to .csv (if needed) and summarize USB
                   enumeration, Control transfers, Endpoints, and HID/CTAPHID traffic.
"""

import argparse
import csv
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

DEFAULT_DATACENTER_BIN = "/Applications/Data Center.app/bin/datacenter"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5042
PROMPT_RE = re.compile(r"(?:^|\n)\d+>\s*$")


def check_loopback_permitted(host: str = DEFAULT_HOST) -> bool:
    """Verify both bind() and connect() on loopback are permitted (fails fast in seatbelt sandbox)."""
    srv = None
    cli = None
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind((host, 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        cli = socket.create_connection((host, port), timeout=0.5)
        return True
    except OSError as e:
        print(f"ERROR: Loopback TCP sockets not permitted in this environment ({e})", file=sys.stderr)
        return False
    finally:
        if cli is not None:
            try:
                cli.close()
            except Exception:
                pass
        if srv is not None:
            try:
                srv.close()
            except Exception:
                pass

# CTAPHID (FIDO2 / U2F over USB HID) command tags (bit 7 set)
CTAPHID_COMMANDS = {
    0x81: "CTAPHID_PING",
    0x83: "CTAPHID_MSG (U2F)",
    0x86: "CTAPHID_INIT",
    0x88: "CTAPHID_WINK",
    0x90: "CTAPHID_CBOR (FIDO2)",
    0x91: "CTAPHID_CANCEL",
    0xBB: "CTAPHID_KEEPALIVE",
    0xBF: "CTAPHID_ERROR",
}

FIDO2_CBOR_COMMANDS = {
    0x01: "authenticatorMakeCredential (0x01)",
    0x02: "authenticatorGetAssertion (0x02)",
    0x04: "authenticatorGetInfo (0x04)",
    0x06: "authenticatorClientPin (0x06)",
    0x07: "authenticatorReset (0x07)",
    0x08: "authenticatorGetNextAssertion (0x08)",
    0x09: "authenticatorBioEnrollment (0x09)",
    0x0A: "authenticatorCredentialManagement (0x0A)",
    0x0B: "authenticatorSelection (0x0B)",
    0x0C: "authenticatorLargeBlobs (0x0C)",
    0x0D: "authenticatorConfig (0x0D)",
}


class StdioDataCenter:
    """Drives Total Phase Data Center via stdin/stdout console (-c)."""

    def __init__(self, binary: str = DEFAULT_DATACENTER_BIN):
        self.binary = binary
        self.proc: Optional[subprocess.Popen] = None

    def __enter__(self) -> "StdioDataCenter":
        if not check_loopback_permitted():
            raise RuntimeError("Loopback TCP sockets not permitted in this environment")
        self.proc = subprocess.Popen(
            [self.binary, "-m", "--no-splash", "--no-prefs", "-c"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        self._read_until_prompt(timeout=10.0)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.proc and self.proc.poll() is None:
            try:
                self.cmd("exit(True)", timeout=3.0)
            except Exception:
                pass
            try:
                self.proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except Exception:
                    self.proc.kill()

    def _read_until_prompt(self, timeout: float = 10.0) -> str:
        assert self.proc and self.proc.stdout
        import selectors

        sel = selectors.DefaultSelector()
        sel.register(self.proc.stdout, selectors.EVENT_READ)
        buf = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            events = sel.select(timeout=max(0.05, deadline - time.time()))
            if not events:
                break
            chunk = os.read(self.proc.stdout.fileno(), 4096).decode("utf-8", errors="replace")
            if not chunk:
                break
            buf.append(chunk)
            joined = "".join(buf)
            if PROMPT_RE.search(joined):
                break
        sel.close()
        text = "".join(buf)
        return PROMPT_RE.sub("", text).strip()

    def cmd(self, command: str, timeout: float = 10.0) -> str:
        assert self.proc and self.proc.stdin
        self.proc.stdin.write(command + "\n")
        self.proc.stdin.flush()
        return self._read_until_prompt(timeout=timeout)


class RemoteDataCenter:
    """Connects to a persistent Python proxy daemon on (HOST:PORT) that holds StdioDataCenter (-c) open."""

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        self.host = host
        self.port = port

    def is_running(self) -> bool:
        try:
            with socket.create_connection((self.host, self.port), timeout=2.0) as sock:
                sock.settimeout(2.0)
                data = sock.recv(128)
                return bool(data and b">" in data)
        except OSError:
            return False

    def start_daemon(self, binary: str = DEFAULT_DATACENTER_BIN, wait_seconds: float = 12.0) -> bool:
        # Fail fast if running in a sandbox that forbids loopback TCP connect()
        if not check_loopback_permitted(self.host):
            return False

        if self.is_running():
            return True
        # Clean up any stray Data Center processes holding the Beagle hardware
        subprocess.run(["pkill", "-9", "-f", "Data Center.app"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "-9", "-f", "datacenter_ctl.py.*_daemon"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.3)
        subprocess.Popen(
            [
                sys.executable,
                os.path.abspath(__file__),
                "--binary",
                binary,
                "--host",
                self.host,
                "--port",
                str(self.port),
                "_daemon",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        deadline = time.time() + wait_seconds
        while time.time() < deadline:
            if self.is_running():
                time.sleep(0.2)
                return True
            time.sleep(0.25)
        return False

    def send_commands(self, commands: List[str], timeout: float = 30.0) -> List[Tuple[str, str]]:
        results: List[Tuple[str, str]] = []
        with socket.create_connection((self.host, self.port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            self._read_until_prompt(sock, timeout=5.0)
            for c in commands:
                sock.sendall((c + "\n").encode("utf-8"))
                out = self._read_until_prompt(sock, timeout=timeout)
                results.append((c, out))
        return results

    @staticmethod
    def _read_until_prompt(sock: socket.socket, timeout: float = 5.0) -> str:
        sock.settimeout(0.5)
        chunks: List[str] = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data.decode("utf-8", errors="replace"))
                joined = "".join(chunks)
                if PROMPT_RE.search(joined):
                    break
            except socket.timeout:
                if chunks and PROMPT_RE.search("".join(chunks)):
                    break
        return PROMPT_RE.sub("", "".join(chunks)).strip()


def cmd_daemon(args):
    """Persistent TCP proxy daemon that holds the SINGLE TCP connection to Data Center (-r) open across start/stop calls."""
    backend_port = args.port + 1
    dc_log = open("/tmp/totalphase_datacenter.log", "w", encoding="utf-8")
    daemon_log = open("/tmp/totalphase_daemon.log", "w", encoding="utf-8", buffering=1)
    daemon_log.write(f"[daemon] Starting Data Center on {args.host}:{backend_port} via {args.binary}\n")
    proc = subprocess.Popen(
        ["/usr/bin/caffeinate", "-i", args.binary, "-m", "--no-splash", "--no-prefs", "-r", f"{args.host}:{backend_port}"],
        stdout=dc_log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    backend_sock: Optional[socket.socket] = None
    deadline = time.time() + 12.0
    while time.time() < deadline:
        if proc.poll() is not None:
            daemon_log.write(f"[daemon] Data Center exited early with code {proc.returncode}\n")
            break
        try:
            s = socket.create_connection((args.host, backend_port), timeout=1.0)
            # Wait for initial prompt on this single persistent connection
            init_out = RemoteDataCenter._read_until_prompt(s, timeout=5.0)
            daemon_log.write(f"[daemon] Connected to Data Center backend, init_out={init_out!r}\n")
            backend_sock = s
            break
        except OSError:
            time.sleep(0.25)

    if backend_sock is None:
        daemon_log.write("[daemon] Failed to connect to Data Center backend; killing process group\n")
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        sys.exit(1)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(8)
    srv.settimeout(2.0)
    should_exit = False
    cmd_idx = 1
    try:
        while not should_exit:
            if proc.poll() is not None:
                daemon_log.write(f"[daemon] Data Center process exited (code={proc.returncode}); shutting down daemon\n")
                break
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            with conn:
                if proc.poll() is not None:
                    daemon_log.write(f"[daemon] Data Center process exited before accept handling (code={proc.returncode})\n")
                    break
                conn.settimeout(180.0)
                try:
                    conn.sendall(f"\n{cmd_idx}> ".encode("utf-8"))
                except OSError:
                    continue
                buf = ""
                while not should_exit:
                    try:
                        data = conn.recv(4096)
                    except OSError:
                        break
                    if not data:
                        break
                    buf += data.decode("utf-8", errors="replace")
                    while "\n" in buf:
                        line, buf = buf.split("\n", 1)
                        line = line.strip()
                        if not line:
                            conn.sendall(f"\n{cmd_idx}> ".encode("utf-8"))
                            continue
                        daemon_log.write(f"[daemon] Executing command: {line}\n")
                        cmd_timeout = 180.0 if line.startswith(("save", "export", "stop", "classify")) else 15.0
                        try:
                            backend_sock.sendall((line + "\n").encode("utf-8"))
                            out = RemoteDataCenter._read_until_prompt(backend_sock, timeout=cmd_timeout)
                            daemon_log.write(f"[daemon] Output ({len(out)} chars): {out[:200]!r}\n")
                        except OSError as e:
                            out = f"ERROR: {e}"
                            daemon_log.write(f"[daemon] Backend socket error: {e}\n")
                            should_exit = True
                        cmd_idx += 1
                        try:
                            conn.sendall(f"{out}\n{cmd_idx}> ".encode("utf-8"))
                        except OSError:
                            pass
                        if line.startswith("exit") or should_exit:
                            should_exit = True
                            break
    finally:
        daemon_log.write("[daemon] Exiting daemon finally block\n")
        srv.close()
        try:
            backend_sock.close()
        except Exception:
            pass
        try:
            proc.wait(timeout=3.0)
        except Exception:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass


def parse_hex_bytes(hex_str: str) -> List[int]:
    parts = hex_str.strip().split()
    out = []
    for p in parts:
        if len(p) == 2:
            try:
                out.append(int(p, 16))
            except ValueError:
                pass
    return out


def decode_ctaphid_packet(data_bytes: List[int]) -> Optional[str]:
    """If a USB packet payload looks like a CTAPHID (FIDO2/U2F) frame, decode it."""
    if len(data_bytes) < 7:
        return None
    cid = (data_bytes[0] << 24) | (data_bytes[1] << 16) | (data_bytes[2] << 8) | data_bytes[3]
    cmd_or_seq = data_bytes[4]
    if cmd_or_seq & 0x80:
        cmd_name = CTAPHID_COMMANDS.get(cmd_or_seq)
        if not cmd_name:
            return None
        bcnt = (data_bytes[5] << 8) | data_bytes[6]
        payload = data_bytes[7:]
        detail = f"CID=0x{cid:08X} {cmd_name} len={bcnt}"
        if cmd_or_seq == 0x90 and payload:
            cbor_cmd = FIDO2_CBOR_COMMANDS.get(payload[0], f"0x{payload[0]:02X}")
            detail += f" [{cbor_cmd}]"
        elif cmd_or_seq == 0xBF and payload:
            detail += f" [err=0x{payload[0]:02X}]"
        return detail
    return None


def analyze_csv(csv_path: str, max_events: int = 80, include_nak: bool = False) -> Dict:
    """Parse a Total Phase Data Center exported USB CSV file into a concise summary."""
    bus_events = []
    level0_records = []
    transactions = []
    ctaphid_frames = []
    errors = []
    endpoints: Dict[str, int] = {}
    total_rows = 0

    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        lines = [line for line in f if not line.startswith("#") and line.strip()]

    # Standard columns:
    # Level,Sp,Index,m:s.ms.us,Dur,Len,Err,Dev,Ep,Record,Data,Summary,ASCII
    reader = csv.reader(lines)
    for row in reader:
        if len(row) < 12:
            continue
        total_rows += 1
        level_str, sp, idx, ts, dur, length, err, dev, ep, record, data, summary = row[:12]
        rec_clean = record.strip()

        if not include_nak and ("NAK" in rec_clean or "SOF" in rec_clean):
            continue

        if err.strip():
            errors.append(
                {"index": idx, "time": ts, "err": err.strip(), "dev": dev, "ep": ep, "record": rec_clean}
            )

        if dev.strip() or ep.strip():
            key = f"Dev {dev or '?'}:Ep {ep or '?'}"
            endpoints[key] = endpoints.get(key, 0) + 1

        if rec_clean.startswith("<") or "Capture " in rec_clean:
            bus_events.append({"index": idx, "time": ts, "event": rec_clean, "summary": summary})
            continue

        if level_str == "0":
            level0_records.append(
                {
                    "index": idx,
                    "time": ts,
                    "dur": dur,
                    "len": length,
                    "dev": dev,
                    "ep": ep,
                    "record": rec_clean,
                    "data": data[:60] + ("..." if len(data) > 60 else ""),
                    "summary": summary,
                }
            )
        elif level_str == "1" and ("txn" in rec_clean or "Transaction" in rec_clean):
            data_bytes = parse_hex_bytes(data)
            ctap_info = decode_ctaphid_packet(data_bytes)
            entry = {
                "index": idx,
                "time": ts,
                "dev": dev,
                "ep": ep,
                "txn": rec_clean,
                "len": length,
                "data_preview": data[:48] + ("..." if len(data) > 48 else ""),
            }
            if ctap_info:
                entry["ctaphid"] = ctap_info
                ctaphid_frames.append(entry)
            transactions.append(entry)

    return {
        "csv_path": csv_path,
        "total_records": total_rows,
        "bus_events": bus_events[:max_events],
        "level0_transfers_count": len(level0_records),
        "level0_transfers": level0_records[:max_events],
        "transactions_count": len(transactions),
        "transactions_sample": transactions[:max_events],
        "ctaphid_frames_count": len(ctaphid_frames),
        "ctaphid_frames": ctaphid_frames[:max_events],
        "errors_count": len(errors),
        "errors": errors[:max_events],
        "endpoints": endpoints,
    }


def print_analysis(report: Dict, as_json: bool = False):
    if as_json:
        print(json.dumps(report, indent=2))
        return

    print(f"=== USB Capture Summary ({report['csv_path']}) ===")
    print(f"Total CSV Records : {report['total_records']}")
    print(f"Top-Level Transfers: {report['level0_transfers_count']}")
    print(f"Transactions       : {report['transactions_count']}")
    print(f"Errors             : {report['errors_count']}")
    if report["endpoints"]:
        ep_str = ", ".join(f"{k} ({v})" for k, v in sorted(report["endpoints"].items()))
        print(f"Active Endpoints   : {ep_str}")

    if report["bus_events"]:
        print("\n--- Bus Events ---")
        for e in report["bus_events"]:
            print(f"  [{e['index']:>5}] {e['time']}  {e['event']} {e['summary']}")

    if report["level0_transfers"]:
        print("\n--- Control / Class Transfers (Level 0) ---")
        for r in report["level0_transfers"]:
            print(
                f"  [{r['index']:>5}] {r['time']} ({r['dur']}) Dev={r['dev']} Ep={r['ep']} "
                f"{r['record']} [{r['len']}] {r['summary']} | {r['data']}"
            )

    if report["ctaphid_frames"]:
        print("\n--- Decoded FIDO CTAPHID Frames ---")
        for c in report["ctaphid_frames"]:
            print(
                f"  [{c['index']:>5}] {c['time']} Dev={c['dev']} Ep={c['ep']} "
                f"{c['txn']} -> {c['ctaphid']}"
            )

    if report["errors"]:
        print("\n--- Bus / Packet Errors ---")
        for err in report["errors"]:
            print(
                f"  [{err['index']:>5}] {err['time']} Err={err['err']} "
                f"Dev={err['dev']} Ep={err['ep']} {err['record']}"
            )


def cmd_devices(args):
    remote = RemoteDataCenter(args.host, args.port)
    if remote.is_running():
        res = remote.send_commands(["connect show"])
        print(res[0][1])
    else:
        with StdioDataCenter(args.binary) as dc:
            print(dc.cmd("connect show"))


def cmd_capture(args):
    out_base = Path(args.output).expanduser().resolve()
    out_base.parent.mkdir(parents=True, exist_ok=True)
    tdc_path = out_base.with_suffix(".tdc")
    csv_path = out_base.with_suffix(".csv")

    with StdioDataCenter(args.binary) as dc:
        print(f"[1/5] Discovering & connecting to analyzer ({args.device})...")
        show_out = dc.cmd("connect show")
        print(show_out)
        conn_out = dc.cmd(f"connect {args.device}")
        print(conn_out)
        if "Unable to connect" in conn_out or "error" in conn_out.lower():
            print("ERROR: Could not connect to analyzer. Ensure USB permissions / BypassSandbox is enabled and no other Data Center GUI holds the device.", file=sys.stderr)
            sys.exit(2)

        dc.cmd("lens usb")
        dc.cmd("classify class")
        if args.vbus_override:
            dc.cmd("device {'usb.vbus_override': True}")

        print("[2/5] Starting capture...")
        run_out = dc.cmd("run")
        print(run_out)

        if args.exec_cmd:
            print(f"[3/5] Running command during capture: {args.exec_cmd}")
            subprocess.run(args.exec_cmd, shell=True)
            if args.duration > 0:
                time.sleep(args.duration)
        else:
            print(f"[3/5] Capturing traffic for {args.duration} seconds...")
            time.sleep(args.duration)

        print("[4/5] Stopping capture...")
        print(dc.cmd("stop", timeout=15.0))

        print(f"[5/5] Saving {tdc_path} and exporting {csv_path}...")
        print(dc.cmd(f"save '{tdc_path}' {{}} True", timeout=20.0))
        print(
            dc.cmd(
                f"export '{csv_path}' {{'visible_records': False, 'mirror_layout': False}} True",
                timeout=30.0,
            )
        )

    if csv_path.exists():
        report = analyze_csv(str(csv_path), max_events=args.max_events)
        print_analysis(report, as_json=args.json)


def cmd_start(args):
    remote = RemoteDataCenter(args.host, args.port)
    if not remote.start_daemon(args.binary):
        print(f"ERROR: Failed to start Data Center remote console on {args.host}:{args.port}", file=sys.stderr)
        sys.exit(1)

    cmds = [
        "stop",
        "connect show",
        f"connect {args.device}",
        "lens usb",
        "clear True",
    ]
    if args.vbus_override:
        cmds.append("device {'usb.vbus_override': True}")
    cmds.append("run")

    for cmd_str, out in remote.send_commands(cmds):
        print(f"> {cmd_str}\n{out}")


def cmd_stop(args):
    out_base = Path(args.output).expanduser().resolve()
    out_base.parent.mkdir(parents=True, exist_ok=True)
    tdc_path = out_base.with_suffix(".tdc")
    csv_path = out_base.with_suffix(".csv")

    remote = RemoteDataCenter(args.host, args.port)
    if not remote.is_running():
        print(f"ERROR: No running Data Center session found on {args.host}:{args.port}", file=sys.stderr)
        sys.exit(1)

    cmds = [
        "stop",
        "classify class",
        f"save '{tdc_path}' {{}} True",
        f"export '{csv_path}' {{'visible_records': False, 'mirror_layout': False}} True",
    ]
    if not args.keep_alive:
        cmds.append("exit(True)")

    for cmd_str, out in remote.send_commands(cmds, timeout=180.0):
        print(f"> {cmd_str}\n{out}")

    if csv_path.exists():
        report = analyze_csv(str(csv_path), max_events=args.max_events)
        print_analysis(report, as_json=args.json)


def cmd_raw(args):
    remote = RemoteDataCenter(args.host, args.port)
    if not remote.is_running():
        print(f"ERROR: No running Data Center session on {args.host}:{args.port}", file=sys.stderr)
        sys.exit(1)
    for cmd_str, out in remote.send_commands([args.command], timeout=15.0):
        print(out)


def cmd_analyze(args):
    in_path = Path(args.file).expanduser().resolve()
    if not in_path.exists():
        print(f"ERROR: File not found: {in_path}", file=sys.stderr)
        sys.exit(1)

    if in_path.suffix.lower() == ".tdc":
        csv_path = Path(args.csv_out).expanduser().resolve() if args.csv_out else Path("/tmp") / (in_path.stem + ".csv")
        with StdioDataCenter(args.binary) as dc:
            dc.cmd(f"open '{in_path}' True", timeout=20.0)
            dc.cmd("classify class")
            dc.cmd(
                f"export '{csv_path}' {{'visible_records': False, 'mirror_layout': False}} True",
                timeout=30.0,
            )
    else:
        csv_path = in_path

    report = analyze_csv(str(csv_path), max_events=args.max_events, include_nak=args.include_nak)
    print_analysis(report, as_json=args.json)


def main():
    parser = argparse.ArgumentParser(description="Total Phase Data Center & Beagle USB 12 CLI Controller")
    parser.add_argument("--binary", default=DEFAULT_DATACENTER_BIN, help="Path to Data Center binary")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Remote console host")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Remote console TCP port")

    sub = parser.add_subparsers(dest="subcommand", required=True)

    sub.add_parser("devices", help="List attached Total Phase analyzers")

    p_cap = sub.add_parser("capture", help="Run a one-shot timed or command-wrapped capture")
    p_cap.add_argument("-d", "--device", default="0", help="Analyzer port (0) or serial number (e.g. 1112-175360)")
    p_cap.add_argument("-t", "--duration", type=float, default=5.0, help="Capture duration in seconds")
    p_cap.add_argument("-e", "--exec", dest="exec_cmd", help="Shell command to execute while capturing")
    p_cap.add_argument("-o", "--output", default="/tmp/usb12_capture", help="Output base path (creates .tdc and .csv)")
    p_cap.add_argument("--vbus-override", action="store_true", help="Override VBUS detection")
    p_cap.add_argument("--max-events", type=int, default=80, help="Max events to print in summary")
    p_cap.add_argument("--json", action="store_true", help="Output analysis in JSON format")

    p_start = sub.add_parser("start", help="Start a persistent background capture session")
    p_start.add_argument("-d", "--device", default="0", help="Analyzer port (0) or serial number (e.g. 1112-175360)")
    p_start.add_argument("--vbus-override", action="store_true", help="Override VBUS detection")

    p_stop = sub.add_parser("stop", help="Stop background capture, export .tdc/.csv, and summarize")
    p_stop.add_argument("-o", "--output", default="/tmp/usb12_capture", help="Output base path (creates .tdc and .csv)")
    p_stop.add_argument("--keep-alive", action="store_true", help="Keep Data Center daemon open after stopping")
    p_stop.add_argument("--max-events", type=int, default=80, help="Max events to print in summary")
    p_stop.add_argument("--json", action="store_true", help="Output analysis in JSON format")

    p_cmd = sub.add_parser("cmd", help="Send a raw CLI command to a running Data Center session")
    p_cmd.add_argument("command", help="Data Center CLI command string")

    p_ana = sub.add_parser("analyze", help="Analyze an existing .tdc or .csv capture file")
    p_ana.add_argument("file", help="Path to .tdc or .csv file")
    p_ana.add_argument("--csv-out", help="Where to write exported CSV when input is .tdc")
    p_ana.add_argument("--max-events", type=int, default=80, help="Max events to print in summary")
    p_ana.add_argument("--include-nak", action="store_true", help="Include NAK/SOF polling records")
    p_ana.add_argument("--json", action="store_true", help="Output analysis in JSON format")

    sub.add_parser("_daemon", help=argparse.SUPPRESS)

    args = parser.parse_args()
    if args.subcommand == "devices":
        cmd_devices(args)
    elif args.subcommand == "capture":
        cmd_capture(args)
    elif args.subcommand == "start":
        cmd_start(args)
    elif args.subcommand == "stop":
        cmd_stop(args)
    elif args.subcommand == "cmd":
        cmd_raw(args)
    elif args.subcommand == "analyze":
        cmd_analyze(args)
    elif args.subcommand == "_daemon":
        cmd_daemon(args)


if __name__ == "__main__":
    main()
