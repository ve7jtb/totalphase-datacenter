#!/usr/bin/env python3
"""USB 12/480 SDK capture. JSON status on stdout; raw JSONL and CSV on disk.
A line on stdin or parent EOF stops capture. No Data Center/.tdc dependency.
"""
import argparse
import csv
import importlib
import json
from pathlib import Path
import sys
import threading


def capture(sdk, port, output, stop):
    def check(value, operation):
        if value < 0:
            raise RuntimeError(f"{operation}: {sdk.bg_status_string(value)} ({value})")
        return value

    count, ports, _ = sdk.bg_find_devices_ext(16, 16)
    check(count, "enumerate analyzers")
    if port not in list(ports[:count]):
        raise RuntimeError(f"No available Beagle analyzer on port {port}; check USB passthrough and permissions")
    handle = check(sdk.bg_open(port), "open analyzer")
    if handle == 0:
        raise RuntimeError("SDK returned an invalid analyzer handle")
    enabled = False
    rows = 0
    try:
        features = check(sdk.bg_features(handle), "read features")
        if not features & sdk.BG_FEATURE_USB or features & sdk.BG_FEATURE_USB_SS:
            raise RuntimeError("This capture backend requires a Beagle USB 12 or USB 480")
        rate = check(sdk.bg_samplerate(handle, 0), "query sample rate")
        if rate == 0:
            raise RuntimeError("Invalid sample rate")
        check(sdk.bg_timeout(handle, 250), "set read timeout")
        check(sdk.bg_latency(handle, 200), "set latency")
        if features & sdk.BG_FEATURE_USB_HS:
            check(sdk.bg_usb_configure(handle, sdk.BG_USB_CAPTURE_USB2,
                                      sdk.BG_USB_TRIGGER_MODE_IMMEDIATE), "configure USB2 capture")
        prefix = Path(output)
        prefix.parent.mkdir(parents=True, exist_ok=True)
        with open(str(prefix) + '.jsonl', 'x', buffering=1) as raw, open(str(prefix) + '.csv', 'x', newline='', buffering=1) as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=['index', 'time_ns', 'duration_ticks', 'data_offset', 'status', 'events', 'length', 'data_hex'])
            writer.writeheader()
            raw.write(json.dumps({'type': 'metadata', 'sample_rate_khz': rate, 'port': port}) + '\n')
            check(sdk.bg_enable(handle, sdk.BG_PROTOCOL_USB), "enable capture")
            enabled = True
            print(json.dumps({'event': 'ready', 'output': str(prefix)}), flush=True)
            while not stop.is_set():
                if features & sdk.BG_FEATURE_USB_HS:
                    length, status, events, sop, duration, offset, packet = sdk.bg_usb2_read(handle, 65536)
                else:
                    length, status, events, sop, duration, offset, packet, _ = sdk.bg_usb2_read_bit_timing(handle, 1024, 8192)
                check(length, "read USB packet")
                if not length and not events and status in (0, sdk.BG_READ_TIMEOUT):
                    continue
                row = dict(index=rows, time_ns=sop * 1000000 // rate, duration_ticks=duration,
                           data_offset=offset, status=status, events=events, length=length,
                           data_hex=bytes(packet[:length]).hex())
                raw.write(json.dumps(row) + '\n')
                writer.writerow(row)
                rows += 1
        print(json.dumps({'event': 'stopped', 'packets': rows, 'output': str(prefix)}), flush=True)
    finally:
        try:
            if enabled:
                check(sdk.bg_disable(handle), "disable capture")
        finally:
            sdk.bg_close(handle)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk', required=True, help='SDK root or its python directory')
    parser.add_argument('--port', type=int, default=0)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    sdk_path = Path(args.sdk).expanduser()
    if (sdk_path / 'python').is_dir():
        sdk_path /= 'python'
    sys.path.insert(0, str(sdk_path))
    stop = threading.Event()
    def wait_for_stop():
        sys.stdin.readline()
        stop.set()
    threading.Thread(target=wait_for_stop, daemon=True).start()
    try:
        capture(importlib.import_module('beagle_py'), args.port, args.output, stop)
    except Exception as error:
        print(json.dumps({'event': 'error', 'message': str(error)}), flush=True)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
