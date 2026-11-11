---
name: totalphase-datacenter
description: >-
  Automate Total Phase Data Center Software and Beagle USB 12 / 480 / 5000 protocol analyzers to
  capture, export (.tdc / .csv), and analyze USB, HID, and FIDO2/U2F (CTAPHID) bus traffic. Use
  this skill whenever the user asks to capture USB traffic, control a Total Phase Beagle analyzer
  or Data Center, or inspect `.tdc` / Data Center `.csv` capture files.
---

# Total Phase Data Center & Beagle USB Capture Skill

This skill enables Antigravity to control **Total Phase Data Center Software** (`/Applications/Data Center.app/bin/datacenter`) and attached **Beagle USB Protocol Analyzers** (including the Beagle USB 12, serial `1112-175360`) to capture live USB traffic, export `.tdc` and `.csv` trace files, and analyze USB enumeration, Control/Class transfers, HID reports, and FIDO2/U2F (`CTAPHID`) frames.

## Helper Script

All operations are encapsulated in:
- [datacenter_ctl.py](./scripts/datacenter_ctl.py)

> **Important Sandbox Note for Live Hardware Capture:**
> Accessing physical USB hardware (`IOKit`) or binding a localhost TCP port (`-r`) requires running `datacenter_ctl.py` with `BypassSandbox: true` in `run_command` (otherwise `connect show` will report `Avail: No`).
> Offline analysis of existing `.tdc` or `.csv` files (`analyze`) works inside the standard sandbox (`BypassSandbox: false`).

---

## Common Workflows

### 1. List Connected Total Phase Analyzers
Check whether the Beagle USB 12 (or another Total Phase analyzer) is connected and available (`Avail: Yes`):

```bash
python3 ~/.gemini/config/skills/totalphase-datacenter/scripts/datacenter_ctl.py devices
```
*(Run with `BypassSandbox: true` so macOS allows USB device inspection.)*

---

### 2. One-Shot Timed or Command-Wrapped Capture (`capture`)
Use `capture` when capturing for a fixed duration (`-t SECONDS`) or while executing a test command (`-e "COMMAND"`). This uses Data Center's stdio console (`-c`) so no background daemon is left running:

```bash
# Capture 10 seconds of USB traffic on port 0 (or serial 1112-175360)
python3 ~/.gemini/config/skills/totalphase-datacenter/scripts/datacenter_ctl.py capture \
  -d 0 -t 10 -o /tmp/usb12_capture

# Capture while running a test command, plus 2 seconds trailing capture
python3 ~/.gemini/config/skills/totalphase-datacenter/scripts/datacenter_ctl.py capture \
  -d 0 -e " your_test_command_here " -t 2 -o /tmp/usb12_test
```

Outputs:
- `/tmp/usb12_capture.tdc` (raw Total Phase Data Center capture file)
- `/tmp/usb12_capture.csv` (full hierarchical protocol export)
- Structured summary of Bus Events, Level 0 Control/Class transfers, Endpoints, Errors, and decoded FIDO `CTAPHID` frames.

---

### 3. Interactive Multi-Step Capture (`start` / `stop`)
Use `start` and `stop` when the user wants to manually plug in a device, press a button, or run an external app while Data Center records in the background:

1. **Start background capture** (launches `datacenter -m --no-splash -r 127.0.0.1:5042` and runs `connect` + `run`):
   ```bash
   python3 ~/.gemini/config/skills/totalphase-datacenter/scripts/datacenter_ctl.py start -d 0
   ```
2. **Ask the user (or run the target workflow) to perform the USB activity.**
3. **Stop capture, save `.tdc` + `.csv`, and print analysis:**
   ```bash
   python3 ~/.gemini/config/skills/totalphase-datacenter/scripts/datacenter_ctl.py stop -o /tmp/usb12_session
   ```

---

### 4. Analyze an Existing `.tdc` or `.csv` Capture (`analyze`)
Convert any `.tdc` file into `.csv` and summarize its USB & CTAPHID traffic (can run with `BypassSandbox: false`):

```bash
python3 ~/.gemini/config/skills/totalphase-datacenter/scripts/datacenter_ctl.py analyze /path/to/capture.tdc
```

Add `--json` for machine-readable JSON output or `--include-nak` if you need to inspect low-level `NAK`/`SOF` polling timing.

---

## Direct Data Center CLI Reference

When sending custom commands via `datacenter_ctl.py cmd "<command>"`:
- `connect show` — list connected analyzers and availability
- `connect 0` or `connect 1112-175360` — connect to Beagle USB 12
- `lens usb` — set protocol lens to USB
- `classify class` — group packets into USB transactions (`Level 1`) and Class/Control transfers (`Level 0`)
- `device {'usb.vbus_override': True}` — capture even if VBUS is not standard 5V
- `run` / `stop` — start / stop capture
- `save '/path/file.tdc' {} True` — save `.tdc` capture file (overwriting if needed)
- `export '/path/file.csv' {'visible_records': False, 'mirror_layout': False} True` — export all columns and records to CSV
- `exit(True)` — force close Data Center without GUI save prompt
