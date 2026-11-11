# Total Phase Data Center & Beagle USB Capture Skill (`totalphase-datacenter`)

Automation skill and Python CLI controller (`datacenter_ctl.py`) for **Total Phase Data Center Software** (`/Applications/Data Center.app/bin/datacenter`) and **Beagle USB Protocol Analyzers** (Beagle USB 12, USB 480, USB 5000).

Captures live USB bus traffic, exports raw `.tdc` and full hierarchical `.csv` traces, and decodes USB enumeration, Control/Class transfers, HID reports, and FIDO2/U2F (`CTAPHID`) frames (including `CTAPHID_INIT`, `CTAPHID_CBOR`, `CTAPHID_MSG`, `CTAPHID_PING`, `CTAPHID_KEEPALIVE`, `CTAPHID_WINK`, `CTAPHID_CANCEL`, and `CTAPHID_ERROR`, plus FIDO2 CBOR command tags `0x01`–`0x0D`).

## Repository Contents

- [`SKILL.md`](./SKILL.md) — Agent skill instructions for Google Antigravity / AI coding assistants.
- [`scripts/datacenter_ctl.py`](./scripts/datacenter_ctl.py) — Standalone CLI utility & persistent TCP proxy daemon for driving Total Phase Data Center via its `-c` (stdio) and `-r` (remote console) interfaces.

## Installation as an Antigravity Skill

Clone this repository directly into your Antigravity skills directory:

```bash
mkdir -p ~/.gemini/config/skills
git clone https://github.com/ve7jtb/totalphase-datacenter.git ~/.gemini/config/skills/totalphase-datacenter
```

## Standalone CLI Usage

### 1. List Connected Total Phase Analyzers
```bash
python3 scripts/datacenter_ctl.py devices
```

### 2. One-Shot Timed or Command-Wrapped Capture
```bash
# Capture 10 seconds of USB traffic on analyzer port 0
python3 scripts/datacenter_ctl.py capture -d 0 -t 10 -o /tmp/usb12_capture

# Capture while executing a test command, plus 2 seconds of trailing traffic
python3 scripts/datacenter_ctl.py capture -d 0 -e "pytest tests/ctap_test.py" -t 2 -o /tmp/usb12_test
```

### 3. Interactive Multi-Step Background Capture (`start` / `stop`)
```bash
# Start background capture daemon (prevents App Nap via caffeinate -i)
python3 scripts/datacenter_ctl.py start -d 0

# ... perform USB activity or run tests ...

# Stop capture, save .tdc + .csv, and print protocol & CTAPHID summary
python3 scripts/datacenter_ctl.py stop -o /tmp/usb12_session
```

### 4. Analyze an Existing `.tdc` or `.csv` Capture
```bash
python3 scripts/datacenter_ctl.py analyze /path/to/capture.tdc
python3 scripts/datacenter_ctl.py analyze /path/to/capture.csv --json
```
