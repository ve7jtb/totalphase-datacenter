import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest

spec = importlib.util.spec_from_file_location('capture', Path(__file__).parents[1] / 'scripts/beagle_sdk_capture.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class SDK:
    BG_FEATURE_USB = 4
    BG_FEATURE_USB_HS = 16
    BG_FEATURE_USB_SS = 32
    BG_PROTOCOL_USB = 2
    BG_READ_TIMEOUT = 256
    def __init__(self, stop, fail=False):
        self.stop, self.fail, self.closed, self.disabled = stop, fail, False, False
    def bg_find_devices_ext(self, *_): return 1, [0], [123]
    def bg_open(self, port): return 1
    def bg_features(self, handle): return 4
    def bg_samplerate(self, *_): return 60000
    def bg_timeout(self, *_): return 0
    def bg_latency(self, *_): return 0
    def bg_enable(self, *_): return 0
    def bg_disable(self, *_): self.disabled = True; return 0
    def bg_close(self, *_): self.closed = True; return 0
    def bg_status_string(self, code): return 'simulated SDK failure'
    def bg_usb2_read_bit_timing(self, *_):
        self.stop.set()
        return (-1 if self.fail else 3), 0, 0, 60000, 4, 0, bytes([0xc3, 1, 2]), []

class CaptureTests(unittest.TestCase):
    def test_packet_output_and_cleanup(self):
        stop = threading.Event(); sdk = SDK(stop)
        with tempfile.TemporaryDirectory() as tmp:
            output = str(Path(tmp) / 'capture')
            module.capture(sdk, 0, output, stop)
            rows = [json.loads(line) for line in Path(output + '.jsonl').read_text().splitlines()]
            self.assertEqual(rows[1]['time_ns'], 1000000)
            self.assertEqual(rows[1]['data_hex'], 'c30102')
            self.assertIn('c30102', Path(output + '.csv').read_text())
        self.assertTrue(sdk.closed and sdk.disabled)
    def test_read_error_closes_hardware(self):
        stop = threading.Event(); sdk = SDK(stop, True)
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RuntimeError, 'read USB packet'):
                module.capture(sdk, 0, str(Path(tmp) / 'capture'), stop)
        self.assertTrue(sdk.closed and sdk.disabled)
    def test_absent_device_fails_before_open(self):
        sdk = SDK(threading.Event())
        sdk.bg_find_devices_ext = lambda *_: (0, [], [])
        with self.assertRaisesRegex(RuntimeError, 'No available Beagle'):
            module.capture(sdk, 0, 'unused', sdk.stop)

if __name__ == '__main__': unittest.main()
