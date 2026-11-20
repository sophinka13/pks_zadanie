"""overenie analyzy zivych zachytov; pripravene s pomocou ai."""
from pathlib import Path
import tempfile
import unittest

from measure_efficiency import build_events, make_dataset, write_pcap
from measure_live import analyse_capture
from test_dissector import TSHARK


# overi nezavislu kontrolu pcap a odmietnutie strateneho alebo pridaneho paketu
@unittest.skipUnless(TSHARK, "TShark is not installed")
class LiveCaptureTests(unittest.TestCase):
    # overi zhodu payloadov, ip dlzok a oddelenie registracii od merani
    def test_capture_accounting(self):
        for variant in ("JSON", "Binary"):
            events = [event for event in build_events(make_dataset(1)) if event["variant"] == variant and event["scenario"] in ("registration", "steady")]
            packets = [event["packet"] for event in events]
            with tempfile.TemporaryDirectory() as work:
                path = Path(work, "fixture.pcap")
                write_pcap(path, events, 9000)
                summary, verified = analyse_capture(path, packets, variant, 1)
                self.assertEqual(verified["captured_packets"], 16)
                self.assertEqual(sum(row["packets"] for row in summary), 16)
                self.assertEqual(sum(row["application_bytes"] for row in summary), sum(map(len, packets)))
                self.assertEqual({row["scenario"]: row["packets"] for row in summary}, dict(registration=8, steady=8))
                with self.assertRaisesRegex(RuntimeError, "Capture mismatch"):
                    analyse_capture(path, packets[:-1], variant, 1)
