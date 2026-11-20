"""kontroly porovnatelnosti a uctovania bajtov; pripravene s pomocou ai."""
import json
import unittest

from binary_protocol import decode_packet
from json_baseline.lib import verify_crc
from measure_efficiency import build_events, make_dataset, sizes


# overi rovnake vstupy, scenare a presne zapocitanie nizsich vrstiev
class EfficiencyTests(unittest.TestCase):
    # overi deterministicke vstupy a zachovanie hodnot v oboch vlastnych formatoch
    def test_equal_inputs(self):
        dataset = make_dataset(3)
        self.assertEqual(dataset, make_dataset(3))
        events = build_events(dataset)
        for variant in ("JSON", "Binary"):
            packets = [event for event in events if event["variant"] == variant and event["scenario"] == "steady" and event["message_type"] == "DATA"]
            self.assertEqual(len(packets), len(dataset))
            for event, row in zip(packets, dataset):
                decoded = decode_packet(event["packet"]) if variant == "Binary" else json.loads(event["packet"])
                self.assertEqual(decoded["values"], row["values"])
                if variant == "JSON":
                    self.assertTrue(verify_crc(decoded))

    # overi padding, fcs a casy obsadenia ethernetoveho media
    def test_layer_sizes(self):
        self.assertEqual(sizes(bytes(12)), dict(application_bytes=12, ip_bytes=40, ethernet_bytes=64, medium_byte_times=84))
        self.assertEqual(sizes(bytes(23)), dict(application_bytes=23, ip_bytes=51, ethernet_bytes=69, medium_byte_times=89))

    # overi pocty paketov a identicke opakovania pri strate ack
    def test_scenarios(self):
        events = build_events(make_dataset())
        for variant in ("JSON", "Binary"):
            groups = {}
            for event in events:
                if event["variant"] == variant:
                    groups.setdefault(event["scenario"], []).append(event)
            self.assertEqual(len(groups["registration"])+len(groups["steady"]), 488)
            self.assertEqual(len(groups["corruption"]), 4)
            self.assertEqual(len(groups["idle_responsive"]), 6)
            self.assertEqual(len(groups["disconnected"]), 3)
            loss = groups["ack_loss"]
            self.assertEqual(len(loss), 7)
            self.assertEqual([row["packet"] for row in loss[:3]], [loss[0]["packet"]]*3)
            self.assertEqual([row["packet"] for row in loss[3:6]], [loss[3]["packet"]]*3)
            self.assertEqual([row["time_seconds"] for row in loss[:6]], [0, 3, 6, 10, 13, 16])
            self.assertNotEqual(groups["corruption"][0]["packet"], groups["corruption"][2]["packet"])


if __name__ == "__main__":
    unittest.main()
