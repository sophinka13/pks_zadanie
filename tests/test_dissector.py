"""overenie lua dissektora cez skutocny tshark; pripravene s pomocou ai."""
import json
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import tempfile
import unittest
import zlib

from binary_protocol import encode_packet, MESSAGE_TYPES
from lib import SENSOR_FIELDS

ROOT = Path(__file__).resolve().parents[1]
TSHARK = shutil.which("tshark") or ("/Applications/Wireshark.app/Contents/MacOS/tshark" if Path("/Applications/Wireshark.app/Contents/MacOS/tshark").exists() else None)


# zapise ethernet ipv4 udp ramce do pcap bez potreby pristupu k sieti
def write_capture(path, packets, port=9000):
    with open(path, "wb") as output:
        output.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for index, payload in enumerate(packets):
            udp = struct.pack("!HHHH", 40000, port, 8+len(payload), 0) + payload
            ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20+len(udp), index, 0, 64, 17, 0, b"\x7f\0\0\1", b"\x7f\0\0\1")
            total = sum(struct.unpack("!10H", ip))
            while total >> 16:
                total = (total & 65535) + (total >> 16)
            ip = ip[:10] + struct.pack("!H", total ^ 65535) + ip[12:]
            frame = bytes.fromhex("00112233445566778899aabb0800") + ip + udp
            output.write(struct.pack("<IIII", 1700000000+index, 0, len(frame), len(frame)))
            output.write(frame)


# overi vsetky spravy, hodnoty aj chybne datagramy v realnom wireshark jadre
@unittest.skipUnless(TSHARK, "TShark is not installed")
class DissectorTests(unittest.TestCase):
    # spusti dissektor bez instalacie pluginu do pouzivatelskeho profilu
    def dissect(self, packets, extra=(), port=9000):
        with tempfile.TemporaryDirectory(prefix="meteo-dissector-") as work:
            capture = Path(work, "test.pcap")
            write_capture(capture, packets, port)
            result = subprocess.run([TSHARK, "-X", "lua_script:"+str(ROOT / "lua/fiit_meteo.lua"), "-r", str(capture), *extra, "-T", "json"], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("Lua Error", result.stderr)
            self.assertNotIn("Error during loading", result.stderr)
            decoded = json.loads(result.stdout)
            self.assertNotIn("Lua Error", result.stdout)
            return [row["_source"]["layers"] for row in decoded]

    # porovna vsetky parametre vratane hranic s python encoderom
    def test_messages_and_values(self):
        packets, expected = [], []
        rng = random.Random(12)
        for sensor, fields in SENSOR_FIELDS.items():
            for kind in MESSAGE_TYPES:
                for sample in range(12 if kind == "DATA" else 1):
                    message = dict(type=kind, sensor_type=sensor, seq=123, token=0xfedcba9876543210)
                    if kind == "REGISTER":
                        message.update(token=0, sensor_id="senzor-ž")
                    elif kind == "REJECT":
                        message["reason_code"] = 3
                    elif kind == "DATA":
                        values = {}
                        for name, (lo, hi, places) in fields.items():
                            scale = 10**places
                            code = 0 if sample == 0 else int((hi-lo)*scale) if sample == 1 else rng.randint(0, int((hi-lo)*scale))
                            value = (int(lo*scale)+code)/scale
                            values[name] = int(value) if places == 0 else value
                        message["values"] = values
                    packets.append(encode_packet(message))
                    expected.append(message)
        layers = self.dissect(packets)
        for actual, message in zip(layers, expected):
            tree = actual["fiitmeteo"]
            self.assertNotIn("fiitmeteo.malformed", json.dumps(tree))
            self.assertEqual(tree["fiitmeteo.crc_ok"], "1")
            self.assertEqual(int(tree["fiitmeteo.type"]), MESSAGE_TYPES.index(message["type"]))
            self.assertEqual(int(tree["fiitmeteo.token"], 16), message["token"])
            if message["type"] == "REGISTER":
                self.assertEqual(tree["fiitmeteo.id"], message["sensor_id"])
            if message["type"] == "DATA":
                subtree = tree["fiitmeteo.payload_tree"]
                for name, value in message["values"].items():
                    self.assertAlmostEqual(float(subtree["fiitmeteo."+name]), value)

    # overi chybne crc a strukturu vratane vsetkych skratenych dlzok
    def test_malformed_packets(self):
        packet = encode_packet(dict(type="DATA", sensor_type="ThermoNode", seq=1, token=1,
            values=dict(temperature=21.3, humidity=55.4, dew_point=11.9, pressure=1013.25)))
        # prepocita crc aby sa strukturala chyba testovala nezavisle od integrity
        def checked(content):
            return content + struct.pack("!I", zlib.crc32(content))
        bad_crc = packet[:-1] + bytes([packet[-1] ^ 1])
        malformed = [packet[:size] for size in range(1, len(packet))]
        malformed += [checked(bytes([packet[0] | 1])+packet[1:-4]), checked(packet[:13]+b"\xff"*6),
            checked(packet[:18]+bytes([packet[18] | 1])), checked(packet[:-4]+b"\0")]
        decoded = self.dissect([bad_crc]+malformed)
        self.assertEqual(decoded[0]["fiitmeteo"]["fiitmeteo.crc_ok"], "0")
        self.assertIn("fiitmeteo.bad_crc", json.dumps(decoded[0]))
        for layers in decoded[1:]:
            self.assertIn("fiitmeteo.malformed", json.dumps(layers))

    # overi hodnoty priamo v info stlpci a importovane farby v skutocnom tsharku
    def test_info_and_colors(self):
        packets = []
        for sensor, fields in SENSOR_FIELDS.items():
            values = {name: lo for name, (lo, hi, places) in fields.items()}
            packets.append(encode_packet(dict(type="DATA", sensor_type=sensor, seq=2, token=1, values=values)))
        with tempfile.TemporaryDirectory() as work:
            path = Path(work, "test.pcap")
            write_capture(path, packets, port=9100)
            shutil.copy(ROOT/"lua/fiit_meteo_colors.txt", Path(work, "colorfilters"))
            result = subprocess.run([TSHARK, "-X", "lua_script:"+str(ROOT/"lua/fiit_meteo.lua"),
                "--color", "-r", str(path), "-T", "fields", "-e", "frame.coloring_rule.name", "-e", "_ws.col.Info"],
                env=dict(os.environ, WIRESHARK_CONFIG_DIR=work), capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("Error during loading", result.stderr)
            for sensor in SENSOR_FIELDS:
                self.assertIn("FIIT "+sensor, result.stdout)
            for value in ("temperature=-50.0 °C", "humidity=0.0 %", "pressure=800.00 hPa",
                          "wind_speed=0.0 m/s", "rainfall=0.0 mm", "co2=300 ppm"):
                self.assertIn(value, result.stdout)

    # overi nastavitelny port aj manualne decode as
    def test_custom_port(self):
        packet = encode_packet(dict(type="ACK", sensor_type="WindSense", seq=1, token=1))
        for options in (("-o", "fiitmeteo.port:9100"), ("-d", "udp.port==9100,fiitmeteo")):
            self.assertIn("fiitmeteo", self.dissect([packet], options, port=9100)[0])


if __name__ == "__main__":
    unittest.main()
