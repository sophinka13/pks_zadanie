"""regresie chybnych paketov a konfliktov seq; pripravene s pomocou ai."""
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import zlib

from binary_protocol import encode_packet, decode_packet

ROOT = Path(__file__).resolve().parents[1]


# overi skutocny server pri neplatnych paketoch a odmietnutej aktivite
@unittest.skipUnless(os.environ.get("PKS_RUN_UDP_TESTS") == "1", "Set PKS_RUN_UDP_TESTS=1")
class RobustnessUDPTests(unittest.TestCase):
    # odmietnute data neobnovia casovac a duplicita sa nespracuje ako nove meranie
    def test_invalid_packets_and_conflicting_sequence(self):
        with tempfile.TemporaryDirectory(prefix="meteo-robustness-") as work:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            # kratky interval testuje rovnaky stavovy automat bez 15 s cakania
            code = "import sys; sys.path.insert(0, sys.argv.pop(1)); import server; server.IDLE_TIMEOUT=1.2; server.main()"
            process = subprocess.Popen([sys.executable, "-c", code, str(ROOT)], cwd=work,
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            try:
                process.stdin.write(f"127.0.0.1\n{port}\n")
                process.stdin.flush()
                log = Path(work, "server.log")
                deadline = time.monotonic()+5
                while time.monotonic() < deadline:
                    if log.exists() and "Server listening" in log.read_text():
                        break
                    time.sleep(0.02)
                self.assertIsNone(process.poll())
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    udp.settimeout(2)
                    target = ("127.0.0.1", port)
                    registration = dict(type="REGISTER", sensor_type="ThermoNode", sensor_id="T-01", seq=1, token=0)
                    valid = encode_packet(registration)
                    # chyby s platnym crc musia byt odmietnute aj po kontrole integrity
                    def checked(content):
                        return content+struct.pack("!I", zlib.crc32(content))
                    invalid = [b"", b"\xff", valid[:10], valid+b"extra",
                        checked(bytes([valid[0] | 1])+valid[1:-4]),
                        checked(bytes([valid[0] & 0x3f])+valid[1:-4])]
                    for packet in invalid:
                        udp.sendto(packet, target)
                    udp.sendto(valid, target)
                    reply = decode_packet(udp.recvfrom(65535)[0])
                    self.assertEqual(reply["type"], "REGISTER_ACK")
                    message = dict(type="DATA", sensor_type="ThermoNode", token=reply["token"], seq=2,
                        values=dict(temperature=21.3, humidity=55.4, dew_point=11.9, pressure=1013.25))
                    original = encode_packet(message)
                    for _ in range(2):
                        udp.sendto(original, target)
                        self.assertEqual(decode_packet(udp.recvfrom(65535)[0])["type"], "ACK")
                    accepted_at = time.monotonic()
                    time.sleep(0.75)
                    message["values"]["temperature"] = 22.0
                    udp.sendto(encode_packet(message), target)
                    conflict = decode_packet(udp.recvfrom(65535)[0])
                    self.assertEqual(conflict["type"], "REJECT")
                    self.assertEqual(conflict["reason_code"], 5)
                    # bez opravy by konflikt posunul prvu sondu na cca 1.95 s
                    udp.settimeout(0.8)
                    keepalive = decode_packet(udp.recvfrom(65535)[0])
                    self.assertEqual(keepalive["type"], "KEEPALIVE")
                    self.assertLess(time.monotonic()-accepted_at, 1.65)
                    # nove platne meranie funguje aj po vsetkych chybach
                    message["seq"] = 3
                    udp.sendto(encode_packet(message), target)
                    self.assertEqual(decode_packet(udp.recvfrom(65535)[0])["type"], "ACK")
                content = log.read_text()
                self.assertEqual(content.count("Measurement accepted:"), 2)
                self.assertEqual(content.count("Duplicate measurement received:"), 1)
                self.assertEqual(content.count("Invalid message:"), len(invalid))
                self.assertIn("Sequence number reused with different data", content)
                process.stdin.write("0\n")
                process.stdin.flush()
                process.wait(timeout=3)
                self.assertEqual(process.returncode, 0)
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGINT)
                _, errors = process.communicate(timeout=5)
                self.assertNotIn("Traceback", errors)
