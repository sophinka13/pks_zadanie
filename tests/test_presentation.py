"""Kontroly scenarov z prezentacie, vytvorene s pomocou AI.

Bez siete: python3 -m unittest discover -s tests -v
Aj UDP: PKS_RUN_UDP_TESTS=1 python3 -m unittest discover -s tests -v
"""

import copy
import io
import json
import logging
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from datetime import datetime
from unittest.mock import patch

from lib import (
    SENSOR_FIELDS, ask_address, calculate_crc, create_logger,
    decode_message, encode_message, parse_sensor_value, validate_values,
)
from server import monitor_sessions, process_measurement, reset_activity
from tester import corrupt_measurement, generate_values, read_custom_values


ROOT = Path(__file__).resolve().parents[1]


class PresentationInputs(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()
        self.logger = logging.Logger("presentation-check")
        self.logger.addHandler(logging.StreamHandler(self.output))

    def test_invalid_addresses_and_ports_are_logged_and_can_be_corrected(self):
        entries = ["300.1.1.1", "127.0.0.1", "abc", "127.0.0.1", "65536", "", ""]
        with patch("builtins.input", side_effect=entries), redirect_stdout(io.StringIO()):
            self.assertEqual(ask_address("127.0.0.1", self.logger, "SERVER"), ("127.0.0.1", 9000))
        self.assertEqual(self.output.getvalue().count("Invalid address or port"), 3)

    def test_boundaries_of_every_sensor_field(self):
        for kind, fields in SENSOR_FIELDS.items():
            for name, (minimum, maximum, places) in fields.items():
                for boundary in (minimum, maximum):
                    with self.subTest(kind=kind, name=name, boundary=boundary):
                        self.assertEqual(parse_sensor_value(kind, name, str(boundary)), boundary)
                for invalid in (str(minimum - 1), str(maximum + 1), "NaN", "Infinity", "abc", ""):
                    with self.subTest(kind=kind, name=name, invalid=invalid):
                        with self.assertRaises(ValueError):
                            parse_sensor_value(kind, name, invalid)
                invalid_precision = str(minimum) + (".01" if places == 1 else ".001" if places == 2 else ".0")
                with self.assertRaises(ValueError):
                    parse_sensor_value(kind, name, invalid_precision)

    def test_precision_is_checked_before_float_rounding(self):
        with self.assertRaises(ValueError):
            parse_sensor_value("ThermoNode", "temperature", "21.300000000000000000000001")
        self.assertEqual(parse_sensor_value("ThermoNode", "temperature", "21.3000"), 21.3)

    def test_bad_custom_input_is_logged_then_corrected(self):
        entries = ["61", "nan", "21.33", "21.3", "55.4", "11.9", "1013.25"]
        with patch("builtins.input", side_effect=entries), redirect_stdout(io.StringIO()):
            values = read_custom_values("ThermoNode", self.logger, "TESTER:ThermoNode:T-01")
        self.assertEqual(values, dict(temperature=21.3, humidity=55.4, dew_point=11.9, pressure=1013.25))
        self.assertEqual(self.output.getvalue().count("Invalid custom value"), 3)

    def test_bad_values_are_rejected_by_server_even_with_valid_crc(self):
        address = ("127.0.0.1", 12345)
        for kind, fields in SENSOR_FIELDS.items():
            for field, (_, maximum, _) in fields.items():
                message = dict(type="DATA", seq=1, sensor_id="test", token="valid", values=generate_values(kind))
                message["values"][field] = maximum + 1
                message["crc"] = calculate_crc(message)
                sessions = {"test": dict(sensor_type=kind, token="valid", address=address)}
                self.assertIsNotNone(process_measurement(message, address, sessions))

    def test_corruption_preserves_original_and_repair_works_for_all_types(self):
        address = ("127.0.0.1", 12345)
        for kind in SENSOR_FIELDS:
            message = dict(type="DATA", seq=1, sensor_id="test", token="valid", values=generate_values(kind))
            message["crc"] = calculate_crc(message)
            original = copy.deepcopy(message)
            damaged = corrupt_measurement(message, kind)
            sessions = {"test": dict(sensor_type=kind, token="valid", address=address)}
            self.assertEqual(message, original)
            self.assertEqual(process_measurement(damaged, address, sessions), "Integrity check failed")
            self.assertIsNone(process_measurement(original, address, sessions))

    def test_disconnect_timing_and_token_invalidation(self):
        class CaptureSocket:
            def __init__(self):
                self.sent = []

            def sendto(self, data, address):
                self.sent.append(decode_message(data))

        udp = CaptureSocket()
        session = dict(sensor_type="ThermoNode", token="old", address=("127.0.0.1", 12345))
        reset_activity(session, 0)
        sessions = {"test": session}
        seq = 1
        for now, count, active in [(14.999, 0, True), (15, 1, True), (20, 2, True), (25, 3, True), (29.999, 3, True), (30, 3, False)]:
            seq = monitor_sessions(udp, sessions, self.logger, seq, now)
            self.assertEqual(len(udp.sent), count)
            self.assertEqual(bool(sessions), active)
        self.assertIn("SENSOR IDLE", self.output.getvalue())
        self.assertIn("SENSOR DISCONNECTED", self.output.getvalue())
        self.assertEqual(process_measurement(dict(sensor_id="test", token="old"), session["address"], sessions), "Invalid sensor ID or token")

    def test_new_run_replaces_old_log_without_duplicate_handlers(self):
        with tempfile.TemporaryDirectory() as work:
            name = str(Path(work) / "check")
            try:
                create_logger(name).info("OLD RUN")
                create_logger(name).info("NEW RUN")
                content = Path(name + ".log").read_text()
                self.assertNotIn("OLD RUN", content)
                self.assertEqual(content.count("NEW RUN"), 1)
            finally:
                for handler in list(logging.getLogger(name).handlers):
                    handler.close()
                    logging.getLogger(name).removeHandler(handler)


@unittest.skipUnless(os.environ.get("PKS_RUN_UDP_TESTS") == "1", "UDP test: nastav PKS_RUN_UDP_TESTS=1")
class PresentationUDP(unittest.TestCase):
    def test_presentation_uat_1_to_4(self):
        with tempfile.TemporaryDirectory(prefix="pks-presentation-") as work:
            processes = []
            server_log = Path(work) / "server.log"
            tester_log = Path(work) / "tester.log"
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]

            def read(path):
                return path.read_text() if path.exists() else ""

            def wait_for(check, timeout=5):
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    if check():
                        return
                    time.sleep(0.05)
                self.fail("Timeout\n" + read(server_log) + "\n" + read(tester_log))

            def send(process, text):
                process.stdin.write(text)
                process.stdin.flush()

            def start(name):
                process = subprocess.Popen(
                    [sys.executable, str(ROOT / name)], cwd=work,
                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True,
                )
                processes.append(process)
                send(process, f"999.1.1.1\n127.0.0.1\n-1\n127.0.0.1\n{port}\n")
                return process

            def messages(path, direction):
                marker = f"| {direction} "
                return [json.loads(line.split(marker, 1)[1]) for line in read(path).splitlines() if marker + "{" in line]

            try:
                server = start("server.py")
                wait_for(lambda: "Server listening" in read(server_log))
                tester = start("tester.py")
                wait_for(lambda: read(tester_log).count("Measurement acknowledged") >= 4)
                workers = [line for line in read(tester_log).splitlines() if "Sensor worker started:" in line]
                self.assertEqual(len(workers), 4)
                self.assertEqual(len({line.split("UDP port ")[1] for line in workers}), 4)
                for sensor_id in ("T-01", "W-01", "R-01", "A-01"):
                    self.assertTrue(any(f"sensor-{sensor_id}," in line for line in workers))
                self.assertEqual(read(server_log).count("Invalid address or port"), 2)
                self.assertEqual(read(tester_log).count("Invalid address or port"), 2)
                print("UAT 1: nespravna IP/port zalogovane, oprava a styri registracie OK", flush=True)

                send(tester, "1\n1\n61\n21.300000000000000001\n21.3\n-1\n55.4\n11.9\n799\n1013.25\n")
                wait_for(lambda: read(tester_log).count("Measurement acknowledged") >= 5)
                self.assertEqual(read(tester_log).count("Invalid custom value"), 4)
                expected = dict(temperature=21.3, humidity=55.4, dew_point=11.9, pressure=1013.25)
                self.assertTrue(any(m.get("values") == expected for m in messages(server_log, "Received")))
                print("UAT 2: neplatne hodnoty odmietnute a zalogovane, presne custom hodnoty prijate", flush=True)

                # Poskodime skutocne nasledujucu automaticku spravu kazdeho senzora.
                for index in range(1, 5):
                    send(tester, f"2\n{index}\n")
                wait_for(lambda: read(tester_log).count("Measurement acknowledged") >= 9, 13)
                for sensor_id in ("T-01", "W-01", "R-01", "A-01"):
                    data = [m for m in messages(server_log, "Received") if m.get("type") == "DATA" and m.get("sensor_id") == sensor_id]
                    repeated = [m for m in data if sum(other["seq"] == m["seq"] for other in data) == 2]
                    self.assertEqual(len(repeated), 2)
                    self.assertNotEqual(repeated[0]["values"], repeated[1]["values"])
                    self.assertEqual(repeated[0]["crc"], repeated[1]["crc"])
                print("UAT 3: poskodenie, RETRANSMIT a oprava vsetkych styroch senzorov OK", flush=True)

                def thermo_tokens():
                    prefix = "TESTER:ThermoNode:T-01 | Received "
                    replies = [json.loads(line.split(prefix, 1)[1]) for line in read(tester_log).splitlines() if prefix + "{" in line]
                    return [m["token"] for m in replies if m.get("type") == "ACK" and "token" in m]

                old_token = thermo_tokens()[0]
                send(tester, "3\n1\n")
                wait_for(lambda: "SENSOR IDLE: ThermoNode:T-01" in read(server_log), 18)
                wait_for(lambda: any(m.get("type") == "KEEPALIVE_ACK" for m in messages(tester_log, "Sent")))
                self.assertNotIn("SENSOR DISCONNECTED: ThermoNode:T-01", read(server_log))
                print("UAT 4: vypnute merania, SENSOR IDLE a KEEPALIVE_ACK OK", flush=True)
                before = read(server_log).count("Measurement accepted: ThermoNode:T-01")
                send(tester, "3\n1\n")
                wait_for(lambda: read(server_log).count("Measurement accepted: ThermoNode:T-01") > before)
                send(tester, "4\n1\n")
                wait_for(lambda: "Local session closed: user request" in read(tester_log))
                send(tester, "5\n1\n")
                wait_for(lambda: "Registration rejected: Sensor ID is already registered" in read(tester_log))
                wait_for(lambda: "SENSOR DISCONNECTED: ThermoNode:T-01" in read(server_log), 33)
                lines = read(server_log).splitlines()
                last_data = next(line for line in reversed(lines) if "Measurement accepted: ThermoNode:T-01" in line)
                disconnected = next(line for line in lines if "SENSOR DISCONNECTED: ThermoNode:T-01" in line)
                stamp = lambda line: datetime.fromisoformat(line.split(" | ")[0].replace("Z", "+00:00"))
                elapsed = (stamp(disconnected) - stamp(last_data)).total_seconds()
                self.assertGreaterEqual(elapsed, 29.8)
                self.assertLess(elapsed, 30.7)
                send(tester, "5\n1\n")
                wait_for(lambda: read(server_log).count("Sensor registered: ThermoNode:T-01") == 2)
                wait_for(lambda: read(server_log).count("Measurement accepted: ThermoNode:T-01") > before + 1)
                self.assertNotEqual(thermo_tokens()[-1], old_token)
                print(f"UAT 4: odpojenie po {elapsed:.3f} s, predcasna registracia odmietnuta, novy token a merania OK", flush=True)
                for process in (tester, server):
                    send(process, "0\n")
                    process.wait(timeout=3)
                    self.assertEqual(process.returncode, 0)
                self.assertEqual(read(tester_log).count("Sensor worker stopped"), 4)
            finally:
                for process in reversed(processes):
                    if process.poll() is None:
                        process.send_signal(signal.SIGINT)
                    process.communicate(timeout=5)

    def test_unresponsive_sensor_does_not_block_other_workers(self):
        with tempfile.TemporaryDirectory(prefix="pks-independent-") as work:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
                server.bind(("127.0.0.1", 0))
                server.settimeout(0.2)
                process = subprocess.Popen(
                    [sys.executable, str(ROOT / "tester.py")], cwd=work,
                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True,
                )
                try:
                    process.stdin.write(f"127.0.0.1\n{server.getsockname()[1]}\n")
                    process.stdin.flush()
                    registered = {}
                    measured = set()
                    deadline = time.monotonic() + 4.5
                    while time.monotonic() < deadline:
                        try:
                            data, sender = server.recvfrom(65535)
                        except socket.timeout:
                            continue
                        message = decode_message(data)
                        sensor_id = message.get("sensor_id")
                        if message["type"] == "REGISTER":
                            registered[sensor_id] = sender
                            if sensor_id == "T-01":
                                # Jednemu senzoru nikdy neposleme registracne ACK.
                                continue
                            reply = dict(type="ACK", seq=1, ack_for=message["seq"], token=sensor_id)
                        elif message["type"] == "DATA":
                            measured.add(sensor_id)
                            reply = dict(type="ACK", seq=2, ack_for=message["seq"])
                        else:
                            continue
                        server.sendto(encode_message(reply), sender)
                    self.assertEqual(len(set(registered.values())), 4)
                    self.assertEqual(measured, {"W-01", "R-01", "A-01"})
                    log = Path(work, "tester.log").read_text()
                    self.assertIn("TESTER:ThermoNode:T-01 | Registration timed out", log)
                    self.assertEqual(log.count("Measurement acknowledged"), 3)
                    process.stdin.write("0\n")
                    process.stdin.flush()
                    process.wait(timeout=3)
                    self.assertEqual(process.returncode, 0)
                    self.assertEqual(Path(work, "tester.log").read_text().count("Sensor worker stopped"), 4)
                finally:
                    if process.poll() is None:
                        process.send_signal(signal.SIGINT)
                    process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
