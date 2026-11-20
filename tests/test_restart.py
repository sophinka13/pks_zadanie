"""zive scenare vypadku a restartu; pripravene s pomocou ai."""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from binary_protocol import encode_packet, decode_packet

ROOT = Path(__file__).resolve().parents[1]


# overi povodne 30 s casovanie aj obnovu relacii po strate stavu servera
@unittest.skipUnless(os.environ.get("PKS_RUN_UDP_TESTS") == "1", "Set PKS_RUN_UDP_TESTS=1")
class RestartTests(unittest.TestCase):
    # po dlhsom aj kratkom vypadku sa da znovu registrovat bez restartu testera
    def test_outage_restart_and_independent_recovery(self):
        with tempfile.TemporaryDirectory(prefix="meteo-restart-") as directory:
            work = Path(directory)
            processes = []
            logs = []
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            tester_log = work/"tester.log"

            # precita priebezny log
            def read(path):
                return path.read_text() if path.exists() else ""

            # pocka na stav s diagnostikou vsetkych procesov
            def wait_for(check, timeout=5):
                deadline = time.monotonic()+timeout
                while time.monotonic() < deadline:
                    if check():
                        return
                    time.sleep(0.03)
                self.fail("Timeout\n"+"\n".join(read(path) for path in [tester_log, *logs]))

            # odovzda prikazy cez skutocne menu
            def send(process, text):
                process.stdin.write(text)
                process.stdin.flush()

            # spusti novy server s prazdnym registrom na rovnakej adrese
            def start_server(index):
                location = work/f"server_{index}"
                location.mkdir()
                path = location/"server.log"
                logs.append(path)
                process = subprocess.Popen([sys.executable, str(ROOT/"server.py")], cwd=location,
                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
                processes.append(process)
                send(process, f"127.0.0.1\n{port}\n")
                wait_for(lambda: "Server listening" in read(path))
                return process, path

            # vyberie prijate registracne odpovede konkretneho senzora
            def registrations(sensor_id):
                messages = [json.loads(line.split(" | Received ", 1)[1]) for line in read(tester_log).splitlines() if " | Received {" in line]
                return [message for message in messages if message["type"] == "REGISTER_ACK" and message["sensor_id"] == sensor_id]

            try:
                server, server_log = start_server(1)
                tester = subprocess.Popen([sys.executable, str(ROOT/"tester.py")], cwd=work,
                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
                processes.append(tester)
                send(tester, f"127.0.0.1\n{port}\n")
                wait_for(lambda: read(tester_log).count("Measurement acknowledged") == 4)
                old_tokens = {identifier: registrations(identifier)[0]["token"] for identifier in ("T-01", "W-01", "R-01", "A-01")}
                outage_start = time.monotonic()
                send(server, "0\n")
                server.wait(timeout=3)
                wait_for(lambda: read(tester_log).count("Local session closed: server contact timeout after 30 seconds") == 4, 33)
                elapsed = time.monotonic()-outage_start
                self.assertGreaterEqual(elapsed, 29.0)
                self.assertLess(elapsed, 31.0)
                lines = read(tester_log).splitlines()
                for kind, identifier in zip(("ThermoNode", "WindSense", "RainDetect", "AirQuality"), old_tokens):
                    source = f"TESTER:{kind}:{identifier}"
                    next(line for line in reversed(lines) if source+" | Measurement acknowledged" in line)
                    next(line for line in lines if source+" | Local session closed: server contact timeout" in line)
                self.assertIsNone(tester.poll())
                server, server_log = start_server(2)
                send(tester, "5\n1\n5\n2\n5\n3\n5\n4\n")
                wait_for(lambda: read(tester_log).count("Registration successful") == 8)
                wait_for(lambda: read(server_log).count("Measurement accepted:") >= 4)
                for identifier, old_token in old_tokens.items():
                    self.assertNotEqual(registrations(identifier)[-1]["token"], old_token)
                # stary token server odmietne aj po vytvoreni novej relacie
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    udp.settimeout(2)
                    packet = encode_packet(dict(type="DATA", sensor_type="ThermoNode", seq=99,
                        token=int(old_tokens["T-01"], 16), values=dict(temperature=21.3, humidity=55.4, dew_point=11.9, pressure=1013.25)))
                    udp.sendto(packet, ("127.0.0.1", port))
                    reply = decode_packet(udp.recvfrom(65535)[0])
                    self.assertEqual((reply["type"], reply["reason_code"], reply["token"]), ("REJECT", 1, 0))
                # jeden lokalne odpojeny senzor neblokuje vlastne meranie ineho
                send(tester, "4\n1\n")
                wait_for(lambda: "TESTER:ThermoNode:T-01 | Local session closed: user request" in read(tester_log))
                wind_ack = read(tester_log).count("TESTER:WindSense:W-01 | Measurement acknowledged")
                send(tester, "1\n2\n10.0\n20.0\n90\n0.5\n")
                wait_for(lambda: read(tester_log).count("TESTER:WindSense:W-01 | Measurement acknowledged") > wind_ack)
                # rychly restart: stara aktivna relacia dostane REJECT a vie sa obnovit
                previous_token = registrations("W-01")[-1]["token"]
                send(server, "0\n")
                server.wait(timeout=3)
                server, server_log = start_server(3)
                send(tester, "1\n2\n10.0\n20.0\n90\n0.5\n")
                wait_for(lambda: "TESTER:WindSense:W-01 | Local session closed: server rejected session" in read(tester_log))
                send(tester, "5\n2\n")
                wait_for(lambda: len(registrations("W-01")) == 3)
                wait_for(lambda: "Measurement accepted: WindSense:W-01" in read(server_log))
                self.assertNotEqual(registrations("W-01")[-1]["token"], previous_token)
                send(tester, "0\n")
                tester.wait(timeout=3)
                self.assertEqual(tester.returncode, 0)
                self.assertEqual(read(tester_log).count("Sensor worker stopped"), 4)
                send(server, "0\n")
                server.wait(timeout=3)
                self.assertEqual(server.returncode, 0)
            finally:
                for process in reversed(processes):
                    if process.poll() is None:
                        process.send_signal(signal.SIGINT)
                    _, errors = process.communicate(timeout=5)
                    self.assertNotIn("Traceback", errors)
