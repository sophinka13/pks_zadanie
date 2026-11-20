"""kontroly starych a oneskorenych odpovedi; pripravene s pomocou ai."""
import io
import logging
import queue
import socket
import threading
import unittest
from unittest.mock import patch

from binary_protocol import decode_packet
from tester import run_sensor


# overi rozhodnutia celeho vlakna s riadenym casom bez sietoveho cakania
class ReplyHandlingTests(unittest.TestCase):
    # stare odpovede nesmu zrusit registraciu, potvrdit data ani obnovit casovac
    def test_stale_replies_and_session_timeout(self):
        output = io.StringIO()
        logger = logging.Logger("reply-test")
        logger.addHandler(logging.StreamHandler(output))
        sensor = dict(sensor_type="ThermoNode", sensor_id="T-01", token=None)
        commands = queue.Queue()
        commands.put(("REGISTER", sensor, None))
        stop = threading.Event()
        clock = [100.0]
        new_token, old_token = "1234567890abcdef", "1111111111111111"
        sent = []

        # zachyti skutocne binarne vystupy vlakna bez otvorenia socketu
        class CaptureSocket:
            # ulozi odoslany paket pre kontrolu typu a poradoveho cisla
            def sendto(self, data, address):
                sent.append(decode_packet(data))

            # vlakno smie nastavit timeout aj pri simulovanom prijimani
            def settimeout(self, timeout):
                pass

        # vytvori aplikacnu odpoved v tvare vratenom dekoderom
        def reply(kind, seq=2, token=new_token, **extra):
            return dict(type=kind, seq=seq, ack_for=seq, token=token, sensor_type="ThermoNode", **extra)

        replies = [
            reply("REJECT", 1, old_token, reason="Sensor ID is already registered", reason_code=2),
            reply("REGISTER_ACK", 1),
            reply("ACK", token=old_token),
            reply("KEEPALIVE", 50, old_token),
            reply("RETRANSMIT", token=old_token),
            dict(reply("ACK"), sensor_type="WindSense"),
            reply("ACK", 999),
            reply("ACK"),
            reply("ACK"),
            reply("ACK", 999),
        ]
        calls = [0]

        # skontroluje stav po predchadzajucej odpovedi a posunie hodiny
        def receive(*args):
            index = calls[0]
            calls[0] += 1
            self.assertLess(index, 12, "Worker failed to stop")
            if index == 1:
                self.assertFalse(sensor.get("active"))
                self.assertNotIn("Registration rejected:", output.getvalue())
            if 2 <= index <= 7:
                self.assertTrue(sensor["active"])
                self.assertEqual(sensor["last_contact"], 101.0)
                self.assertNotIn("Measurement acknowledged", output.getvalue())
                sensor["automatic"] = False
            if index in (8, 9, 10):
                self.assertEqual(sensor["last_contact"], 107.0)
                self.assertEqual(output.getvalue().count("Measurement acknowledged"), 1)
            if index == 10:
                clock[0] = 138.0
                raise socket.timeout()
            if index == 11:
                self.assertFalse(sensor["active"])
                self.assertIsNone(sensor["token"])
                stop.set()
                raise socket.timeout()
            # prve dve odpovede maju rovnaky cas registracie; dalsie idu po sekundach
            clock[0] = 100.0 + index
            return replies[index]

        with patch("tester.time.monotonic", side_effect=lambda: clock[0]), patch("tester.receive_reply", side_effect=receive):
            run_sensor(CaptureSocket(), ("127.0.0.1", 9000), sensor, logger, commands, stop)
        self.assertEqual([message["type"] for message in sent], ["REGISTER", "DATA", "DATA"])
        self.assertEqual([message["seq"] for message in sent], [1, 2, 2])
        self.assertIn("Ignored registration reply", output.getvalue())
        self.assertIn("token does not match", output.getvalue())
        self.assertIn("wrong sensor type", output.getvalue())
        self.assertIn("no pending request", output.getvalue())
        self.assertIn("server contact timeout after 30 seconds", output.getvalue())
