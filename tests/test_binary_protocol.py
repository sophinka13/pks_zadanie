"""testy binarneho formatu pripravene s pomocou ai."""
import random
import struct
import unittest
import zlib

from binary_protocol import decode_packet, encode_packet, MESSAGE_TYPES
from lib import SENSOR_FIELDS


# overi kodovanie, presnost a odmietanie poskodenych datagramov
class BinaryProtocolTests(unittest.TestCase):
    # vytvori zaklad spravy s platnou relaciou
    def message(self, kind="DATA", sensor="ThermoNode"):
        return dict(type=kind, sensor_type=sensor, seq=0xffffffff, token=0xffffffffffffffff)

    # doplni platne crc po cielenej uprave struktury testovacieho paketu
    def checksum(self, content):
        return content + struct.pack("!I", zlib.crc32(content))

    # overi hranice a nahodne presne hodnoty kazdeho parametra
    def test_values_and_lengths(self):
        rng = random.Random(42)
        for sensor, length in zip(SENSOR_FIELDS, (23, 21, 21, 22)):
            for sample in range(102):
                values = {}
                for name, (lo, hi, places) in SENSOR_FIELDS[sensor].items():
                    scale = 10 ** places
                    code = 0 if sample == 0 else int((hi-lo)*scale) if sample == 1 else rng.randint(0, int((hi-lo)*scale))
                    value = (int(lo*scale)+code)/scale
                    values[name] = int(value) if places == 0 else value
                msg = self.message(sensor=sensor)
                msg["values"] = values
                packet = encode_packet(msg)
                self.assertEqual(len(packet), length)
                self.assertEqual(decode_packet(packet), msg)

    # overi kazdy riadiaci typ a viacbajtove utf-8 id
    def test_control_messages(self):
        for kind in MESSAGE_TYPES:
            if kind == "DATA":
                continue
            msg = self.message(kind)
            expected = 17
            if kind == "REGISTER":
                msg.update(token=0, sensor_id="senzor-ž")
                expected = 18 + len(msg["sensor_id"].encode())
            if kind == "REJECT":
                msg["reason_code"] = 2
                expected = 18
            packet = encode_packet(msg)
            self.assertEqual(len(packet), expected)
            self.assertEqual(decode_packet(packet), msg)

    # odmietne kazde skratenie, prebytocne bajty a zmenu bitu bez noveho crc
    def test_corruption_and_truncation(self):
        packet = encode_packet(self.message("ACK"))
        for size in range(len(packet)):
            with self.assertRaises(ValueError):
                decode_packet(packet[:size])
        for index in range(len(packet)):
            damaged = bytearray(packet)
            damaged[index] ^= 1
            with self.assertRaises(ValueError):
                decode_packet(bytes(damaged))
        with self.assertRaises(ValueError):
            decode_packet(self.checksum(packet[:-4] + b"\0"))

    # overi strukturale chyby aj ked je crc platne
    def test_invalid_structure(self):
        packet = encode_packet(self.message("ACK"))
        for control in (packet[0] | 1, packet[0] & 0x3f):
            with self.assertRaises(ValueError):
                decode_packet(self.checksum(bytes([control]) + packet[1:-4]))
        msg = self.message()
        msg["values"] = {name: lo for name, (lo, hi, places) in SENSOR_FIELDS["ThermoNode"].items()}
        packet = encode_packet(msg)
        for payload in (b"\xff" * 6, b"\0" * 5 + b"\x01"):
            with self.assertRaises(ValueError):
                decode_packet(self.checksum(packet[:13] + payload))

    # odmietne nespravnu presnost, rozsahy a nepovolene identifikatory
    def test_invalid_inputs(self):
        msg = self.message()
        msg["values"] = dict(temperature=21.33, humidity=50.0, dew_point=0.0, pressure=1000.0)
        with self.assertRaises(ValueError):
            encode_packet(msg)
        for identifier in ("", " ", "x" * 256):
            with self.assertRaises(ValueError):
                encode_packet(dict(type="REGISTER", sensor_type="ThermoNode", seq=1, token=0, sensor_id=identifier))
        for seq in (0, -1, True, 2**32):
            msg = self.message("ACK")
            msg["seq"] = seq
            with self.assertRaises(ValueError):
                encode_packet(msg)


if __name__ == "__main__":
    unittest.main()
