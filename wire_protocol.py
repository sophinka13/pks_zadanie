"""prepojenie binarneho formatu s aplikaciou; pripravene s pomocou ai."""
import struct
import zlib

from binary_protocol import encode_packet, decode_packet, HEADER, REASONS
from lib import SENSOR_TYPES


# prevedie aplikacnu spravu na binarny paket a zachova zamerne poskodene crc
def encode_message(message):
    kind = message["type"]
    token = message.get("token") or 0
    packet_message = dict(message, token=int(token, 16) if isinstance(token, str) else token)
    if "ack_for" in message:
        packet_message["seq"] = message["ack_for"]
    if kind == "REJECT":
        packet_message["reason_code"] = message.get("reason_code", 3)
    packet = encode_packet(packet_message)
    if kind == "DATA" and "crc" in message:
        packet = packet[:-4] + struct.pack("!I", message["crc"])
    return packet


# dekoduje paket a doplni polia potrebne pre aplikacne logy a stav relacie
def decode_message(data, sessions=None):
    try:
        message = decode_packet(data)
    except ValueError as error:
        if str(error) != "Integrity check failed" or sessions is None or len(data) < 17:
            raise
        control, seq, token = HEADER.unpack(data[:13])
        if control >> 6 != 1 or control & 1 or (control >> 3) & 7 != 3:
            raise
        sensor_type = SENSOR_TYPES[(control >> 1) & 3]
        token_text = f"{token:016x}"
        if not any(s["token"] == token_text and s["sensor_type"] == sensor_type for s in sessions.values()):
            raise
        # pri chybe integrity sa hodnoty nepovazuju za doveryhodne
        try:
            message = decode_packet(data[:-4] + struct.pack("!I", zlib.crc32(data[:-4])))
        except ValueError:
            message = dict(type="DATA", sensor_type=sensor_type, seq=seq, token=token, values={}, raw_hex=data.hex())
    token = message["token"]
    message["token"] = f"{token:016x}" if token else 0
    kind = message["type"]
    if sessions is not None and kind != "REGISTER":
        for sensor_id, session in sessions.items():
            if session["token"] == message["token"] and session["sensor_type"] == message["sensor_type"]:
                message["sensor_id"] = sensor_id
                break
    if kind in ("ACK", "REGISTER_ACK", "REJECT", "RETRANSMIT", "KEEPALIVE_ACK"):
        message["ack_for"] = message["seq"]
    if kind == "REJECT":
        message["reason"] = REASONS[message["reason_code"]]
    if kind == "DATA":
        message["crc"] = struct.unpack("!I", data[-4:])[0]
    return message


# vypocita crc z binarneho zapisu bez uz prilozeneho kontrolneho suctu
def calculate_crc(message):
    clean = {key: value for key, value in message.items() if key != "crc"}
    return struct.unpack("!I", encode_message(clean)[-4:])[0]


# porovna prijate crc s binarnym obsahom merania
def verify_crc(message):
    try:
        return type(message.get("crc")) is int and message["crc"] == calculate_crc(message)
    except (ValueError, KeyError, TypeError):
        return False
