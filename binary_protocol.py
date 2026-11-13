"""binarny format v1; implementacia pripravena s pomocou ai."""
from decimal import Decimal
import struct
import zlib

from lib import SENSOR_FIELDS, SENSOR_TYPES, validate_values

MESSAGE_TYPES = (
    "REGISTER", "ACK", "REJECT", "DATA", "RETRANSMIT", "KEEPALIVE",
    "KEEPALIVE_ACK", "REGISTER_ACK",
)
REASONS = {
    1: "Invalid sensor ID or token", 2: "Sensor ID is already registered",
    3: "Invalid values", 4: "Unsupported message or version",
    5: "Sequence number reused with different data", 6: "Invalid sender address",
}
HEADER = struct.Struct("!BIQ")
CRC = struct.Struct("!I")


# vrati presny celociselny kod a minimalny pocet bitov parametra
def field_code(value, minimum, maximum, places):
    scale = 10 ** places
    code = (Decimal(str(value)) - Decimal(str(minimum))) * scale
    if code != code.to_integral_value():
        raise ValueError("Invalid decimal precision")
    limit = int((Decimal(str(maximum)) - Decimal(str(minimum))) * scale)
    if not 0 <= code <= limit:
        raise ValueError("Value outside allowed range")
    return int(code), limit.bit_length()


# zabali hodnoty senzora od najvyssich bitov a doplni nulove bity
def pack_values(sensor_type, values):
    validate_values(sensor_type, values)
    packed = bits = 0
    for name, (minimum, maximum, places) in SENSOR_FIELDS[sensor_type].items():
        code, width = field_code(values[name], minimum, maximum, places)
        packed = (packed << width) | code
        bits += width
    padding = (-bits) % 8
    return (packed << padding).to_bytes((bits + 7) // 8, "big")


# rozbali parametre a odmietne nepovolene kody aj nenulove doplnenie
def unpack_values(sensor_type, payload):
    fields = SENSOR_FIELDS[sensor_type]
    widths = [field_code(lo, lo, hi, places)[1] for lo, hi, places in fields.values()]
    bits = sum(widths)
    if len(payload) != (bits + 7) // 8:
        raise ValueError("Invalid DATA length")
    packed = int.from_bytes(payload, "big")
    padding = (-bits) % 8
    if packed & ((1 << padding) - 1):
        raise ValueError("Nonzero padding")
    packed >>= padding
    values = {}
    for (name, (lo, hi, places)), width in reversed(list(zip(fields.items(), widths))):
        code = packed & ((1 << width) - 1)
        packed >>= width
        limit = int((Decimal(str(hi)) - Decimal(str(lo))) * 10 ** places)
        if code > limit:
            raise ValueError("Invalid parameter code")
        value = Decimal(str(lo)) + Decimal(code) / 10 ** places
        values[name] = int(value) if places == 0 else float(value)
    return {name: values[name] for name in fields}


# overi rozsah celociselneho pola bez prijatia bool hodnot
def unsigned(value, bits, name):
    if type(value) is not int or not 0 <= value < 1 << bits:
        raise ValueError(f"Invalid {name}")
    return value


# overi token podla typu spravy a jednoznacnost registracie
def check_token(kind, token):
    if kind == "REGISTER" and token != 0:
        raise ValueError("REGISTER requires zero token")
    if kind not in ("REGISTER", "REJECT") and token == 0:
        raise ValueError("Session token must be nonzero")


# prevedie citatelnu spravu na binarny datagram s crc celej hlavicky a dat
def encode_packet(message):
    try:
        kind = message["type"]
        sensor_type = message["sensor_type"]
        control = 0x40 | (MESSAGE_TYPES.index(kind) << 3) | (SENSOR_TYPES.index(sensor_type) << 1)
        seq = unsigned(message["seq"], 32, "sequence number")
        if seq == 0:
            raise ValueError("Sequence number must be positive")
        token = unsigned(message.get("token", 0), 64, "token")
        check_token(kind, token)
        payload = b""
        if kind == "REGISTER":
            sensor_id = message["sensor_id"]
            if not isinstance(sensor_id, str) or not sensor_id.strip():
                raise ValueError("Invalid sensor ID")
            identifier = sensor_id.encode("utf-8")
            if not 1 <= len(identifier) <= 255:
                raise ValueError("Invalid sensor ID length")
            payload = bytes([len(identifier)]) + identifier
        elif kind == "DATA":
            payload = pack_values(sensor_type, message["values"])
        elif kind == "REJECT":
            reason = unsigned(message["reason_code"], 8, "reason code")
            if reason not in REASONS:
                raise ValueError("Unknown rejection reason")
            payload = bytes([reason])
        content = HEADER.pack(control, seq, token) + payload
        return content + CRC.pack(zlib.crc32(content))
    except (KeyError, TypeError, UnicodeError) as error:
        raise ValueError("Invalid message fields") from error


# overi cely datagram a vrati citatelnu spravu s tokenom ako cele cislo
def decode_packet(data):
    if not isinstance(data, bytes) or len(data) < HEADER.size + CRC.size:
        raise ValueError("Truncated packet")
    content, checksum = data[:-4], CRC.unpack(data[-4:])[0]
    if zlib.crc32(content) != checksum:
        raise ValueError("Integrity check failed")
    control, seq, token = HEADER.unpack(content[:HEADER.size])
    if control >> 6 != 1 or control & 1:
        raise ValueError("Unsupported version or reserved bit")
    if seq == 0:
        raise ValueError("Sequence number must be positive")
    kind = MESSAGE_TYPES[(control >> 3) & 7]
    sensor_type = SENSOR_TYPES[(control >> 1) & 3]
    check_token(kind, token)
    message = {"type": kind, "sensor_type": sensor_type, "seq": seq, "token": token}
    payload = content[HEADER.size:]
    if kind == "REGISTER":
        if not payload or payload[0] == 0 or len(payload) != payload[0] + 1:
            raise ValueError("Invalid REGISTER length")
        try:
            sensor_id = payload[1:].decode("utf-8")
        except UnicodeError as error:
            raise ValueError("Invalid UTF-8 sensor ID") from error
        if not sensor_id.strip():
            raise ValueError("Invalid sensor ID")
        message["sensor_id"] = sensor_id
    elif kind == "DATA":
        message["values"] = unpack_values(sensor_type, payload)
    elif kind == "REJECT":
        if len(payload) != 1 or payload[0] not in REASONS:
            raise ValueError("Invalid rejection reason")
        message["reason_code"] = payload[0]
    elif payload:
        raise ValueError("Unexpected payload")
    return message

