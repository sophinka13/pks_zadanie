import ipaddress
import json
import logging
import time
import zlib
from decimal import Decimal, InvalidOperation


SENSOR_TYPES = ("ThermoNode", "WindSense", "RainDetect", "AirQuality")

THERMO_FIELDS = {
    "temperature": (-50, 60, 1),
    "humidity": (0, 100, 1),
    "dew_point": (-50, 60, 1),
    "pressure": (800, 1100, 2),
}


SENSOR_FIELDS = {
    "ThermoNode": THERMO_FIELDS,
    "WindSense": {
        "wind_speed": (0, 50, 1), "wind_gust": (0, 70, 1),
        "wind_direction": (0, 359, 0), "turbulence": (0, 1, 1),
    },
    "RainDetect": {
        "rainfall": (0, 500, 1), "soil_moisture": (0, 100, 1),
        "flood_risk": (0, 3, 0), "rain_duration": (0, 60, 0),
    },
    "AirQuality": {
        "co2": (300, 5000, 0), "ozone": (0, 500, 1),
        "air_quality_index": (0, 500, 0),
    },
}


def validate_number(name, value, minimum, maximum, places):
    number = Decimal(str(value))
    if not number.is_finite() or not minimum <= number <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    # Kontrola povodnych cislic nepouziva zaokruhlovanie float ani Decimal.
    digits = number.as_tuple().digits
    trailing_zeros = 0
    for digit in reversed(digits):
        if digit != 0:
            break
        trailing_zeros += 1
    if number != 0 and number.as_tuple().exponent + trailing_zeros < -places:
        raise ValueError(f"{name} allows at most {places} decimal places")


def parse_sensor_value(sensor_type, name, text):
    minimum, maximum, places = SENSOR_FIELDS[sensor_type][name]
    try:
        number = int(text) if places == 0 else Decimal(text)
    except (ValueError, InvalidOperation):
        raise ValueError(f"{name} must be {'an integer' if places == 0 else 'a number'}") from None
    validate_number(name, number, minimum, maximum, places)
    return number if places == 0 else float(number)


def validate_values(sensor_type, values):
    """Overime uplnost, rozsahy aj presnost merania daneho typu."""
    fields = SENSOR_FIELDS[sensor_type]
    if not isinstance(values, dict) or values.keys() != fields.keys():
        raise ValueError(f"{sensor_type} requires exactly these fields: {', '.join(fields)}")
    for name, (minimum, maximum, places) in fields.items():
        value = values[name]
        if type(value) not in (int, float):
            raise ValueError(f"{name} must be a number")
        if places == 0 and type(value) is not int:
            raise ValueError(f"{name} must be an integer")
        validate_number(name, value, minimum, maximum, places)


def create_logger(name, console=False):
    """Pri spusteni vycistime log; zapisujeme v UTC, volitelne aj do konzoly."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)
    formatter = logging.Formatter(
        "%(asctime)s.%(msecs)03dZ | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    formatter.converter = time.gmtime
    handlers = [logging.FileHandler(f"{name}.log", mode="w", encoding="utf-8")]
    if console:
        handlers.append(logging.StreamHandler())
    for handler in handlers:
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


def log_message(logger, source, direction, message):
    content = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
    logger.info("MESSAGE | INFO | %s | %s %s", source, direction, content)


def ask_address(default_ip, logger=None, source="PROGRAM"):
    """IPv4 a port nacitame z rozhrania a overime pred otvorenim socketu."""
    while True:
        try:
            host = input(f"IP adresa [{default_ip}]: ").strip() or default_ip
            ipaddress.IPv4Address(host)
            port = int(input("UDP port [9000]: ").strip() or "9000")
            if not 1 <= port <= 65535:
                raise ValueError("Port musi byt od 1 do 65535.")
            return host, port
        except ValueError as error:
            print(f"Nespravna adresa alebo port: {error}")
            if logger is not None:
                logger.warning("SYSTEM | WARNING | %s | Invalid address or port: %s", source, error)


def encode_message(message):
    return json.dumps(message, separators=(",", ":")).encode("utf-8")


def calculate_crc(message):
    """CRC32 nad celym JSON objektom okrem pola crc, v jednotnom tvare."""
    content = {key: value for key, value in message.items() if key != "crc"}
    data = json.dumps(
        content, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False,
    ).encode("utf-8")
    return zlib.crc32(data)


def verify_crc(message):
    checksum = message.get("crc")
    if type(checksum) is not int or not 0 <= checksum <= 0xFFFFFFFF:
        return False
    try:
        return checksum == calculate_crc(message)
    except ValueError:
        return False


def decode_message(data):
    message = json.loads(data.decode("utf-8"))
    if not isinstance(message, dict):
        raise ValueError("Sprava musi byt JSON objekt.")
    return message
