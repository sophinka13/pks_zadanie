import ipaddress
import json
import logging
import os
import shutil
import sys
import threading
import time
import zlib
from decimal import Decimal, InvalidOperation

try:
    import readline
except ImportError:
    readline = None


_console_lock = threading.RLock()
_active_prompt = None


# vypise cely blok do terminalu a obnovi rozpisany vstup, aby ho spravy z vlakien neprepisali
def console_write(text, stream=None):
    stream = sys.stdout if stream is None else stream
    with _console_lock:
        redraw = _active_prompt is not None and stream.isatty()
        if redraw:
            stream.write("\r\033[2K")
        stream.write(text + "\n")
        if redraw:
            typed = readline.get_line_buffer() if readline is not None else ""
            stream.write(_active_prompt + typed)
        stream.flush()


# nacita vstup od pouzivatela a zapamata si aktualnu vyzvu pre obnovovanie terminalu
def console_input(prompt):
    global _active_prompt
    with _console_lock:
        _active_prompt = prompt
    try:
        return input(prompt)
    finally:
        with _console_lock:
            _active_prompt = None


# zobrazi nadpis a zoznam riadkov v prehladnom ramceku
def console_panel(title, lines):
    width = min(78, max(40, shutil.get_terminal_size().columns - 2))
    heading = f"─ {title} "
    border = "─" * width
    body = ["", "╭" + heading + "─" * max(0, width - len(heading)), *["│  " + line for line in lines], "╰" + border]
    console_write("\n".join(body))


class ConsoleFormatter(logging.Formatter):
    # nastavi, ci sa pri formatovani konzolovych vypisov pouziju farby
    def __init__(self, color=False):
        super().__init__()
        self.color = color

    # obali text farebnymi kodmi, ak su farby zapnute
    def paint(self, text, code):
        return f"\033[{code}m{text}\033[0m" if self.color else text

    # prevedie logovy zaznam na citatelny konzolovy vypis s casom, zdrojom a hodnotami
    def format(self, record):
        timestamp = time.strftime("%H:%M:%S", time.gmtime(record.created))
        timestamp += f".{int(record.msecs):03d} UTC"
        parts = record.getMessage().split(" | ", 3)
        if len(parts) != 4:
            return f"{timestamp}  {record.getMessage()}"
        kind, level, source, body = parts
        source = source.removeprefix("TESTER:")
        source_color = {"ThermoNode": "36", "WindSense": "34", "RainDetect": "35", "AirQuality": "32"}
        label = self.paint(source, source_color.get(source.split(":")[0], "37"))
        time_label = self.paint(timestamp, "90")
        if kind == "MESSAGE":
            direction, _, raw = body.partition(" ")
            try:
                message = json.loads(raw)
            except (ValueError, TypeError):
                message = None
            if isinstance(message, dict):
                mark = "TX →" if direction == "Sent" else "RX ←"
                mark = self.paint(mark, "36" if direction == "Sent" else "32")
                header = f"{time_label}  {mark}  {label}  {message.get('type', '?')} #{message.get('seq', '?')}"
                details = []
                for key, value in message.items():
                    if key in ("type", "seq", "values"):
                        continue
                    details.append(f"{key}={value}")
                values = message.get("values")
                rows = [header]
                if isinstance(values, dict):
                    units = {
                        "temperature": "°C", "humidity": "%", "dew_point": "°C", "pressure": "hPa",
                        "wind_speed": "m/s", "wind_gust": "m/s", "wind_direction": "°",
                        "rainfall": "mm", "soil_moisture": "%", "rain_duration": "min",
                        "co2": "ppm", "ozone": "µg/m³",
                    }
                    measurements = [f"{name}={value}{' ' + units[name] if name in units else ''}" for name, value in values.items()]
                    rows.extend(self.detail_rows(measurements))
                elif "values" in message:
                    details.append(f"values={values}")
                rows.extend(self.detail_rows(details))
                return "\n".join(rows)
        color = {"INFO": "32", "WARNING": "33", "ERROR": "31"}.get(level, "37")
        badge = self.paint(f"{level:<7}", color)
        return f"{time_label}  {badge}  {label}  {body}"

    # rozdeli podrobnosti spravy do riadkov podla sirky terminalu
    @staticmethod
    def detail_rows(items):
        width = max(36, min(100, shutil.get_terminal_size().columns) - 6)
        rows = []
        current = ""
        for item in items:
            if current and len(current) + len(item) + 3 > width:
                rows.append("    " + current)
                current = ""
            current += (" | " if current else "") + item
        if current:
            rows.append("    " + current)
        return rows


class ConsoleHandler(logging.StreamHandler):
    # naformatuje logovy zaznam a bezpecne ho vypise do konzoly
    def emit(self, record):
        try:
            console_write(self.format(record), self.stream)
        except Exception:
            self.handleError(record)


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


# overi, ci je cislo konecne, v povolenom rozsahu a s povolenou desatinnou presnostou
def validate_number(name, value, minimum, maximum, places):
    number = Decimal(str(value))
    if not number.is_finite() or not minimum <= number <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    # kontrola povodnych cislic nepouziva zaokruhlovanie float ani decimal.
    digits = number.as_tuple().digits
    trailing_zeros = 0
    for digit in reversed(digits):
        if digit != 0:
            break
        trailing_zeros += 1
    if number != 0 and number.as_tuple().exponent + trailing_zeros < -places:
        raise ValueError(f"{name} allows at most {places} decimal places")


# prevedie zadany text na cislo a overi pravidla konkretneho parametra senzora
def parse_sensor_value(sensor_type, name, text):
    minimum, maximum, places = SENSOR_FIELDS[sensor_type][name]
    try:
        number = int(text) if places == 0 else Decimal(text)
    except (ValueError, InvalidOperation):
        raise ValueError(f"{name} must be {'an integer' if places == 0 else 'a number'}") from None
    validate_number(name, number, minimum, maximum, places)
    return number if places == 0 else float(number)


# overi uplnost, datove typy, rozsahy a presnost vsetkych hodnot merania
def validate_values(sensor_type, values):
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


# vytvori logovanie do noveho suboru a volitelne aj do konzoly
def create_logger(name, console=False):
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
    file_handler = logging.FileHandler(f"{name}.log", mode="w", encoding="utf-8")
    file_handler.setFormatter(formatter)
    handlers = [file_handler]
    if console:
        terminal = ConsoleHandler(sys.stdout)
        color = sys.stdout.isatty() and os.environ.get("TERM") != "dumb" and "NO_COLOR" not in os.environ
        terminal.setFormatter(ConsoleFormatter(color=color))
        handlers.append(terminal)
    for handler in handlers:
        logger.addHandler(handler)
    return logger


# zapise odoslanu alebo prijatu protokolovu spravu do logu ako citatelny json
def log_message(logger, source, direction, message):
    content = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
    logger.info("MESSAGE | INFO | %s | %s %s", source, direction, content)


# vypyta ipv4 adresu a port a pri neplatnom vstupe umozni opravu
def ask_address(default_ip, logger=None, source="PROGRAM"):
    while True:
        try:
            host = console_input(f"  IP adresa [{default_ip}]: ").strip() or default_ip
            ipaddress.IPv4Address(host)
            port = int(console_input("  UDP port [9000]: ").strip() or "9000")
            if not 1 <= port <= 65535:
                raise ValueError("Port musi byt od 1 do 65535.")
            return host, port
        except ValueError as error:
            console_write(f"  ! Nesprávna adresa alebo port: {error}")
            if logger is not None:
                logger.warning("SYSTEM | WARNING | %s | Invalid address or port: %s", source, error)


# prevedie slovnik spravy na json bajty zakodovane v utf-8 pre odoslanie cez udp
def encode_message(message):
    return json.dumps(message, separators=(",", ":")).encode("utf-8")


# vypocita crc32 z jednotneho json zapisu celej spravy bez pola crc
def calculate_crc(message):
    content = {key: value for key, value in message.items() if key != "crc"}
    data = json.dumps(
        content, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False,
    ).encode("utf-8")
    return zlib.crc32(data)


# overi, ci sprava obsahuje platne crc a ci sa zhoduje s prepocitanou hodnotou
def verify_crc(message):
    checksum = message.get("crc")
    if type(checksum) is not int or not 0 <= checksum <= 0xFFFFFFFF:
        return False
    try:
        return checksum == calculate_crc(message)
    except ValueError:
        return False


# prevedie prijate utf-8 bajty na json objekt a overi, ze ide o slovnik
def decode_message(data):
    message = json.loads(data.decode("utf-8"))
    if not isinstance(message, dict):
        raise ValueError("Sprava musi byt JSON objekt.")
    return message
