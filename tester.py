import random
import copy
import queue
import socket
import threading
import time

from lib import (
    SENSOR_FIELDS, ask_address, create_logger, decode_message,
    encode_message, log_message, parse_sensor_value, calculate_crc,
)

MEASUREMENT_INTERVAL = 10
ACK_TIMEOUT = 3
MAX_SENDS = 3
SESSION_TIMEOUT = 30


def activate_sensor(sensor, token):
    sensor.update(
        token=token, active=True, automatic=True,
        next_send=time.monotonic(), last_contact=time.monotonic(),
    )


def deactivate_sensor(sensor, pending, registrations, corrupt_next, logger, reason):
    sensor.update(active=False, automatic=False, token=None)
    for mapping in (pending, registrations):
        for message_seq, entry in list(mapping.items()):
            if entry["sensor"] is sensor:
                del mapping[message_seq]
    corrupt_next.discard(sensor["sensor_id"])
    logger.info("SYSTEM | INFO | %s | Local session closed: %s", sensor_source(sensor), reason)


def corrupt_measurement(measurement, sensor_type):
    """Zmenime jednu hodnotu po vypocte CRC; povodna sprava ostane zachovana."""
    damaged = copy.deepcopy(measurement)
    name, (minimum, maximum, places) = next(iter(SENSOR_FIELDS[sensor_type].items()))
    value = damaged["values"][name]
    damaged["values"][name] = maximum if value != maximum else minimum
    return damaged


def sensor_source(sensor):
    return f"TESTER:{sensor['sensor_type']}:{sensor['sensor_id']}"


def generate_values(sensor_type):
    """Cele parametre ostanu int, desatinne maju predpisanu presnost."""
    values = {}
    for name, (minimum, maximum, places) in SENSOR_FIELDS[sensor_type].items():
        scale = 10 ** places
        number = random.randint(minimum * scale, maximum * scale)
        values[name] = number if places == 0 else number / scale
    return values


def receive_reply(udp_socket, server_address, logger, source):
    data, sender = udp_socket.recvfrom(65535)
    if sender != server_address:
        return None
    try:
        return decode_message(data)
    except (ValueError, UnicodeError) as error:
        logger.warning("SYSTEM | WARNING | %s | Invalid reply: %s", source, error)
        return None


def run_sensor(udp_socket, server_address, sensor, logger, commands, stop):
    # Kazdy senzor ma vlastny socket, poradove cisla a cakajuce spravy.
    seq = 1
    pending = {}
    registrations = {}
    corrupt_next = set()
    while not stop.is_set():
        now = time.monotonic()
        outgoing = []
        # Menu vklada poziadavky do fronty; iba toto vlakno pracuje so socketom.
        while True:
            try:
                action, sensor, values = commands.get_nowait()
            except queue.Empty:
                break
            if action == "DISCONNECT":
                deactivate_sensor(sensor, pending, registrations, corrupt_next, logger, "user request")
                continue
            if action == "REGISTER":
                if sensor.get("active") or any(e["sensor"] is sensor for e in registrations.values()):
                    logger.warning("SYSTEM | WARNING | %s | Sensor is already active or registration is pending", sensor_source(sensor))
                    continue
                registration = {
                    "type": "REGISTER", "seq": seq,
                    "sensor_type": sensor["sensor_type"], "sensor_id": sensor["sensor_id"],
                }
                udp_socket.sendto(encode_message(registration), server_address)
                log_message(logger, sensor_source(sensor), "Sent", registration)
                registrations[seq] = {"sensor": sensor, "deadline": time.monotonic() + ACK_TIMEOUT}
                seq += 1
                continue
            if not sensor.get("active"):
                logger.warning("SYSTEM | WARNING | %s | Sensor is disconnected; register it first", sensor_source(sensor))
                continue
            if action == "CORRUPT":
                corrupt_next.add(sensor["sensor_id"])
                logger.info("SYSTEM | INFO | %s | Next measurement will be corrupted", sensor_source(sensor))
                continue
            if action == "TOGGLE_AUTO":
                sensor["automatic"] = not sensor["automatic"]
                if sensor["automatic"]:
                    sensor["next_send"] = time.monotonic()
                state = "enabled" if sensor["automatic"] else "disabled"
                logger.info(
                    "SYSTEM | INFO | %s | Automatic measurements %s",
                    sensor_source(sensor), state,
                )
                print(f"{sensor['sensor_id']}: automaticke merania {'zapnute' if sensor['automatic'] else 'vypnute'}.")
                continue
            damaged = sensor["sensor_id"] in corrupt_next
            corrupt_next.discard(sensor["sensor_id"])
            outgoing.append((sensor, values, damaged))
        if sensor.get("active") and now - sensor["last_contact"] >= SESSION_TIMEOUT:
            deactivate_sensor(sensor, pending, registrations, corrupt_next, logger, "server contact timeout after 30 seconds")
        if sensor.get("active") and sensor["automatic"] and now >= sensor["next_send"]:
            damaged = sensor["sensor_id"] in corrupt_next
            corrupt_next.discard(sensor["sensor_id"])
            outgoing.append((sensor, generate_values(sensor["sensor_type"]), damaged))
            sensor["next_send"] = now + MEASUREMENT_INTERVAL

        for sensor, values, damaged in outgoing:
            if not sensor.get("active"):
                continue
            measurement = {
                "type": "DATA", "seq": seq,
                "sensor_id": sensor["sensor_id"], "token": sensor["token"],
                "values": values,
            }
            # CRC sa pocita az po zostaveni celej spravy, pred jej odoslanim.
            measurement["crc"] = calculate_crc(measurement)
            transmitted = corrupt_measurement(measurement, sensor["sensor_type"]) if damaged else measurement
            udp_socket.sendto(encode_message(transmitted), server_address)
            log_message(logger, sensor_source(sensor), "Sent", transmitted)
            pending[seq] = {
                "sensor": sensor, "message": measurement,
                "deadline": time.monotonic() + ACK_TIMEOUT, "attempts": 1,
            }
            seq += 1

        # Cakajuce potvrdenia patria iba tomuto senzoru.
        now = time.monotonic()
        for message_seq, entry in list(pending.items()):
            if now >= entry["deadline"]:
                source = sensor_source(entry["sensor"])
                logger.warning(
                    "SYSTEM | WARNING | %s | Measurement %s dropped after ACK timeout",
                    source, message_seq,
                )
                del pending[message_seq]

        for message_seq, entry in list(registrations.items()):
            if now >= entry["deadline"]:
                logger.warning("SYSTEM | WARNING | %s | Registration timed out after 3 seconds", sensor_source(entry["sensor"]))
                del registrations[message_seq]

        deadlines = [time.monotonic() + 0.2]
        if sensor.get("active"):
            deadlines.append(sensor["last_contact"] + SESSION_TIMEOUT)
            if sensor["automatic"]:
                deadlines.append(sensor["next_send"])
        deadlines.extend(entry["deadline"] for entry in pending.values())
        # Kratke cakanie umozni spracovat rucne meranie aj ukoncenie menu.
        udp_socket.settimeout(max(0.001, min(0.2, min(deadlines) - time.monotonic())))
        try:
            reply = receive_reply(udp_socket, server_address, logger, sensor_source(sensor))
        except socket.timeout:
            continue
        if reply is None:
            continue
        if reply.get("type") == "KEEPALIVE":
            if reply.get("sensor_id") != sensor["sensor_id"] or not sensor.get("active"):
                log_message(logger, sensor_source(sensor), "Received", reply)
                continue
            source = sensor_source(sensor)
            log_message(logger, source, "Received", reply)
            if reply.get("token") != sensor["token"] or type(reply.get("seq")) is not int or reply["seq"] < 1:
                continue
            sensor["last_contact"] = time.monotonic()
            response = {
                "type": "KEEPALIVE_ACK", "seq": seq, "ack_for": reply["seq"],
                "sensor_id": sensor["sensor_id"], "token": sensor["token"],
            }
            seq += 1
            udp_socket.sendto(encode_message(response), server_address)
            log_message(logger, source, "Sent", response)
            continue
        ack_for = reply.get("ack_for")
        if type(ack_for) is int and ack_for in registrations:
            entry = registrations[ack_for]
            sensor = entry["sensor"]
            source = sensor_source(sensor)
            log_message(logger, source, "Received", reply)
            if reply.get("type") == "ACK" and isinstance(reply.get("token"), str) and reply["token"]:
                activate_sensor(sensor, reply["token"])
                del registrations[ack_for]
                logger.info("SYSTEM | INFO | %s | Registration successful", source)
            elif reply.get("type") == "REJECT":
                del registrations[ack_for]
                logger.warning("SYSTEM | WARNING | %s | Registration rejected: %s", source, reply.get("reason"))
            continue
        if type(ack_for) is not int or ack_for not in pending:
            log_message(logger, sensor_source(sensor), "Received", reply)
            continue
        entry = pending[ack_for]
        sensor = entry["sensor"]
        source = sensor_source(sensor)
        log_message(logger, source, "Received", reply)
        if reply.get("type") == "ACK":
            sensor["last_contact"] = time.monotonic()
            del pending[ack_for]
            logger.info("SYSTEM | INFO | %s | Measurement acknowledged", source)
        elif reply.get("type") == "RETRANSMIT":
            if reply.get("sensor_id") != sensor["sensor_id"] or reply.get("token") != sensor["token"]:
                continue
            sensor["last_contact"] = time.monotonic()
            if entry["attempts"] >= MAX_SENDS:
                # Po tretom odoslani este pockame na ACK do aktualneho deadline.
                continue
            udp_socket.sendto(encode_message(entry["message"]), server_address)
            log_message(logger, source, "Sent", entry["message"])
            entry["attempts"] += 1
            entry["deadline"] = time.monotonic() + ACK_TIMEOUT
        elif reply.get("type") == "REJECT":
            del pending[ack_for]
            logger.warning("SYSTEM | WARNING | %s | Measurement rejected: %s", source, reply.get("reason"))
            if reply.get("reason") == "Invalid sensor ID or token":
                deactivate_sensor(sensor, pending, registrations, corrupt_next, logger, "server rejected session")


def read_custom_values(sensor_type, logger=None, source="TESTER"):
    values = {}
    for name, (minimum, maximum, places) in SENSOR_FIELDS[sensor_type].items():
        while True:
            try:
                text = input(f"{name} ({minimum} az {maximum}, desatinne miesta: {places}): ").strip()
                value = parse_sensor_value(sensor_type, name, text)
                values[name] = value
                break
            except ValueError as error:
                print(f"Nespravna hodnota: {error}")
                if logger is not None:
                    logger.warning(
                        "SYSTEM | WARNING | %s | Invalid custom value for %s: %r; %s",
                        source, name, text, error,
                    )
    return values


def run_menu(sensors, commands, stop, logger):
    while not stop.is_set():
        print(
            "\n1 - Odoslat vlastne meranie\n2 - Poskodit nasledujuce meranie"
            "\n3 - Vypnut/zapnut automaticke merania senzora"
            "\n4 - Uplne odpojit senzor\n5 - Znova zaregistrovat senzor\n0 - Ukoncit tester"
        )
        choice = input("Volba: ").strip()
        if choice == "0":
            return
        if choice not in ("1", "2", "3", "4", "5"):
            print("Zadaj volbu 0 az 5.")
            continue
        for index, sensor in enumerate(sensors, start=1):
            print(f"{index} - {sensor['sensor_type']}:{sensor['sensor_id']}")
        try:
            selected = int(input("Cislo senzora: "))
            if not 1 <= selected <= len(sensors):
                raise ValueError()
        except ValueError:
            print("Nespravne cislo senzora.")
            continue
        sensor = sensors[selected - 1]
        if choice in ("4", "5"):
            commands[sensor["sensor_id"]].put(("DISCONNECT" if choice == "4" else "REGISTER", sensor, None))
            continue
        if choice == "3":
            commands[sensor["sensor_id"]].put(("TOGGLE_AUTO", sensor, None))
            continue
        if choice == "2":
            commands[sensor["sensor_id"]].put(("CORRUPT", sensor, None))
            print("Nasledujuce meranie vybraneho senzora bude poskodene.")
            continue
        values = read_custom_values(sensor["sensor_type"], logger, sensor_source(sensor))
        commands[sensor["sensor_id"]].put(("DATA", sensor, values))
        print("Meranie je vo fronte na odoslanie. Potvrdenie najdes v logu.")


def start_measurements_and_menu(server_address, sensors, logger):
    commands = {sensor["sensor_id"]: queue.Queue() for sensor in sensors}
    stop = threading.Event()
    workers = []

    def sensor_worker(sensor):
        source = sensor_source(sensor)
        try:
            # Vlastny UDP port zaisti, ze vlakna si navzajom nevezmu odpovede.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
                udp_socket.bind(("0.0.0.0", 0))
                logger.info(
                    "SYSTEM | INFO | %s | Sensor worker started: %s, UDP port %s",
                    source, threading.current_thread().name, udp_socket.getsockname()[1],
                )
                sensor_commands = commands[sensor["sensor_id"]]
                sensor_commands.put(("REGISTER", sensor, None))
                run_sensor(udp_socket, server_address, sensor, logger, sensor_commands, stop)
        except OSError as error:
            logger.error("SYSTEM | ERROR | %s | Socket error: %s", source, error)
        finally:
            logger.info("SYSTEM | INFO | %s | Sensor worker stopped", source)

    print("Kazdy senzor bezi vo vlastnom vlakne. Automaticke merania kazdych 10 sekund.")
    try:
        for sensor in sensors:
            worker = threading.Thread(
                target=sensor_worker, args=(sensor,), name=f"sensor-{sensor['sensor_id']}",
            )
            workers.append(worker)
            worker.start()
        run_menu(sensors, commands, stop, logger)
    finally:
        stop.set()
        for worker in workers:
            if worker.ident is not None:
                worker.join()


def main():
    logger = create_logger("tester", console=True)
    try:
        server_address = ask_address("127.0.0.1", logger, "TESTER")
    except (EOFError, KeyboardInterrupt):
        logger.info("SYSTEM | INFO | TESTER | Tester stopped during configuration")
        return
    sensors = [
        {"sensor_type": "ThermoNode", "sensor_id": "T-01", "token": None},
        {"sensor_type": "WindSense", "sensor_id": "W-01", "token": None},
        {"sensor_type": "RainDetect", "sensor_id": "R-01", "token": None},
        {"sensor_type": "AirQuality", "sensor_id": "A-01", "token": None},
    ]
    try:
        start_measurements_and_menu(server_address, sensors, logger)
        logger.info("SYSTEM | INFO | TESTER | Tester stopped")
    except OSError as error:
        logger.error("SYSTEM | ERROR | TESTER | Socket error: %s", error)
    except (KeyboardInterrupt, EOFError):
        logger.info("SYSTEM | INFO | TESTER | Tester stopped")


if __name__ == "__main__":
    main()
