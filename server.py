import secrets
import queue
import socket
import threading
import time

from lib import (
    SENSOR_TYPES, ask_address, create_logger, decode_message,
    encode_message, log_message, validate_values, verify_crc,
    console_input, console_panel, console_write,
)

IDLE_TIMEOUT = 15
KEEPALIVE_INTERVAL = 5
KEEPALIVE_ATTEMPTS = 3


def reset_activity(session, now):
    session.update(
        last_data=now, idle=False, unanswered=0,
        next_probe=now + IDLE_TIMEOUT, probe_seq=None,
    )


def monitor_sessions(udp_socket, sessions, logger, next_seq, now):
    """Po 15 s prva sonda, potom po 5 s; po tretej este 5 s cakame."""
    for sensor_id, session in list(sessions.items()):
        if now < session["next_probe"]:
            continue
        if not session["idle"]:
            session["idle"] = True
            logger.info("SYSTEM | INFO | SERVER | SENSOR IDLE: %s:%s", session["sensor_type"], sensor_id)
        if session["unanswered"] >= KEEPALIVE_ATTEMPTS:
            del sessions[sensor_id]
            logger.warning("SYSTEM | WARNING | SERVER | SENSOR DISCONNECTED: %s:%s", session["sensor_type"], sensor_id)
            continue
        probe = {
            "type": "KEEPALIVE", "seq": next_seq,
            "sensor_id": sensor_id, "token": session["token"],
        }
        udp_socket.sendto(encode_message(probe), session["address"])
        log_message(logger, "SERVER", "Sent", probe)
        session["probe_seq"] = next_seq
        session["unanswered"] += 1
        session["next_probe"] += KEEPALIVE_INTERVAL
        next_seq += 1
    return next_seq


def process_measurement(message, sender, sessions):
    """Vrati None pri uspechu, inak dovod odmietnutia."""
    sensor_id = message.get("sensor_id")
    session = sessions.get(sensor_id) if isinstance(sensor_id, str) else None
    if session is None or message.get("token") != session["token"]:
        return "Invalid sensor ID or token"
    if sender != session["address"]:
        return "Sender address does not match the registered sensor"
    if not verify_crc(message):
        return "Integrity check failed"
    try:
        validate_values(session["sensor_type"], message.get("values"))
    except ValueError as error:
        return str(error)
    return None


def server_menu(commands):
    """Menu nevstupuje do relacii; prikazy spracuje sietova slucka."""
    try:
        while True:
            console_panel("SERVER · MENU", ["Prijímanie meraní a KEEPALIVE bežia na pozadí.", "0  Ukončiť server   ·   Ctrl+C  Ukončiť server"])
            choice = console_input("  Voľba › ").strip()
            if choice == "0":
                commands.put("STOP")
                return
            console_write("  ! Zadaj 0 alebo ukonči server cez Ctrl+C.")
    except (EOFError, KeyboardInterrupt):
        return


def main():
    logger = create_logger("server", console=True)
    console_panel("FIIT METEO · SERVER", ["Príjem meteorologických meraní cez UDP", "Nastav lokálnu IP a port. Enter ponechá predvolenú hodnotu."])
    try:
        address = ask_address("127.0.0.1", logger, "SERVER")
    except (EOFError, KeyboardInterrupt):
        logger.info("SYSTEM | INFO | SERVER | Server stopped during configuration")
        return
    sessions = {}
    next_seq = 1
    commands = queue.Queue()

    try:
        # AF_INET znamena IPv4, SOCK_DGRAM znamena UDP.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:
            udp_socket.bind(address)
            logger.info("SYSTEM | INFO | SERVER | Server listening on %s:%s", *address)
            udp_socket.settimeout(0.2)
            # Vlakno iba cita vstup; pri Ctrl+C nesmie blokovat ukoncenie procesu.
            threading.Thread(target=server_menu, args=(commands,), daemon=True).start()

            while True:
                while True:
                    try:
                        action = commands.get_nowait()
                    except queue.Empty:
                        break
                    if action == "STOP":
                        logger.info("SYSTEM | INFO | SERVER | Server stopped")
                        return
                next_seq = monitor_sessions(udp_socket, sessions, logger, next_seq, time.monotonic())
                deadline = min((s["next_probe"] for s in sessions.values()), default=time.monotonic() + 0.2)
                udp_socket.settimeout(max(0.001, min(0.2, deadline - time.monotonic())))
                try:
                    data, sender = udp_socket.recvfrom(65535)
                except socket.timeout:
                    continue
                try:
                    message = decode_message(data)
                    log_message(logger, "SERVER", "Received", message)
                    seq = message.get("seq")
                    if type(seq) is not int or seq < 1:
                        raise ValueError("Sequence number must be a positive integer")
                    if message.get("type") == "KEEPALIVE_ACK":
                        sensor_id = message.get("sensor_id")
                        session = sessions.get(sensor_id) if isinstance(sensor_id, str) else None
                        if (
                            session is None or sender != session["address"]
                            or message.get("token") != session["token"]
                            or type(message.get("ack_for")) is not int
                            or message["ack_for"] != session["probe_seq"]
                        ):
                            raise ValueError("Invalid KEEPALIVE acknowledgement")
                        session["unanswered"] = 0
                        session["probe_seq"] = None
                        continue
                    if message.get("type") == "DATA":
                        reason = process_measurement(message, sender, sessions)
                        reply = {"type": "ACK", "seq": next_seq, "ack_for": seq}
                        if reason is not None:
                            reply.update(type="REJECT", reason=reason)
                            if reason == "Integrity check failed":
                                session = sessions[message["sensor_id"]]
                                reply.update(
                                    type="RETRANSMIT", sensor_id=message["sensor_id"],
                                    token=session["token"],
                                )
                                logger.warning(
                                    "SYSTEM | WARNING | SERVER | Integrity check failed for %s:%s; retransmission requested",
                                    session["sensor_type"], message["sensor_id"],
                                )
                            logger.warning(
                                "SYSTEM | WARNING | SERVER | Measurement rejected: %s: %s",
                                message.get("sensor_id"), reason,
                            )
                        else:
                            sensor_id = message["sensor_id"]
                            session = sessions[sensor_id]
                            reset_activity(session, time.monotonic())
                            accepted = session["accepted"]
                            if seq not in accepted:
                                accepted[seq] = message["crc"]
                                # Pamat na nedavne merania ma obmedzenu velkost.
                                if len(accepted) > 256:
                                    del accepted[next(iter(accepted))]
                                logger.info(
                                    "SYSTEM | INFO | SERVER | Measurement accepted: %s:%s",
                                    session["sensor_type"], sensor_id,
                                )
                            elif accepted[seq] != message["crc"]:
                                reply.update(type="REJECT", reason="Sequence number reused with different data")
                            else:
                                logger.info("SYSTEM | INFO | SERVER | Duplicate measurement acknowledged: %s, seq=%s", sensor_id, seq)
                        next_seq += 1
                        udp_socket.sendto(encode_message(reply), sender)
                        log_message(logger, "SERVER", "Sent", reply)
                        continue
                    if message.get("type") != "REGISTER":
                        raise ValueError("Unknown message type")
                    sensor_type = message.get("sensor_type")
                    sensor_id = message.get("sensor_id")
                    if sensor_type not in SENSOR_TYPES:
                        raise ValueError("Unknown sensor type")
                    if not isinstance(sensor_id, str) or not sensor_id.strip():
                        raise ValueError("Sensor ID must be a nonempty string")

                    # ID je jedinecne napriec vsetkymi typmi senzorov.
                    if sensor_id in sessions:
                        reply = {
                            "type": "REJECT", "seq": next_seq,
                            "ack_for": seq, "reason": "Sensor ID is already registered",
                        }
                    else:
                        token = secrets.token_hex(8)
                        sessions[sensor_id] = {
                            "sensor_type": sensor_type, "token": token, "address": sender,
                            "accepted": {},
                        }
                        reset_activity(sessions[sensor_id], time.monotonic())
                        reply = {
                            "type": "ACK", "seq": next_seq,
                            "ack_for": seq, "token": token,
                        }
                        logger.info(
                            "SYSTEM | INFO | SERVER | Sensor registered: %s:%s",
                            sensor_type, sensor_id,
                        )
                    next_seq += 1
                    udp_socket.sendto(encode_message(reply), sender)
                    log_message(logger, "SERVER", "Sent", reply)
                except (ValueError, UnicodeError) as error:
                    logger.warning("SYSTEM | WARNING | SERVER | Invalid message: %s", error)
    except OSError as error:
        logger.error("SYSTEM | ERROR | SERVER | Socket error: %s", error)
    except KeyboardInterrupt:
        logger.info("SYSTEM | INFO | SERVER | Server stopped")


if __name__ == "__main__":
    main()
