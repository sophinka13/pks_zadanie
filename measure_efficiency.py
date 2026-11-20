"""opakovatelne meranie serializovanych bajtov; pripravene s pomocou ai."""
import argparse
import csv
import json
import os
from pathlib import Path
import random
import struct
import zlib

from binary_protocol import encode_packet, pack_values
from json_baseline.lib import encode_message as json_encode, calculate_crc as json_crc
from lib import SENSOR_FIELDS


# vytvori rovnaku ulozenu sadu vstupov pre vsetky varianty
def make_dataset(samples=60, seed=42):
    rng = random.Random(seed)
    dataset = []
    for kind, prefix in zip(SENSOR_FIELDS, ("T", "W", "R", "A")):
        for index in range(samples):
            values = {}
            for name, (lo, hi, places) in SENSOR_FIELDS[kind].items():
                scale = 10**places
                value = rng.randint(int(lo*scale), int(hi*scale))
                values[name] = value if places == 0 else value/scale
            dataset.append(dict(sensor_type=kind, sensor_id=f"{prefix}-01", index=index, values=values))
    return dataset


# spocita velkosti vrstiev pri ipv4 bez options a ethernet ii bez vlan
def sizes(payload):
    application = len(payload)
    ip = application + 28
    ethernet = max(64, ip + 18)
    return dict(application_bytes=application, ip_bytes=ip, ethernet_bytes=ethernet,
                medium_byte_times=ethernet+20)


# vytvori coap con post alebo piggyback ack s osembajtovym tokenom
def coap_packet(row, seq, packed=False, response=False):
    token = seq.to_bytes(8, "big")
    if response:
        return struct.pack("!BBH", 0x68, 68, seq) + token
    identifier = row["sensor_id"].encode("ascii")
    # uri-path (11): meteo / id; content-format (12): json 50 alebo octet-stream 42
    options = b"\xb5meteo" + bytes([len(identifier)]) + identifier + bytes([0x11, 42 if packed else 50])
    payload = pack_values(row["sensor_type"], row["values"]) if packed else json.dumps(row["values"], separators=(",", ":")).encode()
    return struct.pack("!BBH", 0x48, 2, seq) + token + options + b"\xff" + payload


# vytvori binarny alebo povodny json datagram z rovnakej udalosti
def own_packet(variant, kind, row, seq, token=0x1234567890abcdef):
    sensor_type, sensor_id = row["sensor_type"], row["sensor_id"]
    token += list(SENSOR_FIELDS).index(sensor_type)
    if variant == "Binary":
        message = dict(type=kind, sensor_type=sensor_type, seq=seq, token=token)
        if kind == "REGISTER":
            message.update(sensor_id=sensor_id, token=0)
        if kind == "DATA":
            message["values"] = row["values"]
        return encode_packet(message)
    message = dict(type=kind, seq=seq)
    if kind == "REGISTER":
        message.update(sensor_type=sensor_type, sensor_id=sensor_id)
    elif kind == "REGISTER_ACK":
        message.update(type="ACK", ack_for=seq, token=f"{token:016x}")
    elif kind == "ACK":
        message["ack_for"] = seq
    elif kind == "DATA":
        message.update(sensor_id=sensor_id, token=f"{token:016x}", values=row["values"])
        message["crc"] = json_crc(message)
    elif kind in ("KEEPALIVE", "KEEPALIVE_ACK", "RETRANSMIT"):
        message.update(sensor_id=sensor_id, token=f"{token:016x}")
        if kind != "KEEPALIVE":
            message["ack_for"] = seq
        if kind == "RETRANSMIT":
            message["reason"] = "Integrity check failed"
    return json_encode(message)


# zostavi oddelene scenare bez predstierania skutocneho sietoveho behu
def build_events(dataset):
    events = []
    representatives = [next(row for row in dataset if row["sensor_type"] == kind) for kind in SENSOR_FIELDS]

    # prida paket s presne zmeranou dlzkou serializacie
    def add(variant, scenario, kind, row, seq, timestamp, response=False, corrupt=False):
        if variant.startswith("CoAP"):
            packet = coap_packet(row, seq, packed=variant == "CoAP-packed", response=response)
        else:
            packet = own_packet(variant, kind, row, seq)
        if corrupt:
            if variant == "JSON":
                damaged = json.loads(packet)
                name, (lo, hi, _) = next(iter(SENSOR_FIELDS[row["sensor_type"]].items()))
                damaged["values"][name] = hi if damaged["values"][name] != hi else lo
                packet = json_encode(damaged)
            else:
                packet = packet[:-1] + bytes([packet[-1] ^ 1])
        events.append(dict(variant=variant, scenario=scenario, sensor_type=row["sensor_type"],
                           sensor_id=row["sensor_id"], message_type=kind, seq=seq,
                           time_seconds=timestamp, response=response, packet=packet, **sizes(packet)))

    for variant in ("JSON", "Binary"):
        for index, row in enumerate(representatives):
            add(variant, "registration", "REGISTER", row, 1, index*0.1)
            add(variant, "registration", "REGISTER_ACK", row, 1, index*0.1+0.01, True)
        row = representatives[0]
        add(variant, "corruption", "DATA", row, 2, 0, corrupt=True)
        add(variant, "corruption", "RETRANSMIT", row, 2, 0.01, True)
        add(variant, "corruption", "DATA", row, 2, 0.02)
        add(variant, "corruption", "ACK", row, 2, 0.03, True)
        # x=5: prva sprava sa zahodi, druha dostane ack pri tretom pokuse
        for seq, start in ((2, 0), (3, 10)):
            for attempt in range(3):
                add(variant, "ack_loss", "DATA", row, seq, start+attempt*3)
        add(variant, "ack_loss", "ACK", row, 3, 16.01, True)
        for seq, timestamp in enumerate((15, 20, 25), start=1):
            add(variant, "idle_responsive", "KEEPALIVE", row, seq, timestamp, True)
            add(variant, "idle_responsive", "KEEPALIVE_ACK", row, seq, timestamp+0.01)
            add(variant, "disconnected", "KEEPALIVE", row, seq, timestamp, True)
    for variant in ("JSON", "Binary", "CoAP-JSON", "CoAP-packed"):
        for row in dataset:
            seq = row["index"]+2
            add(variant, "steady", "DATA", row, seq, row["index"]*10)
            add(variant, "steady", "ACK", row, seq, row["index"]*10+0.01, True)
    return events


# zapise synteticky ethernet ipv4 udp zachyt pre nezavisle overenie v tsharku
def write_pcap(path, events, port):
    with path.open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for index, event in enumerate(sorted(events, key=lambda item: item["time_seconds"])):
            payload = event["packet"]
            response = event["response"]
            client_port = 40000 + list(SENSOR_FIELDS).index(event["sensor_type"])
            source, target = (port, client_port) if response else (client_port, port)
            udp = struct.pack("!HHHH", source, target, 8+len(payload), 0)+payload
            addresses = (b"\x0a\0\0\2", b"\x0a\0\0\1") if response else (b"\x0a\0\0\1", b"\x0a\0\0\2")
            ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20+len(udp), index % 65536, 0, 64, 17, 0, *addresses)
            checksum = sum(struct.unpack("!10H", ip))
            while checksum >> 16:
                checksum = (checksum & 65535)+(checksum >> 16)
            ip = ip[:10]+struct.pack("!H", checksum ^ 65535)+ip[12:]
            frame = bytes.fromhex("00112233445566778899aabb0800")+ip+udp
            frame += b"\0"*max(0, 60-len(frame))
            timestamp = event["time_seconds"]
            seconds = int(timestamp)
            output.write(struct.pack("<IIII", 1700000000+seconds, round((timestamp-seconds)*1e6), len(frame), len(frame)))
            output.write(frame)


# ulozi csv s hlavickou
def write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


# spusti reprodukovatelnu analyzu velkosti a vytvori grafy
def main():
    parser = argparse.ArgumentParser(description="Analyza serializovanych bajtov; nie zivy sietovy benchmark")
    parser.add_argument("--samples", type=int, default=60)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", type=Path, default=Path("measurements"))
    args = parser.parse_args()
    if not 1 <= args.samples <= 65533:
        parser.error("samples musi byt 1..65533")
    args.out.mkdir(parents=True, exist_ok=True)
    dataset = make_dataset(args.samples, args.seed)
    (args.out/"inputs.json").write_text(json.dumps(dataset, indent=2)+"\n")
    events = build_events(dataset)
    rows = [{key: value for key, value in event.items() if key not in ("packet", "response")} for event in events]
    write_csv(args.out/"packets.csv", rows)
    summary = []
    metrics = ("application_bytes", "ip_bytes", "ethernet_bytes", "medium_byte_times")
    for variant, scenario in dict.fromkeys((row["variant"], row["scenario"]) for row in rows):
        group = [row for row in rows if row["variant"] == variant and row["scenario"] == scenario]
        summary.append(dict(variant=variant, scenario=scenario, packets=len(group),
                            **{metric: sum(row[metric] for row in group) for metric in metrics}))
        port = 5683 if variant.startswith("CoAP") else 9000
        write_pcap(args.out/f"{variant}_{scenario}.pcap", [event for event in events if event["variant"] == variant and event["scenario"] == scenario], port)
    write_csv(args.out/"summary.csv", summary)
    per_sensor = []
    for variant in ("JSON", "Binary", "CoAP-JSON", "CoAP-packed"):
        for kind in SENSOR_FIELDS:
            group = [row for row in rows if row["variant"] == variant and row["scenario"] == "steady" and row["sensor_type"] == kind]
            per_sensor.append(dict(variant=variant, sensor_type=kind, measurements=args.samples,
                                  **{metric: sum(row[metric] for row in group)/args.samples for metric in metrics}))
    write_csv(args.out/"per_sensor.csv", per_sensor)
    # matplotlib je volitelne iba pre graf, analyza pouziva standardnu kniznicu
    os.environ.setdefault("MPLCONFIGDIR", "/tmp/pks-measure-matplotlib")
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    steady = [row for row in summary if row["scenario"] == "steady"]
    figure, axes = plt.subplots(1, 2, figsize=(11, 4), layout="constrained")
    for axis, metric, title in zip(axes, ("application_bytes", "ethernet_bytes"), ("Application bytes", "Ethernet bytes including FCS/padding")):
        axis.bar([row["variant"] for row in steady], [row[metric] for row in steady], color=["#64748b", "#0284c7", "#d97706", "#16a34a"])
        axis.set_title(title)
        axis.set_ylabel("Bytes for confirmed measurements")
        axis.tick_params(axis="x", rotation=15)
        for index, row in enumerate(steady):
            axis.text(index, row[metric], str(row[metric]), ha="center", va="bottom", fontsize=8)
        axis.margins(y=0.18)
    figure.suptitle(f"Same {len(dataset)} measurements; serialization analysis, not live traffic")
    figure.savefig(args.out/"comparison.svg")
    figure.savefig(args.out/"comparison.png", dpi=180)
    plt.close(figure)
    for row in steady:
        print(f"{row['variant']}: {row['packets']} packets, L7={row['application_bytes']} B, Ethernet={row['ethernet_bytes']} B")


if __name__ == "__main__":
    main()

