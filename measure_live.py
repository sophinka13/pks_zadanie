"""zivy udp replay proti skutocnym serverom; pripravene s pomocou ai."""
import argparse
from collections import Counter
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import statistics
import socket
import subprocess
import time

from binary_protocol import decode_packet
from json_baseline.lib import decode_message as json_decode, encode_message as json_encode, calculate_crc as json_crc
from wire_protocol import encode_message as binary_encode, calculate_crc as binary_crc
from measure_efficiency import sizes, write_csv

ROOT = Path(__file__).resolve().parent


# najde wireshark nastroj v path alebo v macos aplikacii
def executable(name):
    path = shutil.which(name) or str(Path("/Applications/Wireshark.app/Contents/MacOS", name))
    if not Path(path).is_file():
        raise RuntimeError(f"Missing {name}; install Wireshark or add it to PATH")
    return path


# pocka na pripraveny server alebo zachytavanie s diagnostikou
def wait_ready(process, path, marker, timeout=8):
    deadline = time.monotonic()+timeout
    while time.monotonic() < deadline:
        content = path.read_text(errors="replace") if path.exists() else ""
        if process.poll() is not None:
            raise RuntimeError(f"Process stopped: {content}")
        if marker in content:
            return
        time.sleep(0.03)
    raise RuntimeError(f"Process readiness timeout: {path}")


# ukonci pomocny proces a vzdy uzavrie jeho subory
def stop_process(process):
    if process is not None and process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


# zopakuje ulozene hodnoty cez samostatny socket a relaciu kazdeho senzora
def replay(variant, rows, address, interval, transcript):
    sensors = {}
    packets = []
    encode = binary_encode if variant == "Binary" else json_encode
    decode = decode_packet if variant == "Binary" else json_decode
    crc = binary_crc if variant == "Binary" else json_crc

    # odosle jednu poziadavku a overi potvrdenie bez skryteho opakovania
    def exchange(udp, message, registration=False):
        packet = encode(message)
        udp.sendto(packet, address)
        packets.append(packet)
        transcript.write(json.dumps(dict(direction="sent", time=time.time(), message=message, hex=packet.hex()))+"\n")
        data, sender = udp.recvfrom(65535)
        if sender != address:
            raise RuntimeError("Unexpected reply address")
        reply = decode(data)
        packets.append(data)
        transcript.write(json.dumps(dict(direction="received", time=time.time(), message=reply, hex=data.hex()))+"\n")
        expected = "REGISTER_ACK" if registration and variant == "Binary" else "ACK"
        acknowledged = reply["seq"] if variant == "Binary" else reply.get("ack_for")
        if reply["type"] != expected or acknowledged != message["seq"]:
            raise RuntimeError(f"Unexpected reply: {reply}")
        if variant == "Binary" and (reply["sensor_type"] != message["sensor_type"] or not registration and reply["token"] != int(message["token"], 16)):
            raise RuntimeError("Reply session mismatch")
        return reply

    try:
        for row in rows:
            identifier = row["sensor_id"]
            if identifier in sensors:
                continue
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind(("0.0.0.0", 0))
            udp.settimeout(3)
            state = dict(socket=udp, sensor_type=row["sensor_type"], seq=1)
            sensors[identifier] = state
            reply = exchange(udp, dict(type="REGISTER", seq=1, sensor_type=row["sensor_type"], sensor_id=identifier), True)
            token = reply["token"]
            state["token"] = f"{token:016x}" if variant == "Binary" else token
        start = time.monotonic()
        for index in sorted({row["index"] for row in rows}):
            delay = start + index*interval-time.monotonic()
            if delay > 0:
                time.sleep(delay)
            for row in (item for item in rows if item["index"] == index):
                state = sensors[row["sensor_id"]]
                state["seq"] += 1
                message = dict(type="DATA", seq=state["seq"], sensor_id=row["sensor_id"], token=state["token"], values=row["values"])
                if variant == "Binary":
                    message["sensor_type"] = row["sensor_type"]
                message["crc"] = crc(message)
                exchange(state["socket"], message)
        return packets
    finally:
        for state in sensors.values():
            state["socket"].close()


# porovna skutocny pcap s bajtmi odoslanymi a prijatymi cez sockety
def analyse_capture(capture, packets, variant, run):
    result = subprocess.run([executable("tshark"), "-r", str(capture), "-T", "fields",
        "-e", "udp.payload", "-e", "ip.len", "-e", "frame.len"], capture_output=True, text=True, check=True, timeout=30)
    captured = []
    frame_bytes = ip_bytes = 0
    for line in result.stdout.splitlines():
        payload, ip_length, frame_length = line.split("\t")
        captured.append(bytes.fromhex(payload.replace(":", "")))
        ip_bytes += int(ip_length)
        frame_bytes += int(frame_length)
    if Counter(captured) != Counter(packets):
        raise RuntimeError(f"Capture mismatch: captured {len(captured)}, socket events {len(packets)}")
    if sum(len(packet)+28 for packet in captured) != ip_bytes:
        raise RuntimeError("Captured IPv4 lengths disagree with UDP payloads")
    decode = decode_packet if variant == "Binary" else json_decode
    groups = {"registration": [], "steady": []}
    for packet in captured:
        message = decode(packet)
        if message["type"] == "REGISTER" or message["type"] == "REGISTER_ACK" or message["type"] == "ACK" and "token" in message and variant == "JSON":
            groups["registration"].append(packet)
        else:
            groups["steady"].append(packet)
    summaries = []
    for scenario, group in groups.items():
        summary = dict(variant=variant, run=run, scenario=scenario, packets=len(group))
        for metric in sizes(b""):
            summary[metric] = sum(sizes(packet)[metric] for packet in group)
        summaries.append(summary)
    return summaries, dict(captured_packets=len(captured), captured_frame_bytes=frame_bytes,
        captured_ip_bytes=ip_bytes, sha256=hashlib.sha256(capture.read_bytes()).hexdigest())


# spusti server, dumpcap a replay a uchova skutocne logy aj zachyt
def measure_run(args, rows, variant, run):
    work = args.out/f"{variant.lower()}_{run}"
    work.mkdir(parents=True, exist_ok=False)
    address = (str(socket.gethostbyname(args.host)), args.port)
    server = capture = None
    handles = []
    try:
        error_path = work/"capture.log"
        error_handle = error_path.open("w")
        handles.append(error_handle)
        capture_path = work/"traffic.pcapng"
        capture = subprocess.Popen([executable("dumpcap"), "-i", args.interface,
            "-f", f"udp port {args.port} and host {address[0]}", "-w", str(capture_path.resolve())],
            stdout=subprocess.DEVNULL, stderr=error_handle)
        wait_ready(capture, error_path, "Capturing on")
        # dumpcap oznamuje rozhranie este pred vytvorenim zachytavacieho suboru
        deadline = time.monotonic()+5
        while not capture_path.exists():
            if capture.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError(error_path.read_text())
            time.sleep(0.03)
        if not args.external_server:
            stdout = (work/"server_terminal.txt").open("w")
            handles.append(stdout)
            script = ROOT/("server.py" if variant == "Binary" else "json_baseline/server.py")
            import sys
            server = subprocess.Popen([sys.executable, str(script)], cwd=work.resolve(), stdin=subprocess.PIPE,
                                      stdout=stdout, stderr=subprocess.STDOUT, text=True)
            server.stdin.write(f"{address[0]}\n{args.port}\n")
            server.stdin.flush()
            wait_ready(server, work/"server.log", "Server listening")
        with (work/"replay.jsonl").open("w") as transcript:
            packets = replay(variant, rows, address, args.interval, transcript)
        # pocka na zapis poslednych paketov do zachytu
        time.sleep(0.3)
        stop_process(capture)
        if capture.returncode != 0:
            raise RuntimeError(error_path.read_text())
        summary, capture_info = analyse_capture(capture_path, packets, variant, run)
        expected = 2*len(rows)+2*len({row["sensor_id"] for row in rows})
        if capture_info["captured_packets"] != expected:
            raise RuntimeError("Unexpected number of packets")
        (work/"verified.json").write_text(json.dumps(capture_info, indent=2)+"\n")
        return summary
    finally:
        stop_process(server)
        stop_process(capture)
        if server is not None and server.stdin:
            server.stdin.close()
        for handle in handles:
            handle.close()


# vytvori tabulku priemerov a graf z overenych zivych zachytov
def summarize_results(output, summaries):
    averages = []
    for variant in dict.fromkeys(row["variant"] for row in summaries):
        for scenario in ("registration", "steady"):
            group = [row for row in summaries if row["variant"] == variant and row["scenario"] == scenario]
            record = dict(variant=variant, scenario=scenario, runs=len(group))
            for metric in ("application_bytes", "ip_bytes", "ethernet_bytes"):
                values = [int(row[metric]) for row in group]
                record[metric+"_mean"] = statistics.mean(values)
                record[metric+"_min"] = min(values)
                record[metric+"_max"] = max(values)
            averages.append(record)
    write_csv(output/"averages.csv", averages)
    variants = {row["variant"]: row for row in averages if row["scenario"] == "steady"}
    result = dict(note="L7/L3 captured; Ethernet model calculated from actual UDP payloads; loopback has no Ethernet framing")
    if "JSON" in variants and "Binary" in variants:
        for metric in ("application_bytes", "ethernet_bytes"):
            result[metric+"_saving_percent"] = 100*(1-variants["Binary"][metric+"_mean"]/variants["JSON"][metric+"_mean"])
    (output/"results.json").write_text(json.dumps(result, indent=2)+"\n")
    os.environ.setdefault("MPLCONFIGDIR", "/tmp/pks-measure-matplotlib")
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    figure, axes = plt.subplots(1, 2, figsize=(10, 4), layout="constrained")
    for axis, metric, title in zip(axes, ("application_bytes", "ethernet_bytes"),
        ("Captured application bytes", "Modelled Ethernet bytes (FCS/padding)")):
        names = list(variants)
        values = [variants[name][metric+"_mean"] for name in names]
        errors = [[value-variants[name][metric+"_min"] for name,value in zip(names,values)],
                  [variants[name][metric+"_max"]-value for name,value in zip(names,values)]]
        axis.bar(names, values, yerr=errors, capsize=5, color=["#64748b", "#0284c7"][:len(names)])
        for index, value in enumerate(values):
            axis.text(index, value+max(values)*0.03, f"{value:.1f}", ha="center")
        axis.set_title(title)
        axis.set_ylabel("Bytes per confirmed-measurement batch")
        axis.margins(y=0.2)
    figure.suptitle("Live UDP replay; mean and min/max across runs")
    figure.savefig(output/"comparison.svg")
    figure.savefig(output/"comparison.png", dpi=180)
    plt.close(figure)


# spusti lokalne alebo vzdialene meranie s explicitne ulozenymi podmienkami
def main():
    parser = argparse.ArgumentParser(description="Live UDP replay with real dumpcap captures")
    parser.add_argument("--inputs", type=Path, default=ROOT/"measurements/inputs.json")
    parser.add_argument("--out", type=Path, default=ROOT/"measurements/live")
    parser.add_argument("--variant", choices=("both", "JSON", "Binary"), default="both")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--interval", type=float, default=0.05,
        help="seconds between measurement rounds; 0.05 is accelerated byte benchmark, use 10 for production timing")
    parser.add_argument("--interface", default="lo0")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19000)
    parser.add_argument("--external-server", action="store_true")
    args = parser.parse_args()
    if args.runs < 1 or not 0 <= args.interval <= 10 or not 1 <= args.port <= 65535:
        parser.error("invalid runs, interval or port")
    if args.external_server and (args.variant == "both" or args.runs != 1):
        parser.error("external server requires --variant JSON/Binary --runs 1 and fresh server sessions")
    rows = json.loads(args.inputs.read_text())
    if not rows:
        parser.error("empty dataset")
    args.out.mkdir(parents=True, exist_ok=True)
    if (args.out/"manifest.json").exists():
        parser.error("output already contains a run; use another --out directory")
    manifest = {key: str(value) if isinstance(value, Path) else value for key, value in vars(args).items()}
    manifest.update(input_sha256=hashlib.sha256(args.inputs.read_bytes()).hexdigest(),
                    measurements=len(rows), method="actual UDP with dumpcap; Ethernet sizes modelled from captured IPv4",
                    started_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    (args.out/"inputs.json").write_bytes(args.inputs.read_bytes())
    (args.out/"manifest.json").write_text(json.dumps(manifest, indent=2)+"\n")
    variants = ("JSON", "Binary") if args.variant == "both" else (args.variant,)
    summaries = []
    for run in range(1, args.runs+1):
        for variant in variants:
            summaries.extend(measure_run(args, rows, variant, run))
            print(f"{variant} run {run}: capture and all ACK verified", flush=True)
    write_csv(args.out/"summary.csv", summaries)
    summarize_results(args.out, summaries)
    (args.out/"manifest.json").write_text(json.dumps(dict(manifest, complete=True), indent=2)+"\n")


if __name__ == "__main__":
    main()

