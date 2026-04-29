#!/usr/bin/env python3
"""
PCAP to CSV Converter
=====================
Parses monthly .cap.gz PCAP files and writes one CSV per file.

Output columns:
    timestamp, source_ip, source_port, destination_ip, destination_port,
    protocol, tcp_flags, icmp_type, icmp_code, packet_length, ttl, ip_id,
    window_size

Run from the folder containing the .cap.gz files:
    python pcap_to_csv.py                        # process all months
    python pcap_to_csv.py --months jan feb mar   # process specific months

Output: jan.csv, feb.csv, ... in the same folder.

Requirements:
    pip install dpkt
"""

import argparse
import csv
import gzip
import os
from datetime import datetime, timezone

import dpkt


MONTHS = ["jan", "feb", "mar", "apr", "may", "jun",
          "jul", "aug", "sep", "oct", "nov", "dec"]

PROTO_NAMES = {
    dpkt.ip.IP_PROTO_TCP:  "TCP",
    dpkt.ip.IP_PROTO_UDP:  "UDP",
    dpkt.ip.IP_PROTO_ICMP: "ICMP",
    47:                    "GRE",
}

CSV_HEADER = [
    "timestamp", "source_ip", "source_port",
    "destination_ip", "destination_port",
    "protocol", "tcp_flags", "icmp_type", "icmp_code",
    "packet_length", "ttl", "ip_id", "window_size",
]


def get_ip_layer(buf, linktype):
    """Return dpkt.ip.IP from a raw packet buffer, or None."""
    try:
        if linktype == dpkt.pcap.DLT_EN10MB:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
        elif linktype == 101:   # raw IP
            ip = dpkt.ip.IP(buf)
        else:
            return None
        return ip if isinstance(ip, dpkt.ip.IP) else None
    except Exception:
        return None


def bytes_to_ip(raw):
    """Convert 4-byte IP to dotted-decimal string."""
    return ".".join(str(b) for b in raw)


def process_file(pcap_path, csv_path):
    print(f"  Reading : {pcap_path}")
    print(f"  Writing : {csv_path}")

    total = 0
    skipped = 0

    with gzip.open(pcap_path, "rb") as gz, \
         open(csv_path, "w", newline="", encoding="utf-8") as csvfile:

        writer = csv.writer(csvfile)
        writer.writerow(CSV_HEADER)

        try:
            pcap = dpkt.pcap.Reader(gz)
            linktype = pcap.datalink()
        except Exception as e:
            print(f"  ERROR opening PCAP: {e}")
            return

        for ts, buf in pcap:
            total += 1
            if total % 5_000_000 == 0:
                print(f"    ... {total:,} packets")

            ip = get_ip_layer(buf, linktype)
            if ip is None:
                skipped += 1
                continue

            # Timestamp (UTC ISO-8601)
            try:
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
            except (OSError, OverflowError, ValueError):
                timestamp = ""

            src_ip  = bytes_to_ip(ip.src)
            dst_last = f".{ip.dst[-1]}"         # last octet only, e.g. ".1"
            proto_num = ip.p
            proto_name = PROTO_NAMES.get(proto_num, str(proto_num))
            pkt_len = ip.len
            ttl     = ip.ttl
            ip_id   = ip.id

            # Protocol-specific fields
            src_port    = ""
            dst_port    = ""
            tcp_flags   = ""
            icmp_type   = ""
            icmp_code   = ""
            window_size = ""

            transport = ip.data

            if proto_num == dpkt.ip.IP_PROTO_TCP and isinstance(transport, dpkt.tcp.TCP):
                src_port    = transport.sport
                dst_port    = transport.dport
                tcp_flags   = hex(transport.flags)
                window_size = transport.win

            elif proto_num == dpkt.ip.IP_PROTO_UDP and isinstance(transport, dpkt.udp.UDP):
                src_port = transport.sport
                dst_port = transport.dport

            elif proto_num == dpkt.ip.IP_PROTO_ICMP and isinstance(transport, dpkt.icmp.ICMP):
                icmp_type = transport.type
                icmp_code = transport.code

            writer.writerow([
                timestamp, src_ip, src_port,
                dst_last, dst_port,
                proto_name, tcp_flags, icmp_type, icmp_code,
                pkt_len, ttl, ip_id, window_size,
            ])

    print(f"  Packets read    : {total:,}")
    print(f"  Skipped (non-IP): {skipped:,}")
    print(f"  Done -> {csv_path}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Convert network telescope .cap.gz files to CSV"
    )
    parser.add_argument(
        "--months",
        nargs="+",
        choices=MONTHS,
        default=MONTHS,
        metavar="MONTH",
        help="Months to process (default: all). E.g. --months jan feb mar",
    )
    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))

    print("PCAP to CSV Converter")
    print(f"  Directory : {base_dir}")
    print(f"  Months    : {', '.join(args.months)}\n")

    for month in args.months:
        pcap_path = os.path.join(base_dir, f"{month}.cap.gz")
        csv_path  = os.path.join(base_dir, f"{month}.csv")

        if not os.path.exists(pcap_path):
            print(f"  Skipping {month}: {pcap_path} not found\n")
            continue

        print(f"[{month.upper()}]")
        process_file(pcap_path, csv_path)

    print("All done.")


if __name__ == "__main__":
    main()
