#!/usr/bin/env python3
"""Генератор тестовых pcap-файлов для ЛР3 (граничные случаи сигнатур).

Создаёт файлы:
    probe_ports.pcap  – 7 портов за 1 с (ожидается Port_Probe, LOW)
    slow_scan.pcap    – 15 портов за 150 с (окно 10 с не набирается, алертов нет)
    small_flood.pcap  – 40 SYN с 20 адресов за 1 с (меньше порога 50, алертов нет)
    syn_flood_1src.pcap – 200 SYN с одного адреса за 2 с (SYN_Flood, HIGH)
    icmp_flood.pcap   – 300 ICMP Echo за 1 с на один хост (ICMP_Flood, MEDIUM)
    legit_only.pcap   – только легитимный трафик из lab2_test_traffic.pcap (алертов нет)
    ssh_burst.log     – лог sshd: 12 неудачных входов с одного IP за 40 с (SSH_Brute_Force, HIGH)

Пример запуска:
    python make_test_pcaps_StudentID.py --source lab2_test_traffic.pcap --outdir test_pcaps
"""

import argparse
from ipaddress import ip_address, ip_network
from pathlib import Path

from scapy.all import ICMP, IP, TCP, Ether, rdpcap, wrpcap

START = 1_790_000_000.0  # произвольная начальная метка времени
ATTACK_SCANNER = "203.0.113.100"
ATTACK_FLOOD_NET = ip_network("10.0.0.0/24")


def stamped(packet, timestamp: float):
    """Проставить время захвата пакета."""
    packet.time = timestamp
    return packet


def syn(src: str, dst: str, dport: int, timestamp: float, sport: int = 40000):
    """SYN-пакет."""
    return stamped(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S"), timestamp)


def probe_ports() -> list:
    """7 портов с одного IP за 1 секунду."""
    return [syn("198.51.100.7", "192.168.1.60", 20 + i, START + i / 7) for i in range(7)]


def slow_scan() -> list:
    """15 портов, по одному раз в 10 секунд."""
    return [syn("198.51.100.8", "192.168.1.60", 20 + i, START + i * 10.0) for i in range(15)]


def small_flood() -> list:
    """40 SYN с 20 адресов на один порт за 1 секунду (ниже порога 50)."""
    return [syn(f"10.1.0.{n}", "192.168.1.100", 80, START + (n * 2 + k) / 40, sport=41000 + k)
            for n in range(1, 21) for k in range(2)]


def syn_flood_1src() -> list:
    """200 SYN с одного адреса с разных портов на один порт цели."""
    return [syn("198.51.100.9", "192.168.1.100", 443, START + i / 100, sport=30000 + i) for i in range(200)]


def icmp_flood() -> list:
    """300 ICMP Echo Request от одного источника на один хост за секунду."""
    return [stamped(Ether() / IP(src="198.51.100.10", dst="192.168.1.70") / ICMP(type=8, seq=i),
                    START + i / 300) for i in range(300)]


def legit_only(source: str) -> list:
    """Оставить в исходном pcap только легитимные пакеты (без трёх атак)."""
    kept = []
    for packet in rdpcap(source):
        if IP not in packet:
            continue
        src, dst = packet[IP].src, packet[IP].dst
        if src == ATTACK_SCANNER or ip_address(src) in ATTACK_FLOOD_NET or dst.endswith(".255"):
            continue
        kept.append(packet)
    return kept


def ssh_burst_log() -> list[str]:
    """Лог sshd: быстрый перебор паролей с одного IP на фоне обычных событий."""
    lines = ["Nov 14 10:00:00 server sshd[900]: Accepted password for admin from 192.168.1.5 port 50000 ssh2"]
    for i in range(12):  # 12 попыток за 40 секунд
        second = 5 + i * 3
        lines.append(f"Nov 14 10:00:{second:02d} server sshd[{1000 + i}]: "
                     f"Failed password for root from 203.0.113.77 port {40000 + i} ssh2")
    for i, minute in enumerate((1, 4, 8)):  # редкие ошибки другого адреса — не атака
        lines.append(f"Nov 14 10:{minute:02d}:10 server sshd[{2000 + i}]: "
                     f"Failed password for user from 192.0.2.50 port {41000 + i} ssh2")
    return lines


def main() -> None:
    parser = argparse.ArgumentParser(description="Генератор тестовых pcap для ЛР3.")
    parser.add_argument("--source", default="lab2_test_traffic.pcap", help="pcap из ЛР2 (для legit_only.pcap)")
    parser.add_argument("--outdir", default="test_pcaps", help="папка для результатов")
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    files = {
        "probe_ports.pcap": probe_ports(), "slow_scan.pcap": slow_scan(),
        "small_flood.pcap": small_flood(), "syn_flood_1src.pcap": syn_flood_1src(),
        "icmp_flood.pcap": icmp_flood(),
    }
    if Path(args.source).exists():
        files["legit_only.pcap"] = legit_only(args.source)
    else:
        print(f"Файл {args.source} не найден, legit_only.pcap пропущен.")

    for name, packets in files.items():
        wrpcap(str(outdir / name), packets)
        print(f"{outdir / name}: {len(packets)} пакетов")

    log_lines = ssh_burst_log()
    (outdir / "ssh_burst.log").write_text("\n".join(log_lines) + "\n", encoding="utf-8")
    print(f"{outdir / 'ssh_burst.log'}: {len(log_lines)} строк")


if __name__ == "__main__":
    main()
