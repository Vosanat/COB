#!/usr/bin/env python3
"""Лабораторная работа №2: анализ сетевого трафика на основе библиотеки Scapy.

Скрипт перехватывает пакеты (или читает их из pcap-файла), агрегирует их в
двунаправленные потоки, считает статистику, классифицирует подозрительный
трафик и строит графики.

Примеры запуска:
    python ids_lab2_StudentID.py --iface Realtek --count 500
    python ids_lab2_StudentID.py --iface 7 --count 500
    python ids_lab2_StudentID.py --pcap lab2_test_traffic.pcap --classify --plots
"""

import argparse
import sys
from collections import Counter, defaultdict
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Optional

from scapy.all import ICMP, IP, TCP, UDP, sniff

# --- Константы -------------------------------------------------------------

DEFAULT_COUNT = 500
DEFAULT_TOP = 20
DEFAULT_OUTDIR = "plots"

# Пороги эвристик классификации (задание 9).
SCAN_MIN_PORTS = 10        # столько разных портов с одного IP -> сканирование
FLOOD_MIN_SYN = 50         # столько SYN без ACK на один порт -> SYN-флуд
ICMP_MAX_SIZE = 128        # ICMP-пакеты крупнее (байт) считаются аномальными

CATEGORY_LEGIT = "Легитимный трафик"
CATEGORY_SCAN = "Сканирование портов"
CATEGORY_FLOOD = "SYN-флуд (DoS)"
CATEGORY_ICMP = "Аномалии ICMP"
CATEGORIES = (CATEGORY_LEGIT, CATEGORY_SCAN, CATEGORY_FLOOD, CATEGORY_ICMP)

TCP_FLAG_BITS = {"SYN": 0x02, "ACK": 0x10, "RST": 0x04, "FIN": 0x01, "PSH": 0x08}

FlowKey = tuple  # (ip_a, ip_b, port_a, port_b, protocol)


# --- Накопление статистики -------------------------------------------------

def new_flow() -> dict:
    """Создать пустую запись о потоке (значение для defaultdict)."""
    return {
        "packets": 0, "bytes": 0, "start_time": 0.0, "end_time": 0.0,
        "syn_count": 0, "ack_count": 0, "rst_count": 0, "fin_count": 0,
    }


class Capture:
    """Накопитель данных о перехваченном трафике."""

    def __init__(self) -> None:
        self.flows: defaultdict = defaultdict(new_flow)
        self.sizes: list[int] = []
        self.records: list[tuple[float, int, FlowKey]] = []  # (время, размер, поток)
        self.protocols: Counter = Counter()
        self.flags: Counter = Counter()


def get_protocol(packet) -> Optional[str]:
    """Определить транспортный протокол пакета; None, если пакет не подходит."""
    if IP not in packet:
        return None
    for layer, name in ((TCP, "TCP"), (UDP, "UDP"), (ICMP, "ICMP")):
        if layer in packet:
            return name
    return None


def get_ports(packet, protocol: str) -> tuple[int, int]:
    """Вернуть (порт источника, порт назначения); для ICMP — (0, 0)."""
    if protocol == "ICMP":
        return 0, 0
    layer = packet[TCP] if protocol == "TCP" else packet[UDP]
    return layer.sport, layer.dport


def make_flow_key(src: str, dst: str, sport: int, dport: int, protocol: str) -> FlowKey:
    """Построить симметричный ключ: A -> B и B -> A дают один и тот же ключ."""
    if (src, sport) <= (dst, dport):
        return src, dst, sport, dport, protocol
    return dst, src, dport, sport, protocol


def format_summary(packet, protocol: str) -> str:
    """Краткая сводка пакета: [timestamp] SRC:SPORT -> DST:DPORT (Protocol)."""
    sport, dport = get_ports(packet, protocol)
    stamp = datetime.fromtimestamp(float(packet.time)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    return (f"[{stamp}] {packet[IP].src}:{sport} -> "
            f"{packet[IP].dst}:{dport} ({protocol})")


def process_packet(packet, capture: Capture, verbose: bool = False) -> None:
    """Обработчик пакета: проверить слои, вывести сводку и обновить статистику."""
    protocol = get_protocol(packet)
    if protocol is None:
        return  # нет слоёв IP + TCP/UDP/ICMP — пакет игнорируется

    if verbose:
        print(format_summary(packet, protocol))

    src, dst = packet[IP].src, packet[IP].dst
    sport, dport = get_ports(packet, protocol)
    key = make_flow_key(src, dst, sport, dport, protocol)
    timestamp = float(packet.time)
    size = len(packet)

    flow = capture.flows[key]
    if flow["packets"] == 0:  # первый пакет задаёт время начала и направление
        flow.update(start_time=timestamp, src=src, dst=dst, sport=sport, dport=dport,
                    protocol=protocol, icmp_type=packet[ICMP].type if protocol == "ICMP" else None)
    flow["packets"] += 1
    flow["bytes"] += size
    flow["end_time"] = max(flow["end_time"], timestamp)

    if protocol == "TCP":
        flags = int(packet[TCP].flags)
        for name, bit in TCP_FLAG_BITS.items():
            if flags & bit:
                capture.flags[name] += 1
        flow["syn_count"] += bool(flags & TCP_FLAG_BITS["SYN"])
        flow["ack_count"] += bool(flags & TCP_FLAG_BITS["ACK"])
        flow["rst_count"] += bool(flags & TCP_FLAG_BITS["RST"])
        flow["fin_count"] += bool(flags & TCP_FLAG_BITS["FIN"])

    capture.protocols[protocol] += 1
    capture.sizes.append(size)
    capture.records.append((timestamp, size, key))


def resolve_interface(query: str):
    """Найти интерфейс по индексу, точному имени или части имени/описания.

    Позволяет писать `--iface 7` или `--iface Realtek` вместо полного имени.
    Если интерфейс не найден, выбрасывает ValueError со списком доступных.
    """
    from scapy.all import conf

    interfaces = list(conf.ifaces.values())
    if query.isdigit():
        for iface in interfaces:
            if str(iface.index) == query:
                return iface
    needle = query.lower()
    for iface in interfaces:
        if needle == str(iface.name).lower():
            return iface
    for iface in interfaces:
        if needle in f"{iface.name} {iface.description}".lower():
            return iface

    available = ", ".join(f"{i.index}: {i.name}" for i in interfaces)
    raise ValueError(f"интерфейс '{query}' не найден. Доступные: {available}")


def run_capture(args: argparse.Namespace) -> Capture:
    """Перехватить трафик с интерфейса или прочитать его из pcap-файла."""
    capture = Capture()

    def callback(packet) -> None:
        process_packet(packet, capture, args.verbose)

    if args.pcap:
        sniff(offline=args.pcap, prn=callback, store=False)
    else:
        iface = resolve_interface(args.iface) if args.iface else None
        sniff(iface=iface, prn=callback, count=args.count, store=False)
    return capture


# --- Вычисляемые показатели ------------------------------------------------

def flow_metrics(flow: dict) -> dict:
    """Вычислить длительность, PPS, BPS, долю SYN и средний размер пакета."""
    duration = flow["end_time"] - flow["start_time"]
    packets = flow["packets"]
    return {
        "duration": duration,
        "pps": packets / duration if duration > 0 else None,
        "bps": flow["bytes"] * 8 / duration if duration > 0 else None,
        "syn_percent": 100 * flow["syn_count"] / packets,
        "avg_size": flow["bytes"] / packets,
    }


def format_number(value: Optional[float], digits: int = 1) -> str:
    """Отформатировать число; для неопределённых значений вернуть «—»."""
    return "—" if value is None else f"{value:.{digits}f}"


def flow_name(flow: dict) -> str:
    """Имя потока в виде SRC:SPORT -> DST:DPORT."""
    return f"{flow['src']}:{flow['sport']} -> {flow['dst']}:{flow['dport']}"


def sorted_flows(capture: Capture) -> list[dict]:
    """Потоки, отсортированные по убыванию числа пакетов."""
    return sorted(capture.flows.values(), key=lambda f: (-f["packets"], -f["bytes"]))


# --- Классификация трафика (задание 9) -------------------------------------

def is_broadcast(address: str) -> bool:
    """Широковещательный (x.x.x.255, 255.255.255.255) или multicast-адрес."""
    ip = ip_address(address)
    return ip.is_multicast or address.endswith(".255")


def classify_flows(capture: Capture) -> dict[FlowKey, str]:
    """Отнести каждый поток к одной из категорий CATEGORIES."""
    labels = {key: CATEGORY_LEGIT for key in capture.flows}

    syn_only = {key: f for key, f in capture.flows.items()
                if f["protocol"] == "TCP" and f["syn_count"] == f["packets"] and f["ack_count"] == 0}

    # Сканирование: один источник -> одна цель, много разных портов только SYN.
    ports_by_pair: defaultdict = defaultdict(set)
    for key, flow in syn_only.items():
        ports_by_pair[(flow["src"], flow["dst"])].add(flow["dport"])
    scanners = {pair for pair, ports in ports_by_pair.items() if len(ports) >= SCAN_MIN_PORTS}

    # SYN-флуд: много SYN без ACK на один и тот же порт цели.
    syn_by_target: Counter = Counter()
    for flow in syn_only.values():
        syn_by_target[(flow["dst"], flow["dport"])] += flow["packets"]
    flooded = {target for target, count in syn_by_target.items() if count >= FLOOD_MIN_SYN}

    for key, flow in capture.flows.items():
        if key in syn_only and (flow["src"], flow["dst"]) in scanners:
            labels[key] = CATEGORY_SCAN
        elif key in syn_only and (flow["dst"], flow["dport"]) in flooded:
            labels[key] = CATEGORY_FLOOD
        elif flow["protocol"] == "ICMP" and (
                is_broadcast(flow["dst"]) or flow["bytes"] / flow["packets"] > ICMP_MAX_SIZE):
            labels[key] = CATEGORY_ICMP
    return labels


def summarize_categories(capture: Capture, labels: dict[FlowKey, str]) -> dict:
    """Собрать по категориям число потоков, пакетов, байт и набор источников/целей."""
    summary = {name: {"flows": 0, "packets": 0, "bytes": 0, "src": set(), "dst": set()}
               for name in CATEGORIES}
    for key, flow in capture.flows.items():
        item = summary[labels[key]]
        item["flows"] += 1
        item["packets"] += flow["packets"]
        item["bytes"] += flow["bytes"]
        item["src"].add(flow["src"])
        item["dst"].add(flow["dst"])
    return summary


# --- Текстовый отчёт -------------------------------------------------------

def print_flow_table(capture: Capture, top: int) -> None:
    """Итоговая таблица потоков: пакеты, байты, длительность, PPS, BPS."""
    flows = sorted_flows(capture)
    shown = flows if top <= 0 else flows[:top]

    line = "=" * 112
    print(f"\n{line}\nИТОГОВЫЙ ОТЧЁТ ПО ЗАХВАЧЕННЫМ ПОТОКАМ\n{line}")
    print(f"{'Протокол':<9}{'Поток':<50}{'Пакетов':>8}{'Байт':>9}"
          f"{'Длит., с':>11}{'PPS':>10}{'BPS':>11}")
    print("-" * 112)
    for flow in shown:
        m = flow_metrics(flow)
        print(f"{flow['protocol']:<9}{flow_name(flow):<50}{flow['packets']:>8}{flow['bytes']:>9}"
              f"{m['duration']:>11.4f}{format_number(m['pps']):>10}{format_number(m['bps']):>11}")
    print("-" * 112)
    if len(shown) < len(flows):
        print(f"Показано {len(shown)} из {len(flows)} потоков (параметр --top).")
    print(f"Всего потоков: {len(flows)} | Всего пакетов: {len(capture.sizes)} "
          f"| Всего байт: {sum(capture.sizes)}")


def print_tcp_table(capture: Capture, top: int) -> None:
    """Таблица TCP-потоков: флаги, доля SYN, средний размер пакета."""
    flows = [f for f in sorted_flows(capture) if f["protocol"] == "TCP"]
    shown = flows if top <= 0 else flows[:top]
    if not shown:
        return

    print("\nTCP-флаги и производные показатели:")
    print(f"{'Поток':<50}{'SYN':>5}{'ACK':>5}{'RST':>5}{'FIN':>5}{'SYN, %':>9}{'Ср. размер':>12}")
    print("-" * 91)
    for flow in shown:
        m = flow_metrics(flow)
        print(f"{flow_name(flow):<50}{flow['syn_count']:>5}{flow['ack_count']:>5}"
              f"{flow['rst_count']:>5}{flow['fin_count']:>5}{m['syn_percent']:>9.1f}"
              f"{m['avg_size']:>12.1f}")


def print_classification(capture: Capture, labels: dict[FlowKey, str]) -> None:
    """Сводка по категориям трафика."""
    summary = summarize_categories(capture, labels)
    print("\nКЛАССИФИКАЦИЯ ТРАФИКА")
    print("-" * 112)
    print(f"{'Категория':<22}{'Потоков':>8}{'Пакетов':>9}{'Байт':>8}  Источники -> цели")
    for name in CATEGORIES:
        item = summary[name]
        if item["flows"] == 0:
            continue
        sources = sorted(item["src"])
        targets = sorted(item["dst"])
        src_text = sources[0] if len(sources) == 1 else f"{len(sources)} источников"
        dst_text = targets[0] if len(targets) == 1 else f"{len(targets)} адресов"
        print(f"{name:<22}{item['flows']:>8}{item['packets']:>9}{item['bytes']:>8}  "
              f"{src_text} -> {dst_text}")


# --- Графики (дополнительное задание) --------------------------------------

def build_plots(capture: Capture, labels: Optional[dict], outdir: str, show: bool) -> list[str]:
    """Построить и сохранить графики; вернуть список созданных файлов."""
    import matplotlib
    if not show:
        matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    Path(outdir).mkdir(parents=True, exist_ok=True)
    saved: list[str] = []

    def save(fig, name: str) -> None:
        path = str(Path(outdir) / name)
        fig.tight_layout()
        fig.savefig(path, dpi=150)
        saved.append(path)

    # 1. Топ-10 потоков по количеству пакетов.
    top = sorted_flows(capture)[:10]
    fig, ax = plt.subplots(figsize=(10, 5))
    names = [flow_name(f) for f in top][::-1]
    counts = np.array([f["packets"] for f in top])[::-1]
    ax.barh(names, counts, color="teal")
    ax.set_xlabel("Количество пакетов")
    ax.set_title("Топ-10 самых активных потоков")
    save(fig, "top_flows.png")

    # 2. Гистограмма размеров пакетов (логарифмическая шкала по Y).
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.hist(capture.sizes, bins=50, color="skyblue", edgecolor="black", log=True)
    ax.set_xlabel("Размер пакета (байты)")
    ax.set_ylabel("Количество пакетов")
    ax.set_title("Распределение размеров пакетов в захваченном трафике")
    save(fig, "packet_sizes.png")

    # 3. Протоколы и TCP-флаги.
    fig, (ax_proto, ax_flags) = plt.subplots(1, 2, figsize=(11, 5))
    ax_proto.pie(list(capture.protocols.values()), labels=list(capture.protocols.keys()),
                 autopct="%1.1f%%")
    ax_proto.set_title("Распределение протоколов")
    flag_names = list(TCP_FLAG_BITS)
    ax_flags.bar(flag_names, [capture.flags[name] for name in flag_names], color="teal")
    ax_flags.set_xlabel("TCP-флаг")
    ax_flags.set_ylabel("Количество пакетов")
    ax_flags.set_title("Частота TCP-флагов")
    save(fig, "protocols_flags.png")

    # 4. Таймлайн: время от начала захвата и размер пакета.
    start = min(t for t, _, _ in capture.records)
    fig, ax = plt.subplots(figsize=(10, 5))
    if labels:
        for category in CATEGORIES:
            points = [(t - start, s) for t, s, k in capture.records if labels[k] == category]
            if points:
                xs, ys = zip(*points)
                ax.scatter(xs, ys, s=14, label=category)
        ax.legend()
    else:
        ax.scatter([t - start for t, _, _ in capture.records],
                   [s for _, s, _ in capture.records], s=14, color="orange")
    ax.set_xlabel("Время от начала захвата (с)")
    ax.set_ylabel("Размер пакета (байты)")
    ax.set_title("Активность трафика во времени")
    save(fig, "timeline.png")

    if show:
        plt.show()
    plt.close("all")
    return saved


# --- Точка входа -----------------------------------------------------------

def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    """Разобрать аргументы командной строки."""
    parser = argparse.ArgumentParser(description="Анализ сетевого трафика (Scapy).")
    parser.add_argument("--iface", help="сетевой интерфейс для перехвата (eth0, Ethernet, ...)")
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT,
                        help=f"сколько пакетов перехватить (по умолчанию {DEFAULT_COUNT})")
    parser.add_argument("--pcap", help="читать пакеты из pcap-файла вместо перехвата")
    parser.add_argument("--top", type=int, default=DEFAULT_TOP,
                        help=f"сколько потоков показать в таблицах, 0 — все (по умолчанию {DEFAULT_TOP})")
    parser.add_argument("--verbose", action="store_true", help="печатать сводку по каждому пакету")
    parser.add_argument("--classify", action="store_true", help="классифицировать трафик")
    parser.add_argument("--plots", action="store_true", help="построить графики (matplotlib)")
    parser.add_argument("--show", action="store_true", help="показать графики на экране")
    parser.add_argument("--outdir", default=DEFAULT_OUTDIR, help="папка для PNG-графиков")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    """Запустить анализ. Код возврата: 0 — успех, 1 — ошибка или нет данных."""
    args = parse_args(argv)

    try:
        capture = run_capture(args)
    except (OSError, PermissionError, ValueError) as error:
        print(f"[ERROR] Не удалось получить трафик: {error}", file=sys.stderr)
        return 1

    if not capture.flows:
        print("Подходящих пакетов (IP + TCP/UDP/ICMP) не обнаружено.")
        return 1

    labels = classify_flows(capture) if args.classify else None

    print_flow_table(capture, args.top)
    print_tcp_table(capture, args.top)
    if labels:
        print_classification(capture, labels)

    if args.plots:
        for path in build_plots(capture, labels, args.outdir, args.show):
            print(f"График '{path}' сохранён.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
