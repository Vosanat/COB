#!/usr/bin/env python3
"""Лабораторная работа №3: обнаружение атак по сигнатурам.

Скрипт агрегирует сетевой трафик в потоки (логика ЛР2), сравнивает потоки с базой
сигнатур (сканирование портов, SYN-флуд, ICMP smurf/flood, brute-force SSH по логам),
формирует алерты, пишет их в файл в формате JSON Lines и выводит в консоль с
фильтрацией по уровню серьёзности и цветовой маркировкой.

Примеры запуска:
    python ids_lab3_StudentID.py --iface Realtek --count 500
    python ids_lab3_StudentID.py --iface 7 --threshold-severity MEDIUM --log ids_alerts.log
    python ids_lab3_StudentID.py --ssh-log L1.txt --signatures signatures.json
Проверка на pcap-файле выполняется вспомогательным скриптом test_pcap_StudentID.py.
"""

import argparse
import json
import operator
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Callable, Optional

from scapy.all import ICMP, IP, TCP, UDP, sniff

# --- Константы -------------------------------------------------------------

DEFAULT_LOG = "ids_alerts.log"
DEFAULT_COUNT = 500
DEFAULT_INTERVAL = 50          # как часто (в пакетах) запускать проверку сигнатур при перехвате
DEFAULT_WINDOW = 10.0          # окно анализа по умолчанию, секунд

SEVERITY_LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
SEVERITY_COLORS = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m"}  # красный, жёлтый, синий
COLOR_RESET = "\033[0m"

TCP_FLAG_BITS = {"SYN": 0x02, "ACK": 0x10, "RST": 0x04, "FIN": 0x01}
ICMP_ECHO_REQUEST = 8

# Поля, которые попадают в блок details алерта для каждого типа сигнатур (scope).
DETAIL_FIELDS = {
    "flow": ("proto", "sport", "dport", "icmp_type", "packets", "bytes", "duration", "pps"),
    "src_dst": ("unique_syn_ports", "syn_packets", "packets", "half_open_ratio", "window"),
    "dst_port": ("dport", "unique_sources", "syn_packets", "packets", "syn_ratio", "window"),
    "log_src": ("failed_attempts", "window"),
}

FlowKey = tuple


# --- Агрегация потоков (логика ЛР2) ----------------------------------------

def new_flow() -> dict:
    """Создать пустую запись о потоке (значение для defaultdict)."""
    return {
        "packets": 0, "bytes": 0, "start_time": 0.0, "end_time": 0.0,
        "syn_count": 0, "ack_count": 0, "rst_count": 0, "fin_count": 0,
    }


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
    """Симметричный ключ потока: A -> B и B -> A дают один и тот же ключ."""
    if (src, sport) <= (dst, dport):
        return src, dst, sport, dport, protocol
    return dst, src, dport, sport, protocol


def packet_handler(packet, flow_stats: dict) -> None:
    """Обработчик пакета (аналог process_packet из ЛР2): обновить flow_stats."""
    protocol = get_protocol(packet)
    if protocol is None:
        return

    src, dst = packet[IP].src, packet[IP].dst
    sport, dport = get_ports(packet, protocol)
    key = make_flow_key(src, dst, sport, dport, protocol)
    timestamp = float(packet.time)

    flow = flow_stats.setdefault(key, new_flow())
    if flow["packets"] == 0:  # первый пакет задаёт время начала и направление потока
        flow.update(
            start_time=timestamp, src=src, dst=dst, sport=sport, dport=dport, proto=protocol,
            icmp_type=packet[ICMP].type if protocol == "ICMP" else None,
        )
    flow["packets"] += 1
    flow["bytes"] += len(packet)
    flow["end_time"] = max(flow["end_time"], timestamp)

    if protocol == "TCP":
        flags = int(packet[TCP].flags)
        flow["syn_count"] += bool(flags & TCP_FLAG_BITS["SYN"])
        flow["ack_count"] += bool(flags & TCP_FLAG_BITS["ACK"])
        flow["rst_count"] += bool(flags & TCP_FLAG_BITS["RST"])
        flow["fin_count"] += bool(flags & TCP_FLAG_BITS["FIN"])


# --- Записи журнала sshd как «потоки» (интеграция с ЛР1) -------------------

SSH_FAILED_PATTERNS = (
    re.compile(r"sshd\[\d+\]:\s+Failed password for (?:invalid user )?\S+ "
               r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b"),
    re.compile(r"sshd\[\d+\]:\s+Invalid user \S+ from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b"),
)
SYSLOG_TIMESTAMP = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")


def load_ssh_log(path: str, flow_stats: dict, year: Optional[int] = None) -> int:
    """Добавить неудачные попытки входа из лога sshd в flow_stats как записи proto='LOG'.

    Возвращает число добавленных записей. Год в syslog не указан, поэтому подставляется
    переданный (по умолчанию текущий).
    """
    year = year or datetime.now().year
    added = 0
    with open(path, "r", encoding="utf-8") as file:
        for number, line in enumerate(file):
            ts_match = SYSLOG_TIMESTAMP.match(line)
            ip = next((m.group("ip") for p in SSH_FAILED_PATTERNS if (m := p.search(line))), None)
            if ts_match is None or ip is None:
                continue
            moment = datetime.strptime(f"{year} {ts_match.group('ts')}", "%Y %b %d %H:%M:%S")
            timestamp = moment.replace(tzinfo=timezone.utc).timestamp()
            flow_stats[("LOG", ip, number)] = {
                "proto": "LOG", "src": ip, "dst": None, "sport": 0, "dport": 22,
                "packets": 1, "bytes": len(line), "start_time": timestamp, "end_time": timestamp,
                "syn_count": 0, "ack_count": 0, "rst_count": 0, "fin_count": 0, "icmp_type": None,
            }
            added += 1
    return added


# --- Вычисляемые показатели потока -----------------------------------------

def is_broadcast(address: Optional[str]) -> bool:
    """Широковещательный (x.x.x.255, 255.255.255.255) или multicast-адрес."""
    if not address:
        return False
    return ip_address(address).is_multicast or address.endswith(".255")


def is_half_open(flow: dict) -> bool:
    """Попытка соединения без завершённого рукопожатия.

    Поток начался с SYN и состоит не более чем из двух пакетов: SYN и, возможно, ответ
    (SYN-ACK или RST). Обычное соединение содержит больше пакетов.
    """
    return flow["proto"] == "TCP" and flow["syn_count"] >= 1 and flow["packets"] <= 2


def enrich_flow(flow: dict) -> dict:
    """Скопировать поток и добавить производные показатели (duration, pps, syn_ratio и т. д.)."""
    duration = flow["end_time"] - flow["start_time"]
    stats = dict(flow)
    stats.update(
        duration=duration,
        pps=flow["packets"] / max(duration, 1e-3),
        bps=flow["bytes"] * 8 / max(duration, 1e-3),
        syn_ratio=flow["syn_count"] / flow["packets"],
        avg_size=flow["bytes"] / flow["packets"],
        dst_is_broadcast=is_broadcast(flow.get("dst")),
        is_echo_request=flow.get("icmp_type") == ICMP_ECHO_REQUEST,
        end_time=flow["end_time"],
    )
    return stats


# --- Окно анализа и группы потоков -----------------------------------------

def best_window(events: list, window: float) -> Optional[dict]:
    """Найти окно длиной `window` секунд с наибольшим числом уникальных участников.

    Каждое событие: (время, участник или None, попыток соединения, пакетов, ключ потока).
    Участник None не учитывается в числе уникальных (поток не относится к атаке).
    Возвращает число уникальных участников, попыток соединения (syn_packets), пакетов и потоков.
    """
    events = sorted(events, key=lambda e: e[0])
    members: Counter = Counter()
    syn = packets = left = 0
    best: Optional[tuple] = None

    for right, (ts, member, syn_count, packet_count, _) in enumerate(events):
        if member is not None:
            members[member] += 1
        syn += syn_count
        packets += packet_count
        while ts - events[left][0] > window:
            old_ts, old_member, old_syn, old_packets, _ = events[left]
            if old_member is not None:
                members[old_member] -= 1
                if members[old_member] == 0:
                    del members[old_member]
            syn -= old_syn
            packets -= old_packets
            left += 1
        score = (len(members), syn, packets)
        if best is None or score > best[0]:
            best = (score, left, right, set(members))

    if best is None:
        return None
    _, left, right, member_set = best
    window_events = events[left:right + 1]
    return {
        "members": member_set, "unique": best[0][0], "syn_packets": best[0][1],
        "packets": best[0][2], "flows": len(window_events),
        "start_time": window_events[0][0], "end_time": window_events[-1][0],
        "flow_keys": [e[4] for e in window_events if e[1] is not None],
    }


def build_flow_groups(flow_stats: dict) -> dict:
    """Группа «flow»: каждый поток отдельно."""
    groups = {}
    for key, flow in flow_stats.items():
        if flow["packets"]:
            stats = enrich_flow(flow)
            stats["_flow_keys"] = [key]
            groups[key] = stats
    return groups


def build_src_dst_groups(flow_stats: dict, window: float) -> dict:
    """Группа «src_dst»: TCP-потоки от одного источника к одной цели (сканирование портов)."""
    events: defaultdict = defaultdict(list)
    for key, flow in flow_stats.items():
        if flow["proto"] == "TCP" and flow["packets"]:
            member = flow["dport"] if is_half_open(flow) else None
            events[(flow["src"], flow["dst"])].append(
                (flow["start_time"], member, 1 if member is not None else 0,
                 flow["packets"], key))

    groups = {}
    for (src, dst), items in events.items():
        found = best_window(items, window)
        if found is None:
            continue
        groups[(src, dst)] = {
            "src": src, "dst": dst, "proto": "TCP", "window": window,
            "unique_syn_ports": found["unique"], "syn_packets": found["syn_packets"],
            "packets": found["packets"],
            "half_open_ratio": found["syn_packets"] / found["flows"],
            "start_time": found["start_time"], "end_time": found["end_time"],
            "_flow_keys": found["flow_keys"],
        }
    return groups


def build_dst_port_groups(flow_stats: dict, window: float) -> dict:
    """Группа «dst_port»: TCP-потоки на один порт одной цели (SYN-флуд)."""
    events: defaultdict = defaultdict(list)
    for key, flow in flow_stats.items():
        if flow["proto"] == "TCP" and flow["packets"]:
            member = flow["src"] if is_half_open(flow) else None
            events[(flow["dst"], flow["dport"])].append(
                (flow["start_time"], member, 1 if member is not None else 0,
                 flow["packets"], key))

    groups = {}
    for (dst, dport), items in events.items():
        found = best_window(items, window)
        if found is None:
            continue
        groups[(dst, dport)] = {
            "dst": dst, "dport": dport, "proto": "TCP", "window": window,
            "unique_sources": found["unique"], "syn_packets": found["syn_packets"],
            "packets": found["packets"], "syn_ratio": found["syn_packets"] / found["flows"],
            "sources": sorted(found["members"]),
            "start_time": found["start_time"], "end_time": found["end_time"],
            "_flow_keys": found["flow_keys"],
        }
    return groups


def build_log_groups(flow_stats: dict, window: float) -> dict:
    """Группа «log_src»: неудачные попытки входа из лога sshd по IP-источнику."""
    events: defaultdict = defaultdict(list)
    for key, flow in flow_stats.items():
        if flow["proto"] == "LOG":
            events[flow["src"]].append((flow["start_time"], key, 0, 1, key))

    groups = {}
    for src, items in events.items():
        found = best_window(items, window)
        if found is None:
            continue
        groups[src] = {
            "src": src, "dst": None, "proto": "LOG", "window": window,
            "failed_attempts": found["unique"],
            "start_time": found["start_time"], "end_time": found["end_time"],
            "_flow_keys": found["flow_keys"],
        }
    return groups


def get_groups(flow_stats: dict, scope: str, window: float, cache: dict) -> dict:
    """Построить (или взять из кэша) группы потоков для заданного scope и окна."""
    cache_key = (scope, window)
    if cache_key not in cache:
        if scope == "flow":
            cache[cache_key] = build_flow_groups(flow_stats)
        elif scope == "src_dst":
            cache[cache_key] = build_src_dst_groups(flow_stats, window)
        elif scope == "dst_port":
            cache[cache_key] = build_dst_port_groups(flow_stats, window)
        elif scope == "log_src":
            cache[cache_key] = build_log_groups(flow_stats, window)
        else:
            raise ValueError(f"неизвестный scope сигнатуры: {scope}")
    return cache[cache_key]


# --- База сигнатур ---------------------------------------------------------
# name      – имя сигнатуры;            type     – тип атаки;
# scope     – по каким данным работает: flow | src_dst | dst_port | log_src;
# window    – окно анализа, секунд;     severity – LOW | MEDIUM | HIGH;
# condition – lambda, получает статистику группы и возвращает True при совпадении.

signatures = [
    {
        "name": "Port_Scan", "type": "scan", "scope": "src_dst", "window": 10, "severity": "MEDIUM",
        "description": "Более 10 уникальных портов назначения с одного IP на один IP за 10 секунд",
        "condition": lambda g: g["unique_syn_ports"] > 10 and g["half_open_ratio"] > 0.8,
    },
    {
        "name": "Port_Probe", "type": "scan", "scope": "src_dst", "window": 10, "severity": "LOW",
        "description": "От 5 до 10 уникальных портов назначения за 10 секунд (разведка)",
        "condition": lambda g: 5 <= g["unique_syn_ports"] <= 10 and g["half_open_ratio"] > 0.8,
    },
    {
        "name": "SYN_Flood", "type": "dos", "scope": "dst_port", "window": 5, "severity": "HIGH",
        "description": "Более 50 SYN-пакетов на один IP:порт за 5 секунд, почти без завершённых рукопожатий",
        "condition": lambda g: g["syn_packets"] > 50 and g["syn_ratio"] > 0.9,
    },
    {
        "name": "ICMP_Smurf", "type": "dos", "scope": "flow", "window": DEFAULT_WINDOW, "severity": "HIGH",
        "description": "Не менее 5 ICMP Echo Request на широковещательный адрес",
        "condition": lambda f: f["proto"] == "ICMP" and f["is_echo_request"]
        and f["dst_is_broadcast"] and f["packets"] >= 5,
    },
    {
        "name": "ICMP_Flood", "type": "dos", "scope": "flow", "window": DEFAULT_WINDOW, "severity": "MEDIUM",
        "description": "Более 100 ICMP Echo Request от одного источника с частотой выше 100 пакетов/с",
        "condition": lambda f: f["proto"] == "ICMP" and f["is_echo_request"]
        and f["packets"] > 100 and f["pps"] > 100,
    },
    {
        "name": "SSH_Brute_Force", "type": "bruteforce", "scope": "log_src", "window": 120, "severity": "HIGH",
        "description": "Более 5 неудачных попыток входа по SSH с одного IP за 2 минуты (лог sshd)",
        "condition": lambda g: g["failed_attempts"] > 5,
    },
]


# --- Импорт сигнатур из JSON (дополнительное задание) -----------------------

OPERATORS: dict[str, Callable[[Any, Any], bool]] = {
    ">": operator.gt, ">=": operator.ge, "<": operator.lt,
    "<=": operator.le, "==": operator.eq, "!=": operator.ne,
}
REQUIRED_SIGNATURE_KEYS = ("name", "severity", "conditions")


def build_condition(conditions: list[dict]) -> Callable[[dict], bool]:
    """Собрать из списка условий JSON одну функцию-предикат (все условия через И)."""
    checks = []
    for item in conditions:
        op = OPERATORS.get(item.get("op"))
        if op is None or "field" not in item or "value" not in item:
            raise ValueError(f"некорректное условие: {item}")
        checks.append((item["field"], op, item["value"]))

    def condition(stats: dict) -> bool:
        return all(op(stats[field], value) for field, op, value in checks)

    return condition


def load_signatures(path: str) -> list[dict]:
    """Загрузить базу сигнатур из JSON-файла вида {"signatures": [...]}.

    Выбрасывает ValueError при отсутствии обязательных полей или неверном severity.
    """
    with open(path, "r", encoding="utf-8") as file:
        data = json.load(file)

    loaded = []
    for item in data.get("signatures", []):
        missing = [key for key in REQUIRED_SIGNATURE_KEYS if key not in item]
        if missing:
            raise ValueError(f"в сигнатуре {item.get('name', '?')} нет полей: {', '.join(missing)}")
        if item["severity"] not in SEVERITY_LEVELS:
            raise ValueError(f"сигнатура {item['name']}: severity должен быть LOW, MEDIUM или HIGH")
        loaded.append({
            "name": item["name"], "type": item.get("type", "custom"),
            "scope": item.get("scope", "flow"), "window": item.get("window", DEFAULT_WINDOW),
            "severity": item["severity"], "description": item.get("description", ""),
            "condition": build_condition(item["conditions"]),
        })
    return loaded


# --- Движок правил ---------------------------------------------------------

ALERTED: set = set()  # «память»: (имя сигнатуры, ключ группы) уже выданных алертов


def iso_time(timestamp: float) -> str:
    """Время в формате ISO 8601 (UTC) с миллисекундами."""
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(timespec="milliseconds")


def clean_value(value: Any) -> Any:
    """Привести значение к JSON-совместимому виду."""
    if isinstance(value, float):
        return round(value, 4)
    if isinstance(value, (set, tuple)):
        return sorted(value)
    return value


def build_alert(signature: dict, stats: dict) -> dict:
    """Сформировать словарь алерта {timestamp, src_ip, dst_ip, signature_name, severity, details}."""
    scope = signature.get("scope", "flow")
    src_ip = stats.get("src")
    if scope == "dst_port":
        sources = stats["sources"]
        src_ip = sources[0] if len(sources) == 1 else "multiple"

    details = {field: clean_value(stats[field]) for field in DETAIL_FIELDS[scope] if field in stats}
    details["description"] = signature.get("description", "")
    details["type"] = signature.get("type", "custom")
    if scope == "dst_port":
        details["sources_sample"] = stats["sources"][:5]
    return {
        "timestamp": iso_time(stats["end_time"]),
        "src_ip": src_ip,
        "dst_ip": stats.get("dst"),
        "signature_name": signature["name"],
        "severity": signature["severity"],
        "details": details,
    }


def detect_signatures(flow_stats: dict, signatures: list[dict], alerted: Optional[set] = None,
                      return_matches: bool = False):
    """Применить сигнатуры к статистике потоков и вернуть список новых алертов.

    Для уже выданных алертов (пара «сигнатура + ключ группы») повторное оповещение
    не формируется. Если return_matches=True, дополнительно возвращается список
    списков ключей потоков, вызвавших каждый алерт (используется при оценке качества).
    """
    memory = ALERTED if alerted is None else alerted
    cache: dict = {}
    alerts: list[dict] = []
    matches: list[list] = []

    for signature in signatures:
        groups = get_groups(flow_stats, signature.get("scope", "flow"),
                            signature.get("window", DEFAULT_WINDOW), cache)
        for key, stats in groups.items():
            memory_key = (signature["name"], key)
            if memory_key in memory:
                continue
            try:
                matched = signature["condition"](stats)
            except (KeyError, TypeError, ZeroDivisionError):
                matched = False  # условие неприменимо к этому типу записей
            if not matched:
                continue
            memory.add(memory_key)
            alerts.append(build_alert(signature, stats))
            matches.append(stats["_flow_keys"])

    alerts_order = sorted(range(len(alerts)), key=lambda i: (-SEVERITY_LEVELS[alerts[i]["severity"]],
                                                              alerts[i]["timestamp"]))
    alerts = [alerts[i] for i in alerts_order]
    matches = [matches[i] for i in alerts_order]
    return (alerts, matches) if return_matches else alerts


# --- Вывод и логирование алертов -------------------------------------------

def enable_colors() -> None:
    """Включить обработку ANSI-кодов в консоли Windows (на других системах ничего не делает)."""
    try:
        import colorama
        colorama.just_fix_windows_console()
    except ImportError:
        if os.name == "nt":
            os.system("")  # включает режим ANSI в современных консолях Windows


def filter_by_severity(alerts: list[dict], minimum: str) -> list[dict]:
    """Оставить алерты с уровнем не ниже `minimum` (MEDIUM → HIGH и MEDIUM)."""
    level = SEVERITY_LEVELS[minimum]
    return [a for a in alerts if SEVERITY_LEVELS[a["severity"]] >= level]


def format_alert(alert: dict, use_color: bool = True) -> str:
    """Строка алерта для консоли; цвет зависит от серьёзности."""
    details = alert["details"]
    skip = {"description", "type", "sources_sample", "window"}
    metrics = ", ".join(f"{k}={v}" for k, v in details.items() if k not in skip)
    line = (f"[{alert['severity']}] {alert['timestamp']} {alert['signature_name']}: "
            f"{alert['src_ip']} -> {alert['dst_ip'] or '-'} | {metrics}")
    if use_color:
        return f"{SEVERITY_COLORS[alert['severity']]}{line}{COLOR_RESET}"
    return line


def write_alerts(alerts: list[dict], path: str) -> None:
    """Дописать алерты в файл в формате JSON Lines (одна строка — один JSON-объект)."""
    with open(path, "a", encoding="utf-8") as file:
        for alert in alerts:
            file.write(json.dumps(alert, ensure_ascii=False) + "\n")


def ips_dry_run(alert: dict) -> Optional[str]:
    """Команда iptables, которую выполнила бы IPS (только текст, ничего не запускается)."""
    if alert["severity"] != "HIGH" or alert["src_ip"] in (None, "multiple"):
        return None
    return f"iptables -A INPUT -s {alert['src_ip']} -j DROP"


def handle_alerts(alerts: list[dict], args: argparse.Namespace) -> None:
    """Записать все алерты в лог и вывести в консоль те, что проходят фильтр severity."""
    if not alerts:
        return
    write_alerts(alerts, args.log)
    for alert in filter_by_severity(alerts, args.threshold_severity):
        print(format_alert(alert, use_color=not args.no_color))
        command = ips_dry_run(alert) if args.ips_dry_run else None
        if command:
            print(f"    [IPS dry-run] {command}")


def print_summary(total: Counter, shown: int, args: argparse.Namespace) -> None:
    """Итоговая строка: число алертов по уровням."""
    parts = ", ".join(f"{level}: {total.get(level, 0)}" for level in ("HIGH", "MEDIUM", "LOW"))
    print(f"\nВсего алертов: {sum(total.values())} ({parts}); "
          f"выведено по порогу {args.threshold_severity}: {shown}; журнал: {args.log}")


# --- Перехват и запуск -----------------------------------------------------

def resolve_interface(query: str):
    """Найти интерфейс по индексу, точному имени или части имени/описания."""
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


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    """Разобрать аргументы командной строки."""
    parser = argparse.ArgumentParser(description="Сигнатурный IDS (ЛР3).")
    parser.add_argument("--iface", help="интерфейс для перехвата трафика")
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT,
                        help=f"сколько пакетов перехватить (по умолчанию {DEFAULT_COUNT})")
    parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL,
                        help=f"проверять сигнатуры каждые N пакетов (по умолчанию {DEFAULT_INTERVAL})")
    parser.add_argument("--ssh-log", help="лог sshd для сигнатуры SSH_Brute_Force (интеграция с ЛР1)")
    parser.add_argument("--signatures", help="JSON-файл с базой сигнатур вместо встроенной")
    parser.add_argument("--list-signatures", action="store_true", help="показать базу сигнатур и выйти")
    parser.add_argument("--log", default=DEFAULT_LOG, help=f"файл алертов JSON Lines (по умолчанию {DEFAULT_LOG})")
    parser.add_argument("--threshold-severity", choices=list(SEVERITY_LEVELS), default="LOW",
                        type=str.upper, help="минимальный уровень алертов для вывода в консоль")
    parser.add_argument("--no-color", action="store_true", help="отключить цветовую маркировку")
    parser.add_argument("--ips-dry-run", action="store_true",
                        help="для HIGH-алертов показать команду iptables (без выполнения)")
    return parser.parse_args(argv)


def print_signatures(signature_list: list[dict]) -> None:
    """Вывести базу сигнатур в виде таблицы."""
    print(f"{'Сигнатура':<17}{'Тип':<12}{'Severity':<10}{'Окно, с':>8}  Условие")
    print("-" * 110)
    for sig in signature_list:
        print(f"{sig['name']:<17}{sig['type']:<12}{sig['severity']:<10}{sig['window']:>8}  {sig['description']}")


def run_live(args: argparse.Namespace, signature_list: list[dict], flow_stats: dict, total: Counter) -> int:
    """Перехват трафика с периодической проверкой сигнатур. Возвращает число показанных алертов."""
    shown = 0
    counter = [0]

    def check() -> None:
        nonlocal shown
        alerts = detect_signatures(flow_stats, signature_list)
        total.update(a["severity"] for a in alerts)
        shown += len(filter_by_severity(alerts, args.threshold_severity))
        handle_alerts(alerts, args)

    def callback(packet) -> None:
        packet_handler(packet, flow_stats)
        counter[0] += 1
        if counter[0] % args.interval == 0:
            check()

    iface = resolve_interface(args.iface)
    sniff(iface=iface, prn=callback, count=args.count, store=False)
    check()
    return shown


def main(argv: Optional[list[str]] = None) -> int:
    """Запустить IDS. Код возврата: 0 — успех, 1 — ошибка."""
    args = parse_args(argv)
    if not args.no_color:
        enable_colors()

    try:
        signature_list = load_signatures(args.signatures) if args.signatures else signatures
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"[ERROR] Не удалось загрузить сигнатуры: {error}", file=sys.stderr)
        return 1

    if args.list_signatures:
        print_signatures(signature_list)
        return 0
    if not args.iface and not args.ssh_log:
        print("[ERROR] Укажите --iface для перехвата трафика и/или --ssh-log для анализа лога.", file=sys.stderr)
        return 1

    flow_stats: dict = {}
    total: Counter = Counter()
    shown = 0
    try:
        if args.ssh_log:
            added = load_ssh_log(args.ssh_log, flow_stats)
            print(f"Из лога {args.ssh_log} загружено неудачных попыток входа: {added}")
            alerts = detect_signatures(flow_stats, signature_list)
            total.update(a["severity"] for a in alerts)
            shown += len(filter_by_severity(alerts, args.threshold_severity))
            handle_alerts(alerts, args)
        if args.iface:
            shown += run_live(args, signature_list, flow_stats, total)
    except (OSError, PermissionError, ValueError) as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        return 1

    print_summary(total, shown, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
