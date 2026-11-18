#!/usr/bin/env python3
"""Вспомогательный скрипт ЛР3: проверка IDS на pcap-файле из ЛР2.

Читает pcap через scapy.rdpcap, воспроизводит работу packet_handler из ЛР2 для каждого
пакета, собирает flow_stats и передаёт его в движок ids_lab3. Скрипты должны
лежать в одной папке.

Примеры запуска:
    python test_pcap.py lab2_test_traffic.pcap
    python test_pcap.py lab2_test_traffic.pcap --evaluate
    python test_pcap.py lab2_test_traffic.pcap --signatures signatures_loose.json --evaluate
    python test_pcap.py lab2_test_traffic.pcap --repeat 2 --threshold-severity MEDIUM
"""

import argparse
import json
import sys
from collections import Counter
from ipaddress import ip_address, ip_network
from typing import Optional

from scapy.all import rdpcap

try:
    import ids_lab3 as ids
except ImportError:
    sys.exit("[ERROR] Не найден ids_lab3.py: положите оба скрипта в одну папку.")

# Эталонная разметка для lab2_test_traffic.pcap (известна из анализа в ЛР2).
ATTACK_SCANNER = "203.0.113.100"
ATTACK_FLOOD_NET = ip_network("10.0.0.0/24")


def replay_pcap(path: str) -> dict:
    """Прочитать pcap и собрать flow_stats, вызывая packet_handler для каждого пакета."""
    flow_stats: dict = {}
    for packet in rdpcap(path):
        ids.packet_handler(packet, flow_stats)
    return flow_stats


def is_attack_flow(flow: dict) -> bool:
    """Эталон: поток относится к атаке (сканер, источники SYN-флуда, ICMP на broadcast)."""
    if flow["proto"] == "LOG":
        return False
    return (flow["src"] == ATTACK_SCANNER
            or ip_address(flow["src"]) in ATTACK_FLOOD_NET
            or ids.is_broadcast(flow["dst"]))


def evaluate(flow_stats: dict, matches: list[list]) -> dict:
    """Сравнить найденные потоки с эталоном и вернуть матрицу ошибок TP/TN/FP/FN."""
    detected = {key for keys in matches for key in keys}
    result = Counter()
    for key, flow in flow_stats.items():
        if flow["proto"] == "LOG":
            continue
        actual, found = is_attack_flow(flow), key in detected
        result["TP" if actual and found else "FN" if actual else "FP" if found else "TN"] += 1
    return result


def print_evaluation(result: Counter) -> None:
    """Вывести матрицу ошибок и метрики качества."""
    tp, tn, fp, fn = (result[k] for k in ("TP", "TN", "FP", "FN"))
    total = tp + tn + fp + fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    print("\nОЦЕНКА КАЧЕСТВА (по потокам)")
    print(f"  TP (атака найдена):        {tp}")
    print(f"  TN (атаки нет, тишина):    {tn}")
    print(f"  FP (ложная тревога):       {fp}")
    print(f"  FN (атака пропущена):      {fn}")
    print(f"  Точность (precision):      {precision:.2%}")
    print(f"  Полнота (recall):          {recall:.2%}")
    print(f"  Доля верных (accuracy):    {(tp + tn) / total:.2%}")


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    """Разобрать аргументы командной строки."""
    parser = argparse.ArgumentParser(description="Проверка IDS на pcap-файле.")
    parser.add_argument("pcap", help="путь к pcap-файлу")
    parser.add_argument("--signatures", help="JSON-файл с базой сигнатур")
    parser.add_argument("--ssh-log", help="лог sshd для сигнатуры SSH_Brute_Force")
    parser.add_argument("--log", default=ids.DEFAULT_LOG, help="файл алертов JSON Lines")
    parser.add_argument("--threshold-severity", choices=list(ids.SEVERITY_LEVELS), default="LOW",
                        type=str.upper, help="минимальный уровень алертов для вывода")
    parser.add_argument("--repeat", type=int, default=1, help="сколько раз запустить проверку (проверка памяти алертов)")
    parser.add_argument("--evaluate", action="store_true", help="оценить TP/TN/FP/FN по эталонной разметке")
    parser.add_argument("--no-color", action="store_true", help="отключить цветовую маркировку")
    parser.add_argument("--ips-dry-run", action="store_true", help="показать команды iptables для HIGH-алертов")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    """Запустить проверку. Код возврата: 0 — успех, 1 — ошибка."""
    args = parse_args(argv)
    if not args.no_color:
        ids.enable_colors()

    try:
        signature_list = ids.load_signatures(args.signatures) if args.signatures else ids.signatures
        flow_stats = replay_pcap(args.pcap)
        if args.ssh_log:
            added = ids.load_ssh_log(args.ssh_log, flow_stats)
            print(f"Из лога {args.ssh_log} загружено неудачных попыток входа: {added}")
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        return 1

    packets = sum(f["packets"] for f in flow_stats.values() if f["proto"] != "LOG")
    flows = sum(1 for f in flow_stats.values() if f["proto"] != "LOG")
    print(f"Файл {args.pcap}: пакетов {packets}, потоков {flows}, сигнатур {len(signature_list)}")

    memory: set = set()
    total: Counter = Counter()
    shown = 0
    all_matches: list[list] = []
    for number in range(1, args.repeat + 1):
        alerts, matches = ids.detect_signatures(flow_stats, signature_list, memory, return_matches=True)
        if args.repeat > 1:
            print(f"\n--- Проход {number}: новых алертов {len(alerts)} ---")
        total.update(a["severity"] for a in alerts)
        shown += len(ids.filter_by_severity(alerts, args.threshold_severity))
        all_matches.extend(matches)
        ids.handle_alerts(alerts, args)

    ids.print_summary(total, shown, args)
    if args.evaluate:
        print_evaluation(evaluate(flow_stats, all_matches))
    return 0


if __name__ == "__main__":
    sys.exit(main())
