#!/usr/bin/env python3
"""Генератор тестового трафика для лабораторной №2: пустые UDP-пакеты в цикле.

Пример запуска:
    python udp_sender_StudentID.py --host 127.0.0.1 --port 9999 --count 1000
"""

import argparse
import socket
import time


def send_udp(host: str, port: int, count: int, delay: float = 0.0) -> int:
    """Отправить `count` пустых UDP-датаграмм и вернуть число отправленных.

    `delay` — пауза между пакетами в секундах (0 — максимальная скорость).
    """
    sent = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for _ in range(count):
            sock.sendto(b"", (host, port))
            sent += 1
            if delay:
                time.sleep(delay)
    return sent


def main() -> None:
    parser = argparse.ArgumentParser(description="Отправка пустых UDP-пакетов в цикле.")
    parser.add_argument("--host", default="127.0.0.1", help="адрес получателя")
    parser.add_argument("--port", type=int, default=9999, help="порт получателя")
    parser.add_argument("--count", type=int, default=1000, help="число пакетов")
    parser.add_argument("--delay", type=float, default=0.0, help="пауза между пакетами, с")
    args = parser.parse_args()

    sent = send_udp(args.host, args.port, args.count, args.delay)
    print(f"Отправлено {sent} пустых UDP-пакетов на {args.host}:{args.port}")


if __name__ == "__main__":
    main()
