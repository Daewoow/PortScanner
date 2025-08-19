import argparse
import time
import elevate
from scaner import Scaner

elevate.elevate()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="Port Scanner")
    parser.add_argument("target", help="IP адрес")
    parser.add_argument("ports", nargs="+", help="Порты для сканирования")
    parser.add_argument("--timeout", type=float, default=2,
                        help="Таймаут ожидания ответа (по умолчанию: 2)", dest="timeout")
    parser.add_argument("-v", "--verbose", action="store_true", help="Выводить ли колонку [TIME, ms]",
                        dest="verbose")
    parser.add_argument("-g", "--guess", action="store_true", help="Определять ли протокол", dest="guess")
    args = parser.parse_args()
    scanner = Scaner(args)
    scanner.scan_ports()
    print("Конец сканирования")
    input("Нажмите Enter для выхода")
