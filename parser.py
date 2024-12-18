import argparse
from protocols import ProtocolType


class Parser:
    def __init__(self):
        self.parser = argparse.ArgumentParser(description="Traceroute")
        self.parser.add_argument("-t", "--timeout", type=int, default=2, help="таймаут ожидания ответа (по умолчанию 2 с)")
        self.parser.add_argument("-p", "--port", type=int, help="порт (для tcp или udp)")
        self.parser.add_argument("-n", "--num", type=int, default=30, help="максимальное количество запросов")
        self.parser.add_argument("-v", "--verbose", action='store_true', default=False,
                                 help="вывод номера автономной системы для каждого ip-адреса")
        self.parser.add_argument("IP_ADDRESS", help="ip адрес")
        self.parser.add_argument("protocol_type", type=ProtocolType, help="тип протокола (tcp, udp, icmp)")

    def parse(self):
        args = self.parser.parse_args()
        if args.protocol_type in [ProtocolType.TCP, ProtocolType.UDP]:
            if args.port is None:
                raise ValueError("Port must be specified for tcp and udp protocols")
            if args.port < 0 or args.port > 65535:
                raise ValueError("Port must be between 0 and 65535")
        if args.timeout < 0:
            raise ValueError("Timeout must be non-negative")
        if args.num is not None and args.num < 0:
            raise ValueError("Num must be non-negative")
        return args.IP_ADDRESS, args.timeout, args.port, args.num, args.verbose, args.protocol_type
