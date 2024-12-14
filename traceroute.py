import socket

from scapy.layers.inet import IP, ICMP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.sendrecv import sr1
import time
from formater import Formater

from protocols import ProtocolType
from parser import Parser

class RouteTracer:
    def __init__(self, ip_address, timeout, port, max_hops, verbose, protocol_type):
        self.ip_address = ip_address
        self.timeout = timeout
        self.port = port
        self.max_hops = max_hops
        self.verbose = verbose
        self.protocol_type = protocol_type

    def run(self):
        if self.protocol_type == ProtocolType.TCP:
            protocol = TCP(dport=self.port)
        elif self.protocol_type == ProtocolType.UDP:
            protocol = UDP(dport=self.port)
        else:
            protocol = ICMP()

        for ttl in range(1, self.max_hops + 1):
            try:
                # IPv4
                if ":" not in self.ip_address:
                    packet = IP(dst=self.ip_address, ttl=ttl) / protocol
                # IPv6
                else:
                    packet = IPv6(dst=self.ip_address, hlim=ttl) / protocol
            except socket.gaierror:
                raise ValueError(f"Cannot resolve host {self.ip_address}")

            start_time = time.perf_counter()
            data = sr1(packet, verbose=0, timeout=self.timeout)
            finish_time = time.perf_counter()

            if not data:
                Formater.format_empty(ttl)
                continue

            received_addr = data.src
            Formater.format_without_number(ttl, received_addr, round((finish_time - start_time)*1000))
            if received_addr == self.ip_address:
                break


if __name__ == "__main__":
    RouteTracer(*Parser().parse()).run()
