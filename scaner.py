import random
import socket
import struct
import time
import selectors
from protocoller import Protocoller
from helpfulUsages import Utils


class Scaner:
    def __init__(self, arguments) -> None:
        random_id = random.randint(0, 10000)
        self.UDP_Ports = {
            'HTTP': b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n',
            'DNS': struct.pack("!HHHHHH", random_id, 256, 1, 0, 0, 0),
            'ECHO': b"ping"
        }
        self.protocols = {
            443: "HTTPS",
            80: "HTTP",
            53: "DNS",
            7: "ECHO"
        }
        self.ip = arguments.target
        self.ports = arguments.ports
        self.timeout = arguments.timeout
        self.verbose = arguments.verbose
        self.guess = arguments.guess
        self.sorted_ports = Utils.parse_ports(self.ports)
        self.selector = selectors.DefaultSelector()
        self.tcp_ports = {}
        self.udp_ports = {}

    def scan_ports(self):
        if self.guess and not self.verbose:
            print(f"{'Protocol':<10}{'Port':<6}{'Protocol'}")
        elif self.verbose and not self.guess:
            print(f"{'Protocol':<10}{'Port':<6}{'Response Time':<15}{'Start Time':<25}{'End Time':<25}")
        elif self.verbose and self.guess:
            print(f"{'Protocol':<10}{'Port':<6}{'Response Time':<15}{'Start Time':<25}{'End Time':<25}{'Protocol'}")
        else:
            print(f"{'Protocol':<10}{'Port':<6}")
        self.scan_tcp()
        self.scan_udp()

    def scan_tcp(self):
        for tcp_port in self.sorted_ports["tcp"]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setblocking(False)
                sock.connect_ex((self.ip, tcp_port))
                self.selector.register(sock, selectors.EVENT_WRITE, self.handle_tcp)
                self.tcp_ports[sock] = tcp_port
            except Exception as e:
                if self.verbose:
                    print(f"Error creating socket for port {tcp_port}: {e}")

        while self.selector.get_map():
            events = self.selector.select(timeout=self.timeout)
            for key, _ in events:
                callback = key.data
                callback(key.fileobj)

    def handle_tcp(self, sock):
        tcp_port = self.tcp_ports[sock]
        start_time = time.time()
        try:
            error = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if error == 0:
                protocol = self.tcp_ports.get(tcp_port, "UNKNOWN")
                if self.guess and protocol == "UNKNOWN":
                    guessed_protocol = Protocoller.identify_protocol(self.ip, tcp_port, "tcp")
                    if guessed_protocol:
                        protocol = guessed_protocol
                    src_ip = socket.gethostbyname(socket.gethostname())
                    src_port = random.randint(1024, 65535)
                    syn_packet = Utils.create_syn_packet(src_ip, self.ip, src_port, tcp_port)
                    Utils.send_packet(self.ip, syn_packet)
                response_time = time.time() - start_time
                if self.verbose:
                    print(
                        f"TCP        {tcp_port:<6}{str(round(response_time, 3) * 1000) + 'ms':<15}"
                        f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()):<25}"
                        f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()):<25}"
                        f"{protocol if self.guess else ''}")
                else:
                    print(f"TCP        {tcp_port:<6}{protocol if self.guess else ''}")
        except Exception as e:
            if self.verbose:
                print(f"Ошибка на порту {tcp_port}: {e}")
        finally:
            self.selector.unregister(sock)
            sock.close()

    def scan_udp(self):
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        raw_socket.setblocking(False)
        self.selector.register(raw_socket, selectors.EVENT_READ, self.handle_icmp)

        for udp_port in self.sorted_ports["udp"]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                request = self.UDP_Ports.get("HTTP", b"PING")
                sock.sendto(request, (self.ip, udp_port))

                self.selector.register(sock, selectors.EVENT_READ, self.handle_udp)
                self.udp_ports[sock] = udp_port
            except Exception as e:
                if self.verbose:
                    print(f"Возникла ошибка при создании сокета {udp_port}: {e}")

        start_time = time.time()
        while self.selector.get_map():
            events = self.selector.select(timeout=self.timeout)

            if not events:
                if time.time() - start_time > self.timeout:
                    for key in list(self.selector.get_map().values()):
                        self.selector.unregister(key.fileobj)
                        key.fileobj.close()
                    break

            for key, _ in events:
                callback = key.data
                callback(key.fileobj)

    def handle_udp(self, sock):
        udp_port = self.udp_ports[sock]
        start_time = time.time()
        try:
            data, _ = sock.recvfrom(1024)
            protocol = self.protocols.get(udp_port, "UNKNOWN")
            guessed_protocol = Protocoller.identify_protocol(self.ip, udp_port, "udp")
            if guessed_protocol:
                protocol = guessed_protocol

            if self.guess and protocol == "UNKNOWN":
                if b"NTP" in data:
                    protocol = "NTP"

            response_time = time.time() - start_time

            if self.verbose:
                print(
                    f"UDP        {udp_port:<6}{str(round(response_time, 3) * 1000) + 'ms':<15}"
                    f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()):<25}"
                    f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime()):<25}"
                    f"{protocol if self.guess else ''}")
            else:
                print(f"UDP        {udp_port:<6}{protocol if self.guess else ''}")
        except Exception as e:
            if self.verbose:
                print(f"Ошибка на порту {udp_port}: {e}")
        finally:
            self.selector.unregister(sock)
            sock.close()

    def handle_icmp(self, raw_socket):
        try:
            data, addr = raw_socket.recvfrom(1024)
            icmp_type, icmp_code = Utils.parse_icmp(data)
            if icmp_type == 3:
                udp_port = struct.unpack('!H', data[50:52])[0]
                if icmp_code == 3:
                    return False
            return True
        except Exception as e:
            if self.verbose:
                print(f"Ошибка при обработке ICMP: {e}")
            return False
