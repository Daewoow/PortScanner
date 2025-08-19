import struct
import socket


class Utils:
    @staticmethod
    def parse_ports(ports) -> dict:
        sorted_ports = {
            "udp": set(),
            "tcp": set()
        }
        for port in ports:
            protocol = port[:3]
            if '/' not in port:
                sorted_ports[protocol].update(range(1, 65536))
            else:
                for p in port[4:].split(','):
                    if "-" in p:
                        start, end = map(int, p.split("-"))
                        sorted_ports[protocol].update(range(start, end + 1))
                    else:
                        sorted_ports[protocol].add(int(p))
        return sorted_ports

    @staticmethod
    def parse_icmp(data):
        icmp_header = data[20:28]
        icmp_type, icmp_code, _, _ = struct.unpack('!BBHI', icmp_header)
        return icmp_type, icmp_code

    @staticmethod
    def calculate_checksum(data):
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + (data[i + 1] if i + 1 < len(data) else 0)
            checksum += word
            while checksum > 0xFFFF:
                checksum = (checksum & 0xFFFF) + (checksum >> 16)
        return ~checksum & 0xFFFF

    @staticmethod
    def parse_ip_header(header):
        iph = struct.unpack('!BBHHHBBH4s4s', header)
        src_ip = socket.inet_ntoa(iph[8])
        dst_ip = socket.inet_ntoa(iph[9])
        proto = iph[6]
        return src_ip, dst_ip, proto

    @staticmethod
    def parse_tcp_header(header):
        tcph = struct.unpack('!HHLLBBHHH', header)
        src_port = tcph[0]
        dst_port = tcph[1]
        seq = tcph[2]
        ack_seq = tcph[3]
        flags = tcph[5]
        return src_port, dst_port, seq, ack_seq, flags

    @staticmethod
    def create_syn_packet(src_ip, dest_ip, src_port, dest_port):
        ip_header = Utils.build_ip_header(src_ip, dest_ip)
        tcp_header = Utils.build_tcp_header(src_ip, dest_ip, src_port, dest_port, syn=True)
        return ip_header + tcp_header

    @staticmethod
    def build_ip_header(src_ip, dest_ip):
        version_ihl = (4 << 4) | 5
        type_of_service = 0
        total_length = 40
        packet_id = 54321
        fragment_offset = 0
        ttl = 64
        protocol = socket.IPPROTO_TCP
        checksum = 0
        src_ip = socket.inet_aton(src_ip)
        dest_ip = socket.inet_aton(dest_ip)

        ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, type_of_service, total_length,
                                packet_id, fragment_offset, ttl, protocol, checksum, src_ip, dest_ip)
        return ip_header

    @staticmethod
    def build_tcp_header(src_ip, dest_ip, src_port, dest_port, syn=False, ack=False, rst=False):
        seq_number = 0
        ack_number = 0
        data_offset = (5 << 4)
        flags = 0
        if syn:
            flags |= 0x02
        if ack:
            flags |= 0x10
        if rst:
            flags |= 0x04
        window = 8192
        checksum = 0
        urgent_pointer = 0

        tcp_header = struct.pack('!HHLLBBHHH', src_port, dest_port, seq_number, ack_number,
                                 data_offset, flags, window, checksum, urgent_pointer)

        protocol = socket.IPPROTO_TCP
        reserved = 0
        src_ip = socket.inet_aton(src_ip)
        dest_ip = socket.inet_aton(dest_ip)

        pseudo_header = struct.pack('!4s4sBBH', src_ip, dest_ip, reserved, protocol, len(tcp_header))
        checksum = Utils.calculate_checksum(pseudo_header + tcp_header)

        tcp_header = struct.pack('!HHLLBBH', src_port, dest_port, seq_number, ack_number,
                                 data_offset, flags, window) + struct.pack('H', checksum) + struct.pack('!H',
                                                                                                        urgent_pointer)

        return tcp_header

    @staticmethod
    def send_packet(dst_ip, packet):
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s:
            s.sendto(packet, (dst_ip, 0))
