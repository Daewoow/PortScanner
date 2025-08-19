import random
import socket
import ssl
import struct
import traceback


class Protocoller:
    @staticmethod
    def identify_protocol(ip, port, transport):
        if port == 53:
            return Protocoller.check_dns(ip, port)
        elif port == 80:
            return Protocoller.check_http(ip, port)
        elif port == 443:
            return Protocoller.check_https(ip, port)
        elif transport == "udp":
            return Protocoller.check_echo(ip, port)
        return None

    @staticmethod
    def check_http(ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            http_request = b"GET / HTTP/1.1\r\nHost: target\r\n\r\n"
            sock.sendall(http_request)
            response = sock.recv(1024)
            if response.startswith(b"HTTP/"):
                return "HTTP"
        except Exception:
            return None
        finally:
            sock.close()
        return None

    @staticmethod
    def check_https(ip, port):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((ip, port), timeout=2) as raw_sock:
                with context.wrap_socket(raw_sock, server_hostname=ip) as tls_sock:
                    http_request = b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n"
                    tls_sock.sendall(http_request)
                    response = tls_sock.recv(1024)

                    if response.startswith(b"HTTP/"):
                        return "HTTPS"
        except TimeoutError:
            return "HTTPS"
        except Exception as e:
            print(traceback.format_exception(e))
        return None

    @staticmethod
    def check_dns(ip, port):
        query_id = random.randint(0, 65535)
        query = struct.pack(
            "!HHHHHH", query_id, 256, 1, 0, 0, 0
        ) + b'\x07example\x03com\x00\x00\x01\x00\x01'
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(query, (ip, port))
            response = sock.recvfrom(512)
            if response:
                return "DNS"
        except socket.timeout:
            return None
        finally:
            sock.close()
        return None

    @staticmethod
    def check_echo(ip, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2)
                sock.connect((ip, port))
                test_data = b"ECHO"
                sock.sendall(test_data)
                response = sock.recv(1024)
                if response == test_data:
                    return "ECHO"
        except Exception:
            return None
        return None
