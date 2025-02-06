import time
from wolfssl import SSLContext, PROTOCOL_TLSv1_3, CERT_REQUIRED
import socket

class TLSHelper:
    def __init__(self, ca_cert_file, self_cert_file=None, key_file=None, is_server=False):
        self.context = SSLContext(PROTOCOL_TLSv1_3, server_side=is_server)
        self.context.verify_mode = CERT_REQUIRED
        if is_server:
            self.context.load_cert_chain(self_cert_file, key_file)
        self.context.load_verify_locations(ca_cert_file)
        self.is_server = is_server
        self.socket_ = None

    def connect(self, host, port):
        max_tries = 30
        delay = 1  # seconds between retries
        for attempt in range(max_tries):
            try:
                raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                if self.is_server:
                    raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    raw_socket.bind((host, port))
                    raw_socket.listen(1)
                    conn, addr = raw_socket.accept()
                    self.socket_ = self.context.wrap_socket(conn, server_side=True)
                else:
                    raw_socket.connect((host, port))
                    self.socket_ = self.context.wrap_socket(raw_socket, server_side=False, server_hostname=host)
                return
            except Exception as e:
                time.sleep(delay)
        raise ConnectionError("Failed to establish connection after multiple attempts")

    def send(self, message):
        if not self.socket_:
            raise ConnectionError("No active connection to send data")
        if isinstance(message, str):
            message = message.encode('utf-8')
        self.socket_.sendall(message)

    def receive(self, buffer_size=4096):
        if not self.socket_:
            raise ConnectionError("No active connection to receive data")
        data = self.socket_.recv(buffer_size)
        return data.decode('utf-8')

    def close(self):
        try:
            if self.socket_:
                self.socket_.shutdown(socket.SHUT_RDWR)
                self.socket_.close()
                self.socket_ = None
        except Exception as e:
            pass
