from wolfssl import SSLContext, PROTOCOL_TLSv1_3, CERT_REQUIRED
import socket

class TLSHelper:
    def __init__(self, ca_cert_file, self_cert_file, key_file, is_server=False):
        self.context = SSLContext(PROTOCOL_TLSv1_3, server_side=is_server)
        self.context.verify_mode = CERT_REQUIRED
        self.context.load_cert_chain(self_cert_file, key_file)
        self.context.load_verify_locations(ca_cert_file)
        self.is_server = is_server
        self.socket_ = None

    def connect(self, host, port):
        socket_ = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        if self.is_server:
            socket_.bind((host, port))
            socket_.listen(5)
            socket_, address_ = socket_.accept()
            socket_ = self.context.wrap_socket(socket_, server_side=True)
        else:
            socket_.connect((host, port))
            socket_ = self.context.wrap_socket(socket_, server_side=False, server_hostname=host)
        
        self.socket_ = socket_  
    
    def send(self, message):
        self.socket_.sendall(message)
    
    def receive(self, buffer_size=4096):
        return self.socket_.recv(buffer_size).decode()
    
    def close(self):
        self.socket_.close()
