import socket
from wolfssl import SSLContext, PROTOCOL_TLSv1_3
import wolfssl

class HelloWorldClient:
    def __init__(self, host='127.0.0.1', port=12345, name='Client'):
        self.host = host
        self.port = port
        self.name = name
        self.context = SSLContext(PROTOCOL_TLSv1_3)
        self.context.verify_mode = wolfssl.CERT_REQUIRED
        self.context.load_cert_chain("certs/client-cert.pem", "certs/client-key.pem")
        self.context.load_verify_locations("certs/ca-cert.pem")

    def start(self):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        
        ssl_socket = self.context.wrap_socket(client_socket, server_side=False, server_hostname=self.host)
        
        try:
            ssl_socket.connect((self.host, self.port))
            print(f"Connected to server at {self.host}:{self.port}")
            
            message = f"Hello, World! from {self.name}"
            ssl_socket.sendall(message.encode())
            print(f"Sent: {message}")
            
            response = ssl_socket.recv(1024)
            print(f"Received from server: {response.decode()}")

        except Exception as e:
            print(f"Error connecting to the server: {e}")
        finally:
            ssl_socket.close()
            print("Connection closed.")