import socket
import threading
from wolfssl import SSLContext, PROTOCOL_TLSv1_3
from server_interface import ServerInterface
from wolfssl import CERT_REQUIRED
import wolfssl
class Server(ServerInterface):
    def __init__(self, host='127.0.0.1', port=12345):        
        self.host = host
        self.port = port
        self.context = SSLContext(PROTOCOL_TLSv1_3, server_side=True)
        self.context.load_cert_chain("certs/server-cert.pem", "certs/server-key.pem")
        self.context.load_verify_locations("certs/ca-cert.pem")
        self.context.verify_mode = CERT_REQUIRED
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        self.clients = []

    def start_server(self):
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        print(f"Server listening on {self.host}:{self.port}")
        while True:
            client_socket, client_adress = self.socket.accept()
            print(f"Connection accepted from {client_adress}")
            ssl_socket = self.context.wrap_socket(client_socket, server_side=True)
            client_thread = threading.Thread(target=self.handle_client, args=(ssl_socket, client_adress))
            client_thread.start()
            self.clients.append(client_thread)


    def stop_server(self):
        self.socket.close()
        for client in self.clients:
            client.join()
        print("Server connection closed")
    
    def handle_client(self, client_socket, client_address):
        print(f"Handling client {client_address}")

        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    print(f"Connection closed by {client_address}")
                    break
                message = data.decode()
                print(f"Received from {client_address}: {message}")
                
                response = f"Hello {client_address[0]}! Your message was received."
                client_socket.sendall(response.encode())
        except Exception as e:
            print(f"Error with client {client_address}: {e}")
        finally:
            client_socket.close()
            print(f"Connection with {client_address} closed")