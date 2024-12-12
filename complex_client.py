from TLS_helper import TLSHelper
from display_helper import pretty_print
from tools import generate_request


class ComplexClient:
    def __init__(self, ca_cert_file):
        self.connection_with_personal_tee = TLSHelper(ca_cert_file, is_server=False)
        pretty_print("CLIENT", "Initialized")
        
    def start(self, personal_tee_host, personal_tee_port):
        self.connection_with_personal_tee.connect(personal_tee_host, personal_tee_port)
        response = self.send_query()
    
    def send_query(self):
        request = generate_request(["verb", "route", "username", "password", "params"], ["GET", "get_height", "ben", "password", []])
        pretty_print("CLIENT", "Sending query", request)
        self.connection_with_personal_tee.send(request)
        response = self.connection_with_personal_tee.receive()
        return response