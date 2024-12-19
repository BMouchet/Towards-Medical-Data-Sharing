import base64
import json

from bson import ObjectId
from TLS_helper import TLSHelper
from display_helper import pretty_print
from tools import from_json_to_bytes, generate_request, prepare_bytes_for_json


class ComplexClient:
    def __init__(self, ca_cert_file):
        self.connection_with_personal_tee = TLSHelper(ca_cert_file, is_server=False)
        pretty_print("CLIENT", "Initialized")
        
    def start(self, personal_tee_host, personal_tee_port):
        self.connection_with_personal_tee.connect(personal_tee_host, personal_tee_port)
        response = self.send_query()
        pretty_print("CLIENT", f"Request was successful {response}")
        response = json.loads(response)["response"]
        response = base64.b64decode(response).decode()
        pretty_print("CLIENT", f"Request was successful {response}")
        self.stop()
        return
    
    def send_query(self):
        # request = generate_request(["verb", "route", "username", "password", "params"], ["GET", "is_heavier_than", "doctor1", "password", {"patient": "patient1"}])
        request = generate_request(["verb", "route", "username", "password", "params"], ["GET", "get_height", "external1", "password", {"patient_id": str(ObjectId('111111111111111111111111'))}])
        pretty_print("CLIENT", "Sending query", request)
        self.connection_with_personal_tee.send(request)
        response = self.connection_with_personal_tee.receive()
        pretty_print("CLIENT", f"Received response {response}")
        return response
    
    def stop(self):
        response = generate_request(["close"], ["close"])
        self.connection_with_personal_tee.send(response)
        try:
            self.connection_with_personal_tee.close() 
        except:
            print("Connections already closed")
        finally:
            return
        