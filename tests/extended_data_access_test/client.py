import base64
import json
import time
from TLS_helper import TLSHelper
from tools import generate_json_from_lists

class Client:
    def __init__(self, ca_cert_file):
        self.connection_with_peronal_tee = TLSHelper(ca_cert_file, is_server=False)
        self.personal_tee_public_key = None
        
    def set_personal_tee_public_key(self, personal_tee_public_key): 
        self.personal_tee_public_key = personal_tee_public_key
        
    def start(self, personal_tee_host, personal_tee_port, query):
        self.connection_with_peronal_tee.connect(personal_tee_host, personal_tee_port)        
        start_time = time.time()        
        response = self.send_query(query)
        response = self.read_response(response)
        duration = time.time() - start_time
        self.stop()
        return response, duration
    
    def send_query(self, query):
        self.connection_with_peronal_tee.send(query)
        response = self.connection_with_peronal_tee.receive()
        return response
    
    def read_response(self, response):
        response = json.loads(response)["result"]
        response = base64.b64decode(response)
        response = self.personal_tee_public_key.verify(response)
        return response
        
    def stop(self):
        try:            
            close_request = generate_json_from_lists(["close"], ["close"])
            self.connection_with_peronal_tee.send(close_request)
            self.connection_with_peronal_tee.close()    
        except:
            pass