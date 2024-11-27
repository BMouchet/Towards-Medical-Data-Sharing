from TLS_helper import TLSHelper
from pymongo import MongoClient
import json
from display_helper import pretty_print

class Database:
    def __init__(self, ca_cert_file, self_cert_file, key_file):
        self.secure_connection = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=True)
        self.client = MongoClient('localhost', 27017)
        self.db = self.client['mydb']
        self.collection = self.db['mycollection']
        self.tee_public_key = None
    
    def listen(self, host, port):
        self.secure_connection.connect(host, port)
        request = self.secure_connection.receive()
        pretty_print("DATABASE", "Received request", request)
        signed_request = self.validate_request(request)
        pretty_print("DATABASE", "Validated request", signed_request)
        db_response = self.query_db(signed_request)
        db_response = {"response": db_response}
        db_response = json.dumps(db_response).encode('utf-8')
        pretty_print("DATABASE", "Sending response", db_response)
        self.secure_connection.send(db_response)

    def validate_request(self, request):
        return request
    
    def query_db(self, request):
        return self.collection.count_documents({})
    
    def close_connection(self):
        self.secure_connection.close()