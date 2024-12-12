import inspect
import json
from TLS_helper import TLSHelper
from tools import generate_request, prepare_bytes_for_json, from_json_to_bytes
from display_helper import pretty_print
from nacl.signing import SigningKey
from nacl.hash import sha256

class TEE_DB_Proxy:
    def __init__(self, ca_cert_file, self_cert_file, key_file):
        self.connection_with_client = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=True)
        self.connection_with_verifier = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=False)
        self.listening = False
        self.private_signing_key = SigningKey.generate()
        self.public_signing_key = self.private_signing_key.verify_key
        pretty_print("TEE DB PROXY", "Initialized")
        self.methods = {}
        
    def get_public_key(self):
        return self.public_signing_key
    
    def start(self, tee_host, tee_port, verifier_host, verifier_port):
        self.connection_with_client.connect(tee_host, tee_port)
        if verifier_host and verifier_port:
            self.connection_with_verifier.connect(verifier_host, verifier_port)
            pretty_print("TEE DB PROXY", "Connected to verifier")
        self.listening = True
        
        while self.listening:
            request = self.connection_with_client.receive()
            self.dispatch_request(request)        
        
    def dispatch_request(self, request):
        request_json = json.loads(request)
        pretty_print("TEE DB PROXY", "Received request", request_json)
        try:
            if request_json['verb'] == 'GET' and request_json['route'] == 'evidence':
                nonce = request_json['nonce']
                evidence = prepare_bytes_for_json(self.generate_evidence(request_json['nonce']))
                self.send_evidence(evidence, nonce)
            elif request_json['verb'] == 'GET' and request_json['route'] in self.methods or True:
                if request_json['route']:
                    self.start_attestation_protocol()
                response = self.execute_query(request_json)
                self.send_response(response)
        except:
            if 'error' in request_json or 'close' in request_json:
                pretty_print("TEE DB PROXY", "Received close request")
                self.listening = False
                self.connection_with_client.close()
            
    def generate_evidence(self, nonce):
        source_code = inspect.getsource(TEE_DB_Proxy)
        evidence_hash = sha256(source_code.encode('utf-8') + from_json_to_bytes(nonce))  
        evidence = self.private_signing_key.sign(evidence_hash)
        return evidence      
    
    def send_evidence(self, evidence, nonce):
        response = generate_request(["evidence", "nonce"], [evidence, nonce])
        self.connection_with_client.send(response)
        
    def execute_query(self, query):
        pretty_print("TEE DB PROXY", "Executing query", query)
        response = generate_request(["response"], ["response"])
        return response
    
    def send_response(self, response):
        pretty_print("TEE DB PROXY", "Sending response", response)
        self.connection_with_client.send(response)
        
    def start_attestation_protocol(self):
        pretty_print("TEE DB PROXY", "Starting attestation protocol")
        nonce = self.request_nonce()
        pretty_print("TEE DB PROXY", "Received nonce", nonce)
        evidence = self.request_evidence(nonce)
        pretty_print("TEE DB PROXY", "Received evidence", evidence)
        self.send_evidence_to_verifier(evidence)
        
        
    def request_nonce(self):
        pretty_print("TEE DB PROXY", "Requesting nonce")
        request = generate_request(["verb", "route"], ["GET", "nonce"])
        pretty_print("TEE DB PROXY", "Sending request", request)
        self.connection_with_verifier.send(request)
        nonce = self.connection_with_verifier.receive()
        return nonce
    
    def request_evidence(self, nonce):
        nonce = json.loads(nonce)['nonce']
        request = generate_request(["verb", "route", "nonce"], ["GET", "evidence", nonce])
        self.connection_with_client.send(request)
        evidence = self.connection_with_client.receive()
        return evidence
    
    def send_evidence_to_verifier(self, evidence):
        data = json.loads(evidence)
        evidence = data['evidence']
        nonce = data['nonce']
        request = generate_request(["verb", "route", "evidence", "nonce"], ["GET", "attestation", evidence, nonce])
        self.connection_with_verifier.send(request)
        attestation = self.connection_with_verifier.receive()   
        pretty_print("TEE DB Proxy", "Received attestation", attestation)
        return attestation