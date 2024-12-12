import base64
import inspect
import json
import time
from TLS_helper import TLSHelper
from display_helper import pretty_print
from nacl.signing import SigningKey
from nacl.hash import sha256

from tools import from_json_to_bytes, generate_request

class ClientTEE:
    def __init__(self, ca_cert_file, self_cert_file, key_file, db_tee_public_key, verifier_public_key):
        self.connection_with_verifier = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=False)
        self.connection_with_db_proxy = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=False)
        self.connection_with_client = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=True)
        self.verifier_public_key = verifier_public_key
        self.db_tee_public_key = db_tee_public_key
        self.private_signing_key = SigningKey.generate()
        self.public_signing_key = self.private_signing_key.verify_key
        self.listening = False
        self.methods = {"get_height": True}
        pretty_print("CLIENT TEE", "Initialized")
        
    def start(self, client_host, client_port, tee_host, tee_port, verifier_host, verifier_port):
        self.connection_with_client.connect(client_host, client_port)
        self.connection_with_verifier.connect(verifier_host, verifier_port)
        self.connection_with_db_proxy.connect(tee_host, tee_port)
        self.listening = True
        
        while self.listening:
            request = self.connection_with_client.receive()
            self.dispatch_request(request)
        
    def dispatch_request(self, request):
        request_json = json.loads(request)  
        pretty_print("CLIENT TEE", "Received request", request_json)
        try:
            if request_json['verb'] == 'GET' and request_json['route'] in self.methods:
                response = self.execute_query(request_json)
                self.send_response(response)
        except:
            if 'error' in request_json or 'close' in request_json:
                pretty_print("TEE DB PROXY", "Received close request")
                self.listening = False
                self.connection_with_client.close()
                self.stop()
                
    def execute_query(self, query):
        self.start_attestation_protocol()
        pretty_print("CLIENT", "Executing query", query)
        response = generate_request(["response"], ["response"])
        return response
    
    def start_attestation_protocol(self):
        nonce = self.request_nonce()
        pretty_print("CLIENT TEE", "Received nonce", nonce)
        evidence_requested = self.request_evidence(nonce)
        pretty_print("CLIENT TEE", "Received evidence", evidence_requested)
        attestation = self.send_evidence_to_verifier(evidence_requested)
        pretty_print("CLIENT TEE", "Received attestation", attestation)
        attestation = self.verify_attestation(attestation)
        if not attestation:
            pretty_print("CLIENT TEE", "Attestation failed")
            self.stop()
            return
        pretty_print("CLIENT TEE", "Attestation succeeded, sending query")
        response = self.send_query()
        if 'evidence' in response:
            evidence_requested = self.generate_evidence(response)
            response = self.send_evidence_to_db_proxy(evidence_requested)
        response = self.verify_response(response)
        response = self.do_something_with_response(response)
        self.send_response(response)           
    
    def get_public_key(self):
        return self.public_signing_key  
    
    def request_nonce(self):
        pretty_print("CLIENT TEE", "Requesting nonce")
        request = generate_request(["verb", "route"], ["GET", "nonce"])
        self.connection_with_verifier.send(request)
        nonce = self.connection_with_verifier.receive()
        return nonce
    
    def request_evidence(self, nonce):
        nonce = json.loads(nonce)['nonce']
        request = generate_request(["verb", "route", "nonce"], ["GET", "evidence", nonce])
        self.connection_with_db_proxy.send(request)
        evidence = self.connection_with_db_proxy.receive()
        return evidence
    
    def send_evidence_to_verifier(self, evidence):
        data = json.loads(evidence)
        evidence = data['evidence']
        nonce = data['nonce']
        request = generate_request(["verb", "route", "evidence", "nonce"], ["GET", "attestation", evidence, nonce])
        self.connection_with_verifier.send(request)
        attestation = self.connection_with_verifier.receive()   
        pretty_print("CLIENT TEE", "Received attestation", attestation)
        return attestation
    
    def send_evidence_to_db_proxy(self, evidence):
        data = json.loads(evidence)
        evidence = data['evidence']
        nonce = data['nonce']
        response = generate_request(["evidence", "nonce"], [evidence, nonce])
        self.connection_with_db_proxy.send(response)
        
    def verify_attestation(self, attestation):
        attestation = json.loads(attestation)
        pretty_print("CLIENT TEE", "Verifying attestation", attestation)
        attestation_siganture = attestation['attestation']
        attestation_siganture = base64.b64decode(attestation_siganture)
        pretty_print("CLIENT TEE", f"{attestation_siganture}")
        attestation = self.verifier_public_key.verify(attestation_siganture)
        pretty_print("CLIENT TEE", "Attestation verified", attestation)
        attestation_json = json.loads(attestation)
        expiration = attestation_json['expiration']
        if(time.time() > expiration):
            pretty_print("CLIENT TEE", "Attestation expired")
            return False
        else:
            pretty_print("CLIENT TEE", "Attestation valid")
            return attestation
    
    def generate_evidence(self, nonce):
        source_code = inspect.getsource(ClientTEE)
        evidence_hash = sha256(source_code.encode('utf-8') + from_json_to_bytes(nonce))
        evidence = self.private_signing_key.sign(evidence_hash)
        return evidence
    
    def send_query(self):
        request = generate_request(["verb", "route", "username", "password", "query_params"], ["GET", "query", "username", "password", "query_params"])
        self.connection_with_db_proxy.send(request)
        response = self.connection_with_db_proxy.receive()
        
    def verify_response(self, response):
        return response
    
    def do_something_with_response(self, response):
        return response
    
    def send_response(self, response):
        pretty_print("CLIENT TEE", "Sending response", response)
        self.connection_with_client.send(response)
    
    def stop(self):
        response = generate_request(["close"], ["close"])
        self.connection_with_verifier.send(response)
        self.connection_with_db_proxy.send(response)
        try:
            self.connection_with_verifier.close()
            self.connection_with_db_proxy.close()    
        except:
            print("Connections already closed")
        finally:
            return
    