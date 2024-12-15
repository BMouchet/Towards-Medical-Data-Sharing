import base64
import json
import time
from TLS_helper import TLSHelper
import inspect
from tee_db_proxy import TEE_DB_Proxy
from nacl.signing import SigningKey
import nacl.utils, nacl.secret
from tools import generate_request, prepare_bytes_for_json, from_json_to_bytes
from display_helper import pretty_print
from nacl.hash import sha256
import threading

class Verifier:
    def __init__(self, ca_cert_file, self_cert_file, key_file):
        self.connections = {}
        self.connections["Client"] = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=True)
        self.connections["TEE"] = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=True)
        self.tee_source_code = inspect.getsource(TEE_DB_Proxy)
        self.tee_public_key = None
        self.pending_verifications = {}
        self.exipiration = 300
        self.private_signing_key = SigningKey.generate()
        self.public_signing_key = self.private_signing_key.verify_key
        pretty_print("VERIFIER", "Initialized")
        self.listening = False
        
    def set_tee_public_key(self, tee_public_key):
        self.tee_public_key = tee_public_key
        
    def get_public_key(self):
        return self.public_signing_key
    
    def handle_connection(self, connection):
        while self.listening:
            try:
                request = self.connections[connection].receive()
                self.dispatch_request(request, connection)
            except:
                pretty_print("VERIFIER", "Connection error")
                break
    
    def start(self, verifier_host, verifier_port, other_verifier_port):
        self.listening = True
        self.connections["Client"].connect(verifier_host, verifier_port)
        if other_verifier_port:
            self.connections["TEE"].connect(verifier_host, other_verifier_port)
            tee_thread = threading.Thread(target=self.handle_connection, args=("TEE",))
            tee_thread.start()

        
        client_thread = threading.Thread(target=self.handle_connection, args=("Client",))
        
        client_thread.start()
        
        
    def dispatch_request(self, request, connection):
        request_json = json.loads(request)
        pretty_print("VERIFIER", "Received request", request_json)
        try: 
            if request_json['verb'] == 'GET' and request_json['route'] == 'nonce':
                nonce = self.return_nonce()
                self.send_nonce(nonce, connection)
            elif request_json['verb'] == 'GET' and request_json['route'] == 'attestation':
                pretty_print("VERIFIER", "Received attestation request")
                attestation = self.generate_attestation(request_json['evidence'], request_json['nonce'])
                self.send_attestation(attestation, connection)
        except:
            if 'error' in request_json or 'close' in request_json:
                pretty_print("VERIFIER", "Received close request")
                self.listening = False
                self.connections[connection].close()


    def return_nonce(self):
        pretty_print("VERIFIER", "Received nonce request")
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        self.pending_verifications[prepare_bytes_for_json(nonce)] = time.time()
        return nonce
    
    def compute_known_evidence(self, nonce):
        evidence_hash = sha256(self.tee_source_code.encode('utf-8') + from_json_to_bytes(nonce))
        return evidence_hash
    
    def verify_evidence(self, evidence):
        bytes_evidence = base64.b64decode(evidence)
        return self.tee_public_key.verify(bytes_evidence)
    
    def generate_attestation(self, evidence, nonce):
        pretty_print("VERIFIER", f"Pending ? {self.pending_verifications[nonce]}")
        if(nonce in self.pending_verifications):
            pretty_print("VERIFIER", "Nonce found")
            if(time.time() - self.pending_verifications[nonce] < self.exipiration):
                pretty_print("VERIFIER", "Nonce not expired")
                pretty_print("VERIFIER", f"Verifying evidence {evidence}")
                received_evidence = self.verify_evidence(evidence)
                pretty_print("VERIFIER", "Received evidence verified")
                known_evidence = self.compute_known_evidence(nonce)
                if(received_evidence == known_evidence):
                    pretty_print("VERIFIER", "Evidence match")
                    expiration = time.time() + self.exipiration
                    evidence = {"expiration": expiration, "evidence": evidence}
                    evidence_json = json.dumps(evidence, separators=(',', ':')).encode('utf-8') 
                    attestation = self.private_signing_key.sign(evidence_json)
                    return attestation  
    
    def send_attestation(self, attestation, connection):
        response = generate_request(["attestation"], [prepare_bytes_for_json(attestation)])
        pretty_print("VERIFIER", "Sending attestation", response)
        self.connections[connection].send(response)
    
    def send_nonce(self, nonce, connection):
        response = generate_request(["nonce"], [prepare_bytes_for_json(nonce)])
        pretty_print("VERIFIER", "Sending nonce", response)
        self.connections[connection].send(response)