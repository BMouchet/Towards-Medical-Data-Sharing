import base64
import datetime
import json
import os
import time
from TLS_helper import TLSHelper
import inspect
from tee_db_proxy import TEE_DB_Proxy
from client_tee import ClientTEE
from nacl.signing import SigningKey
import nacl.utils, nacl.secret
from tools import generate_request, prepare_bytes_for_json, from_json_to_bytes, write_data
from display_helper import pretty_print
from nacl.hash import sha256
import threading
from pymongo import MongoClient
import dotenv

class Verifier:
    def __init__(self, ca_cert_file, self_cert_file, key_file):
        self.connections = {}
        self.connections["Client"] = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=True)
        self.connections["TEE"] = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=True)
        self.tee_source_code = inspect.getsource(TEE_DB_Proxy)
        self.client_tee_source_code = inspect.getsource(ClientTEE)
        self.tee_public_key = None
        self.client_tee_public_key = None
        self.pending_verifications = {}
        self.exipiration = 300
        self.private_signing_key = SigningKey.generate()
        self.public_signing_key = self.private_signing_key.verify_key
        # pretty_print("VERIFIER", "Initialized")
        self.listening = False
        self.threads = {}
        client = MongoClient('localhost', 27017)
        db = client['pipelines']
        self.approved_pipelines = db['approved_pipelines']
        self.start_time = None
        dotenv.load_dotenv()
        self.file = os.getenv('FILE')
        
    def set_tee_public_key(self, tee_public_key):
        self.tee_public_key = tee_public_key
    
    def set_client_tee_public_key(self, client_tee_public_key):
        self.client_tee_public_key = client_tee_public_key
        
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
            self.threads["TEE"] = threading.Thread(target=self.handle_connection, args=("TEE",))
            self.threads["TEE"].start()

        
        self.threads["Client"] = threading.Thread(target=self.handle_connection, args=("Client",))
        
        self.threads["Client"].start()
        
        
    def dispatch_request(self, request, connection):
        self.start_time = time.time()
        request_json = json.loads(request)
        # pretty_print("VERIFIER", "Received request", request_json)
        try: 
            if request_json['verb'] == 'GET' and request_json['route'] == 'nonce':
                nonce = self.return_nonce()
                self.send_nonce(nonce, connection)
                duration = time.time() - self.start_time
                write_data(self.file, [datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), None, "Nonce Verifier", duration])
            elif request_json['verb'] == 'GET' and request_json['route'] == 'attestation':
                # pretty_print("VERIFIER", "Received attestation request")
                self.start_time = time.time()
                if 'pipeline_evidence' in request_json:
                    attestation = self.generate_attestation_with_pipeline(request, connection)
                    self.send_attestation(attestation, connection)
                else:
                    attestation = self.generate_attestation(request, connection)
                    self.send_attestation(attestation, connection)
                duration = time.time() - self.start_time
                write_data(self.file, [datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), None, "Attestation Generation", duration])
        except:
            if 'error' in request_json or 'close' in request_json:
                pretty_print("VERIFIER", "Received close request")
                self.listening = False
                for connection in self.connections:
                    try:
                        self.connections[connection].close()
                        self.threads[connection].join()
                    except:
                        pass


    def return_nonce(self):
        # pretty_print("VERIFIER", "Received nonce request")
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        self.pending_verifications[prepare_bytes_for_json(nonce)] = time.time()
        return nonce
    
    def compute_known_evidence(self, nonce, connection):
        if connection == "TEE":
            evidence_hash = sha256(self.client_tee_source_code.encode('utf-8') + from_json_to_bytes(nonce))
        else:
            evidence_hash = sha256(self.tee_source_code.encode('utf-8') + from_json_to_bytes(nonce))
        return evidence_hash
    
    def compute_known_pipeline_evidence(self, pipeline_name, nonce):
        try:
            pipeline = self.approved_pipelines.find_one({"name": pipeline_name})["pipeline"]
            pipeline_hash = sha256(str(pipeline).encode('utf-8') + from_json_to_bytes(nonce))
            return pipeline_hash
        except Exception as e:
            pretty_print("VERIFIER", f"Error computing pipeline evidence {e}")
            return None
        
    
    def verify_evidence(self, evidence, connection):
        bytes_evidence = base64.b64decode(evidence)
        if connection == "TEE":
            return self.client_tee_public_key.verify(bytes_evidence)
        else:
            return self.tee_public_key.verify(bytes_evidence)
    
    def generate_attestation(self, request, connection):
        request_json = json.loads(request)
        nonce = request_json['nonce']
        evidence = request_json['evidence']
        # pretty_print("VERIFIER", f"Pending ? {self.pending_verifications[nonce]}")
        if(nonce in self.pending_verifications):
            # pretty_print("VERIFIER", "Nonce found")
            if(time.time() - self.pending_verifications[nonce] < self.exipiration):
                # pretty_print("VERIFIER", "Nonce not expired")
                # pretty_print("VERIFIER", f"Verifying evidence {evidence}")
                received_evidence = self.verify_evidence(evidence, connection)
                # pretty_print("VERIFIER", "Received evidence verified")
                known_evidence = self.compute_known_evidence(nonce, connection)
                if(received_evidence == known_evidence):
                    # pretty_print("VERIFIER", "Evidence match")
                    expiration = time.time() + self.exipiration
                    evidence = {"expiration": expiration, "evidence": evidence}
                    evidence_json = json.dumps(evidence, separators=(',', ':')).encode('utf-8') 
                    attestation = self.private_signing_key.sign(evidence_json)
                    return attestation  
                
    def generate_attestation_with_pipeline(self, request, connection):
        request_json = json.loads(request)
        nonce = request_json['nonce']
        pipeline_name = request_json['pipeline']
        evidence = request_json['evidence']
        pipeline_evidence = request_json['pipeline_evidence']
        # pretty_print("VERIFIER", f"Pending ? {self.pending_verifications[nonce]}")
        if(nonce in self.pending_verifications):
            # pretty_print("VERIFIER", "Nonce found")
            if(time.time() - self.pending_verifications[nonce] < self.exipiration):
                # pretty_print("VERIFIER", "Nonce not expired")
                # pretty_print("VERIFIER", f"Verifying evidence for pipeline {evidence}")
                received_evidence = self.verify_evidence(evidence, connection)
                received_pipeline = self.verify_evidence(pipeline_evidence, connection)
                # pretty_print("VERIFIER", "Received evidence verified")
                known_evidence = self.compute_known_evidence(nonce, connection)
                # pretty_print("VERIFIER", f"Known evidence {known_evidence}")    
                known_pipeline_evidence = self.compute_known_pipeline_evidence(pipeline_name, nonce)
                # pretty_print("VERIFIER", f"Known pipeline evidence {known_pipeline_evidence}, computed {received_pipeline}")
                if(received_evidence == known_evidence and received_pipeline == known_pipeline_evidence):
                    try:
                        # pretty_print("VERIFIER", "Evidence match for pipeline")
                        expiration = time.time() + self.exipiration
                        evidence = {"expiration": expiration, "evidence": evidence, "pipeline_evidence": pipeline_evidence}
                        evidence_json = json.dumps(evidence, separators=(',', ':')).encode('utf-8') 
                        attestation = self.private_signing_key.sign(evidence_json)
                        # pretty_print("VERIFIER", f"Attestation generated for pipeline {attestation}")
                        return attestation  
                    except Exception as e:
                        pretty_print("VERIFIER", f"Error generating attestation {e}")
                # pretty_print("VERIFIER", "Evidence does not match for pipeline")
    
    def send_attestation(self, attestation, connection):
        response = generate_request(["attestation"], [prepare_bytes_for_json(attestation)])
        # pretty_print("VERIFIER", "Sending attestation", response)
        self.connections[connection].send(response)
    
    def send_nonce(self, nonce, connection):
        response = generate_request(["nonce"], [prepare_bytes_for_json(nonce)])
        # pretty_print("VERIFIER", "Sending nonce", response)
        self.connections[connection].send(response)
