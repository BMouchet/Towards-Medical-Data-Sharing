import base64
import time
from TLS_helper import TLSHelper
from nacl.signing import SigningKey
import inspect
import json
import nacl.hash, nacl.encoding
from display_helper import pretty_print

class TEE:
    def __init__(self, ca_cert_file, self_cert_file, key_file,  verifier_public_key):
        self.client_secure_connection = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=True)
        self.verifier_secure_connection = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=False)
        self.db_secure_connection = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=False)
        self.private_key = SigningKey.generate()
        self.public_key = self.private_key.verify_key
        self.verifier_public_key = verifier_public_key
        self.access_token = None
        self.hasher = nacl.hash.sha256
        self.secret = "Secret"

    def get_public_key(self):
        return self.public_key
    
    def handle_client_request(self, client_host, client_port, verifier_host, verifier_port, db_host, db_port):
        self.client_secure_connection.connect(client_host, client_port)
        request = self.client_secure_connection.receive()
        pretty_print("TEE", "Received request", request)
        request_hash = self.hasher(request.encode())
        pretty_print("TEE", "Requesting nonce")
        nonce = self.request_nonce(verifier_host, verifier_port, request_hash)
        pretty_print("TEE", "Received nonce", nonce)
        evidence = self.generate_evidence(request_hash, nonce)
        attestation = self.send_evidence(evidence, nonce)
        pretty_print("TEE", "Received attestation, requesting database Token", attestation)
        self.token = self.request_token(verifier_host, verifier_port, attestation)
        signed_token = self.private_key.sign(self.token.encode())
        # signed_request = self.sign_request(request)
        db_response = self.query_db(db_host, db_port, request, signed_token)
        pretty_print("TEE", "Received response from database, signing it", db_response)
        signed_result = self.sign_result(db_response)
        signed_result = base64.b64encode(signed_result).decode('utf-8')
        response = {"response": signed_result, "request": request, "attestation": attestation}
        response = json.dumps(response)
        pretty_print("TEE", "Sending response", response)
        self.client_secure_connection.send(response.encode())

    def request_nonce(self, verifier_host, verifier_port, request_hash):
        self.verifier_secure_connection.connect(verifier_host, verifier_port)
        request = {"request": "Request nonce", "params": base64.b64encode(request_hash).decode('utf-8')}
        self.verifier_secure_connection.send(json.dumps(request).encode())
        nonce = self.verifier_secure_connection.receive()
        return nonce
    
    def generate_evidence(self, request, nonce):
        source_bytes = inspect.getsource(TEE).encode('utf-8')  # Encode source code as bytes
        secret_bytes = self.secret.encode('utf-8')  # Encode secret as bytes
        nonce_json = json.loads(nonce)
        nonce_bytes = nonce_json["nonce"].encode('utf-8')  # Encode nonce as bytes

        # Concatenate all parts
        data_to_hash = source_bytes + secret_bytes + nonce_bytes

        # Hash the concatenated data
        source_hash = self.hasher(data_to_hash, encoder=nacl.encoding.HexEncoder)

        evidence = source_hash
        return self.private_key.sign(evidence) 
    
    def send_evidence(self, evidence, nonce):
        evidence_response = {"request": "Send evidence", "evidence": base64.b64encode(evidence).decode('utf-8'), "nonce": nonce}
        encoded_evidence = json.dumps(evidence_response).encode()
        
        pretty_print("TEE", "Generated evidence, sending it to Verifier", encoded_evidence)
        self.verifier_secure_connection.send(encoded_evidence) 
        attestation = self.verifier_secure_connection.receive()
        return attestation
    
    def request_token(self, verifier_host, verifier_port, attestation):
        # self.verifier_secure_connection.connect(verifier_host, verifier_port)
        request= {"request": "Request token", "attestation": attestation}
        self.verifier_secure_connection.send(json.dumps(request).encode())
        token = self.verifier_secure_connection.receive()

        return token
    
    def sign_request(self, request):
        return self.private_key.sign(request)
    
    def query_db(self, db_host, db_port, request, token):
        self.db_secure_connection.connect(db_host, db_port)
        token = base64.b64encode(token).decode('utf-8')
        data = json.dumps({"request": request, "token": token }).encode()
        pretty_print("TEE", "Received token and signed it, querying database", data)
        self.db_secure_connection.send(data)

        db_response = self.db_secure_connection.receive()

        return db_response
    
    def sign_result(self, db_response):
        signed_data = self.private_key.sign(db_response.encode())
        return signed_data
    
    def close_connections(self):
        self.client_secure_connection.close()
        self.verifier_secure_connection.close()
        self.db_secure_connection.close()