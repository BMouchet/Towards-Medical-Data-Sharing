import base64
import json
import time
from TLS_helper import TLSHelper
from nacl.signing import SigningKey 
import nacl.utils, nacl.secret
import inspect
import nacl.hash
from tee import TEE
from display_helper import pretty_print

class Verifier:
    def __init__(self, ca_cert_file, self_cert_file, key_file, tee_secret):
        self.secure_connection = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=True)
        self.tee_secret = tee_secret.encode('utf-8')
        self.tee_source_code = inspect.getsource(TEE).encode('utf-8')
        self.tee_public_key = None
        self.signing_key = SigningKey.generate()
        self.public_key = self.signing_key.verify_key
        self.pending_verifications = {}
        self.hasher = nacl.hash.sha256
        self.is_listening = False
        


    def get_public_key(self):
        return self.public_key

    def listen(self, host, port):
        self.is_listening = True
        self.secure_connection.connect(host, port)
        while self.is_listening:
            received_data = self.secure_connection.receive()
            try:
                # Decode Base64-encoded evidence
                # binary_data = base64.b64decode(received_data.encode('utf-8'))
                binary_data = received_data.encode('utf-8')
                request = json.loads(binary_data)
            except json.JSONDecodeError as e:
                raise e

            if request["request"] == "Request nonce":
                pretty_print("VERIFIER", "Received nonce request")
                nonce = self.generate_nonce()
                timestamp = time.time()
                response = {"nonce": nonce, "timestamp": timestamp}
                self.pending_verifications[nonce] = timestamp
                response = json.dumps(response).encode('utf-8')
                pretty_print("VERIFIER", "Sending nonce", response)
                self.secure_connection.send(response)
            elif request["request"] == "Request token":
                pretty_print("VERIFIER", "Received token request")
                if self.verify_attestation_for_token(request["attestation"]):
                    token = self.generate_token()
                    response = json.dumps({"token": base64.b64encode(token).decode('utf-8')}).encode('utf-8')
                    pretty_print("VERIFIER", "Attestation valid, sending token", response)
                    self.secure_connection.send(response)
                self.is_listening = False
            elif request["request"] == "Send evidence":    
                signed_attestation = self.validate_evidence(request)
                encoded_signed_attestation = base64.b64encode(signed_attestation).decode('utf-8')
                response = json.dumps({"attestation": encoded_signed_attestation}).encode('utf-8')
                pretty_print("VERIFIER", "Evidence valid, sending attestation", response)
                self.secure_connection.send(response)

    
    def generate_nonce(self):
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        return base64.b64encode(nonce).decode('utf-8')
    
    def validate_evidence(self, request):
        try:
            signed_evidence = base64.b64decode(request["evidence"])

            signed_hash = self.tee_public_key.verify(signed_evidence)
            nonce_json = json.loads(request["nonce"])
            nonce = nonce_json["nonce"].encode('utf-8')
            recomputed_hash = self.hasher(
                self.tee_source_code + self.tee_secret + nonce,
                encoder=nacl.encoding.HexEncoder,
            )
            if recomputed_hash == signed_hash:
                return self.signing_key.sign(request["evidence"].encode('utf-8'))
            else:
                return None

        except Exception as e:
            pretty_print("VERIFIER", "Evidence validation failed:", e)
            return None

    def verify_attestation_for_token(self, attestation):
        json_attestation = json.loads(attestation)
        try:
            signed_attestation = base64.b64decode(json_attestation["attestation"])
            self.public_key.verify(signed_attestation)
            return True
        except Exception as e:
            pretty_print("VERIFIER", "Attestation verification failed:", e)
            return False   
               
    
    def generate_token(self):
        return nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
     
    
    def close_connection(self):
        self.is_listening = False
        self.secure_connection.close()