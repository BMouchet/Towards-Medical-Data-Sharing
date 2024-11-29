import base64
from TLS_helper import TLSHelper
import json
from nacl.signing import VerifyKey
import time
from display_helper import pretty_print


class Client:
    def __init__(self, ca_cert_file, self_cert_file, key_file, tee_public_key, verifier_public_key):
        self.secure_connection = TLSHelper(ca_cert_file, self_cert_file, key_file, is_server=False)
        self.tee_public_key = tee_public_key
        self.verifier_public_key = verifier_public_key

    def send_request(self, tee_host, tee_port, username, password, avs_number):
        self.secure_connection.connect(tee_host, tee_port)
        request_data = {
            "username": username,
            "password": password,
            "avs_number": avs_number
        }
        request_json = json.dumps(request_data)
        pretty_print("CLIENT", "Sending request", request_json)
        self.secure_connection.send(request_json.encode('utf-8'))
        response = self.secure_connection.receive()
        pretty_print("CLIENT", "Received response", response)
        binary_data = response.encode('utf-8')
        response_json = json.loads(binary_data)
        pretty_print("CLIENT", "Verifying response")
        query_result = self.verify_result(response_json)
        pretty_print("CLIENT", "Verifying attestation")
        attestation = self.verify_attestation(response_json)
        if query_result and attestation:
            pretty_print("CLIENT", "Request was successful")
            pretty_print("CLIENT", query_result)
        else:
            pretty_print("CLIENT", "Request was unsuccessful")

    def verify_result(self, response):
        try:
            response = base64.b64decode(response['response'])
            pretty_print("CLIENT", f"Response: {response}")
            query_result = self.tee_public_key.verify(response)
            return query_result
        except Exception as e:
            pretty_print("CLIENT", f"Query validation: {e}")
            return False
    
    def verify_attestation(self, response):
        try:
            expiration_time = base64.b64decode(response['expiration'])
            expiration_time = self.verifier_public_key.verify(expiration_time)
            if time.time() - float(expiration_time) > 300:
                pretty_print("CLIENT", "Attestation expired")
                return False
            attestation = base64.b64decode(response['attestation'])
            attestation = self.verifier_public_key.verify(attestation)
            return attestation
        except Exception as e:
            pretty_print("CLIENT", f"Attestation validation: {e}")
            return False
        
    def close_connection(self):
        self.secure_connection.close()

