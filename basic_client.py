from bson import ObjectId
from TLS_helper import TLSHelper
from display_helper import pretty_print
import json
import base64
import time
from nacl.signing import VerifyKey
from tools import generate_request

class BasicClient:
    def __init__(self, ca_cert_file, tee_public_key, verifier_public_key):
        """
        Initializes the BasicClient with necessary TLS configurations and public keys.

        :param ca_cert_file: Path to the CA certificate file.
        :param tee_public_key: Public key of the TEE.
        :param verifier_public_key: Public key of the verifier.
        """
        self.connection_with_verifier = TLSHelper(ca_cert_file, is_server=False)
        self.connection_with_db_proxy = TLSHelper(ca_cert_file, is_server=False)
        self.tee_public_key = tee_public_key
        self.verifier_public_key = verifier_public_key
        pretty_print("CLIENT", "Initialized")

    def start(self, tee_host, tee_port, verifier_host, verifier_port):
        """
        Starts the client process by connecting to the verifier and TEE DB proxy,
        performing attestation, and sending a query if attestation is valid.
        
        :param tee_host: Host address for the TEE.
        :param tee_port: Port for the TEE.
        :param verifier_host: Host address for the verifier.
        :param verifier_port: Port for the verifier.
        """
        try:
            self.connection_with_verifier.connect(verifier_host, verifier_port)
            self.connection_with_db_proxy.connect(tee_host, tee_port)

            nonce = self.request_nonce()
            pretty_print("CLIENT", "Received nonce", nonce)

            evidence = self.request_evidence(nonce)
            pretty_print("CLIENT", "Received evidence", evidence)

            attestation = self.send_evidence(evidence)
            if self.verify_attestation(attestation):
                query_result = self.send_query()
                query_result = self.verify_response(query_result)
                pretty_print("CLIENT", "Request was successful", query_result)
            else:
                pretty_print("CLIENT", "Attestation failed")

        except Exception as e:
            pretty_print("CLIENT", f"Error occurred: {str(e)}")

        finally:
            self.stop()

    def request_nonce(self):
        """
        Requests a nonce from the verifier.

        :return: Nonce received from the verifier.
        """
        pretty_print("CLIENT", "Requesting nonce")
        request = generate_request(["verb", "route"], ["GET", "nonce"])
        self.connection_with_verifier.send(request)
        return self.connection_with_verifier.receive()

    def request_evidence(self, nonce):
        """
        Requests evidence from the TEE DB proxy using the nonce.

        :param nonce: Nonce received from the verifier.
        :return: Evidence received from the TEE DB proxy.
        """
        nonce = json.loads(nonce)['nonce']
        request = generate_request(["verb", "route", "nonce"], ["GET", "evidence", nonce])
        self.connection_with_db_proxy.send(request)
        return self.connection_with_db_proxy.receive()

    def send_evidence(self, evidence):
        """
        Sends evidence to the verifier and requests attestation.

        :param evidence: Evidence received from the TEE DB proxy.
        :return: Attestation received from the verifier.
        """
        data = json.loads(evidence)
        request = generate_request(["verb", "route", "evidence", "nonce"], ["GET", "attestation", data['evidence'], data['nonce']])
        self.connection_with_verifier.send(request)
        return self.connection_with_verifier.receive()

    def verify_attestation(self, attestation):
        """
        Verifies the attestation received from the verifier.

        :param attestation: Attestation JSON string.
        :return: Decoded attestation if valid, False otherwise.
        """
        try:
            attestation = json.loads(attestation)
            pretty_print("CLIENT", "Verifying attestation", attestation)

            signature = base64.b64decode(attestation['attestation'])
            verified_attestation = self.verifier_public_key.verify(signature)
            pretty_print("CLIENT", "Attestation verified", verified_attestation)

            attestation_data = json.loads(verified_attestation)
            if time.time() > attestation_data['expiration']:
                pretty_print("CLIENT", "Attestation expired")
                return False

            pretty_print("CLIENT", "Attestation valid")
            return verified_attestation

        except Exception as e:
            pretty_print("CLIENT", f"Failed to verify attestation: {str(e)}")
            return False

    def send_query(self):
        """
        Sends a query to the TEE DB proxy.

        :return: Response from the TEE DB proxy.
        """
        request = generate_request(
            ["verb", "route", "username", "password", "params"],
            ["GET", "get_height", "doctor1", "password", {"patient_id": str(ObjectId('111111111111111111111111'))}]
        )
        self.connection_with_db_proxy.send(request)
        return self.connection_with_db_proxy.receive()

    def verify_response(self, response):
        """
        Verifies the response received from the TEE DB proxy.

        :param response: Response JSON string.
        :return: Decoded response if valid.
        """
        try:
            response_data = json.loads(response)
            pretty_print("CLIENT", "Verifying response", response_data)

            decoded_response = base64.b64decode(response_data['response'])
            return self.tee_public_key.verify(decoded_response)

        except Exception as e:
            pretty_print("CLIENT", f"Failed to verify response: {str(e)}")
            return None

    def stop(self):
        """
        Gracefully stops the client by closing all connections.
        """
        try:
            close_request = generate_request(["close"], ["close"])
            self.connection_with_verifier.send(close_request)
            self.connection_with_db_proxy.send(close_request)

            self.connection_with_verifier.close()
            self.connection_with_db_proxy.close()

        except Exception as e:
            pretty_print("CLIENT", f"Error during shutdown: {str(e)}")

        finally:
            pretty_print("CLIENT", "Connections closed")
