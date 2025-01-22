import base64
import json

from bson import ObjectId
from TLS_helper import TLSHelper
from display_helper import pretty_print
from tools import generate_request


class ComplexClient:
    def __init__(self, ca_cert_file):
        """
        Initialize the ComplexClient with a TLS connection.

        Args:
            ca_cert_file (str): Path to the CA certificate file.
        """
        self.connection_with_personal_tee = TLSHelper(ca_cert_file, is_server=False)
        # pretty_print("CLIENT", "Initialized")
        
    def start(self, personal_tee_host, personal_tee_port, query):
        """
        Start the connection to the personal TEE and send a query.

        Args:
            personal_tee_host (str): Hostname of the personal TEE.
            personal_tee_port (int): Port number of the personal TEE.

        Returns:
            None
        """
        self.connection_with_personal_tee.connect(personal_tee_host, personal_tee_port)
        response = self.send_query(query)
        # pretty_print("CLIENT", f"Request was successful {response}")
        response = json.loads(response)["response"]
        response = base64.b64decode(response).decode()
        # pretty_print("CLIENT", f"Request was successful {response}")
        self.stop()
        return response
    
    def send_query(self, query):
        """
        Send a query to the personal TEE.

        Returns:
            str: The response from the personal TEE.
        """
        # request = generate_request(["verb", "route", "username", "password", "params"], ["GET", "is_bp_above_mean", "external1", "password", {"patient_id": str(ObjectId('111111111111111111111111'))}])
        request = generate_request(["verb", "route", "username", "password", "params"], query)

        # pretty_print("CLIENT", "Sending query", request)
        self.connection_with_personal_tee.send(request)
        response = self.connection_with_personal_tee.receive()
        # pretty_print("CLIENT", f"Received response {response}")
        return response
    
    def stop(self):
        """
        Stop the connection to the personal TEE.

        Returns:
            None
        """
        response = generate_request(["close"], ["close"])
        self.connection_with_personal_tee.send(response)
        try:
            self.connection_with_personal_tee.close() 
        except:
            pass
        finally:
            return