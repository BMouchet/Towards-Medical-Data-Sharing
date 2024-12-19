from basic_client import BasicClient
from tee_db_proxy import TEE_DB_Proxy
from verifier import Verifier
import threading

host = "127.0.0.1"
client_port = 12345
verifier_port = 12346
tee_port = 12347
ca_cert_file = "certs/ca-cert.pem"
client_key_file = "certs/client-key.pem"
server_key_file = "certs/server-key.pem"
server_cert_file = "certs/server-cert.pem"

verifier = Verifier(ca_cert_file, server_cert_file, server_key_file)
tee_db_proxy = TEE_DB_Proxy(ca_cert_file, server_cert_file, server_key_file, verifier.get_public_key())
client = BasicClient(ca_cert_file, tee_db_proxy.get_public_key(), verifier.get_public_key())
verifier.set_tee_public_key(tee_db_proxy.get_public_key())
def handle_verifier():
    verifier.start(host, verifier_port, None)
    
def handle_tee():
    tee_db_proxy.start(host, tee_port, None, None)

def handle_client():
    client.start(host, tee_port, host, verifier_port)

    
verifier_thread = threading.Thread(target=handle_verifier)
tee_thread = threading.Thread(target=handle_tee)
client_thread = threading.Thread(target=handle_client)

verifier_thread.start()
client_thread.start()
tee_thread.start()
