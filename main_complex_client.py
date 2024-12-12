from tee_db_proxy import TEE_DB_Proxy
from verifier import Verifier
import threading
from complex_client import ComplexClient
from client_tee import ClientTEE

host = "127.0.0.1"
client_port = 12345
verifier_port = 12346
tee_port = 12347
client_tee_port = 12348
other_verifier_port = 12349
ca_cert_file = "certs/ca-cert.pem"
client_key_file = "certs/client-key.pem"
server_key_file = "certs/server-key.pem"
server_cert_file = "certs/server-cert.pem"

verifier = Verifier(ca_cert_file, server_cert_file, server_key_file)
tee_db_proxy = TEE_DB_Proxy(ca_cert_file, server_cert_file, server_key_file)
client_tee = ClientTEE(ca_cert_file, server_cert_file, server_key_file, tee_db_proxy.get_public_key(), verifier.get_public_key())
client = ComplexClient(ca_cert_file)
verifier.set_tee_public_key(tee_db_proxy.get_public_key())

def handle_verifier():
    verifier.start(host, verifier_port, other_verifier_port)
    
def handle_tee():
    tee_db_proxy.start(host, tee_port, host, other_verifier_port)
    
def handle_client():
    client.start(host, client_tee_port)
    
def handle_client_tee():
    client_tee.start(host, client_tee_port, host, tee_port, host, verifier_port)
    
verifier_thread = threading.Thread(target=handle_verifier)
tee_thread = threading.Thread(target=handle_tee)
client_thread = threading.Thread(target=handle_client)
client_tee_thread = threading.Thread(target=handle_client_tee)

verifier_thread.start()
client_thread.start()
client_tee_thread.start()
tee_thread.start()

verifier_thread.join()
client_thread.join()
client_tee_thread.join()
tee_thread.join()

