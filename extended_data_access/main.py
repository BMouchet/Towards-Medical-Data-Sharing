import queue
import threading
import time
from client import Client
from tee_db_proxy import TEE_DB_Proxy
from verifier import Verifier
from client_tee import ClientTEE

from tools import generate_json_from_lists

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
tee_db_proxy = TEE_DB_Proxy(ca_cert_file, server_cert_file, server_key_file, verifier.get_public_key())
client_tee = ClientTEE(ca_cert_file, server_cert_file, server_key_file, tee_db_proxy.get_public_key(), verifier.get_public_key())
client = Client(ca_cert_file)
verifier.set_tee_public_key(tee_db_proxy.get_public_key())
verifier.set_client_tee_public_key(client_tee.get_public_key())
verifier.set_tee_public_key(tee_db_proxy.get_public_key())
client.set_personal_tee_public_key(client_tee.get_public_key())

def handle_verifier():
    verifier.start(host, verifier_port, other_verifier_port)
    
def handle_tee():
    tee_db_proxy.start(host, tee_port, host, other_verifier_port)
    
def handle_client(query, result_queue):
    result = client.start(host, client_tee_port, query)
    result_queue.put(result)
    
def handle_client_tee():
    client_tee.start(host, client_tee_port, host, tee_port, host, verifier_port)
    
query = generate_json_from_lists(["method", "route", "username", "password", "params"], ["GET", "is_bp_above_mean", "external1", "password", {"patient_id": "111111111111111111111111"}])

result_queue = queue.Queue()  
for i in range(100):
    verifier_thread = threading.Thread(target=handle_verifier, daemon=True)
    tee_thread = threading.Thread(target=handle_tee, daemon=True)
    client_thread = threading.Thread(target=handle_client, args=(query, result_queue), daemon=True)
    client_tee_thread = threading.Thread(target=handle_client_tee, daemon=True)
    verifier_thread.start()
    tee_thread.start()
    client_thread.start()
    client_tee_thread.start()
    verifier_thread.join()
    tee_thread.join()
    client_thread.join()
    client_tee_thread.join()

    print("Result:", result_queue.get(), i)
    time.sleep(2)
        

