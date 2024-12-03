from db import Database
from tee import TEE
from verifier import Verifier
from client import Client
import threading
import time

host = "127.0.0.1"
client_port = 12345
verifier_port = 12346
db_port = 12347
tee_port = 12348

verifier = Verifier(ca_cert_file="certs/ca-cert.pem", self_cert_file="certs/server-cert.pem", key_file="certs/server-key.pem", tee_secret="Secret")
database = Database(ca_cert_file="certs/ca-cert.pem", self_cert_file="certs/server-cert.pem", key_file="certs/server-key.pem", verifier_public_key=verifier.get_public_key())
tee = TEE(ca_cert_file="certs/ca-cert.pem", self_cert_file="certs/server-cert.pem", key_file="certs/server-key.pem", verifier_public_key=verifier.get_public_key())
client = Client(ca_cert_file="certs/ca-cert.pem", self_cert_file="certs/client-cert.pem", key_file="certs/client-key.pem", tee_public_key=tee.get_public_key(), verifier_public_key=verifier.get_public_key())

def handle_tee():
    tee.handle_client_request(host, client_port, host, verifier_port, host, db_port)
    tee.close_connections()

def handle_client():
    client.send_request(host, client_port, "756.1111.1111.12", "Password", "get_height", {"avs_param": "756.1111.1111.11"})   
    client.close_connection()

def handle_verifier():
    verifier.tee_public_key = tee.get_public_key()
    verifier.listen(host, verifier_port)
    verifier.close_connection()
def handle_db():
    database.tee_public_key = tee.get_public_key()
    database.listen(host, db_port)
    database.close_connection()

tee_thread = threading.Thread(target=handle_tee)
time.sleep(1)
client_thread = threading.Thread(target=handle_client)
verifier_thread = threading.Thread(target=handle_verifier)
db_thread = threading.Thread(target=handle_db)
tee_thread.start()
client_thread.start()
verifier_thread.start()
db_thread.start()

tee_thread.join()
client_thread.join()
verifier_thread.join()
db_thread.join()

time.sleep(1)