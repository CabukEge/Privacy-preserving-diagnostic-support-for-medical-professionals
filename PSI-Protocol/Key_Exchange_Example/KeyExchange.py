import socket
import threading

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

#todo not entierly necessary maybe(!) only parameter sharing.

# Generate some parameters. These can be reused.
parameters = dh.generate_parameters(generator=2, key_size=2048)

# In a real handshake the peer_public_key will be received from the
# other party. For this example we'll generate another private key and
# get a public key from that. Note that in a DH handshake both peers
# must agree on a common set of parameters.

def server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 1234))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)

            # Generate a private key for use in the exchange.
            private_key = parameters.generate_private_key()
            public_key = private_key.public_key().public_bytes(
                encoding = serialization.Encoding.PEM,
                format = serialization.PublicFormat.SubjectPublicKeyInfo
            )

            conn.send(public_key)
            peer_public_key = conn.recv(1024)
            peer_public_key = serialization.load_pem_public_key(
                peer_public_key,
                backend=default_backend()
            )

            shared_key = private_key.exchange(peer_public_key)

            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
            ).derive(shared_key)

            print('Derived Key:', derived_key)
            print('Private Key Server:', private_key)

def client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('127.0.0.1', 1234))
        print('Connected to server')
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key().public_bytes(
            encoding = serialization.Encoding.PEM,
            format = serialization.PublicFormat.SubjectPublicKeyInfo
        )

        s.send(public_key)
        peer_public_key = s.recv(1024)
        peer_public_key = serialization.load_pem_public_key(
            peer_public_key,
            backend=default_backend()
        )

        shared_key = private_key.exchange(peer_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)

        print('Derived Key:', derived_key)
        print('Private Key Client:', private_key.)

try:
    server_thread = threading.Thread(target=server)
    client_thread = threading.Thread(target=client)
    server_thread.start()
    client_thread.start()
    server_thread.join()
    client_thread.join()
except Exception as e:
    print(e)