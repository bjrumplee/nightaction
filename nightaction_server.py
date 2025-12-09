#!/usr/bin/env python3
"""
NightAction Server
Secure authentication server for covert communications
"""

import socket
import threading
import json
import base64
import sqlite3
import hashlib
import os
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class NightActionServer:
    def __init__(self, host='0.0.0.0', port=7777, db_path='nightaction.db'):
        self.host = host
        self.port = port
        self.db_path = db_path
        self.sessions = {}  # Track active sessions

        # Generate or load RSA keys
        self.private_key, self.public_key = self._load_or_generate_keys()

        # Initialize database
        self._init_database()

    def _load_or_generate_keys(self):
        """Load existing RSA keys or generate new ones"""
        private_key_path = Path('server_private.pem')
        public_key_path = Path('server_public.pem')

        if private_key_path.exists() and public_key_path.exists():
            print("[*] Loading existing RSA keys...")
            with open(private_key_path, 'rb') as f:
                private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            with open(public_key_path, 'rb') as f:
                public_key = serialization.load_pem_public_key(
                    f.read(), backend=default_backend()
                )
        else:
            print("[*] Generating new RSA key pair...")
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            public_key = private_key.public_key()

            # Save keys
            with open(private_key_path, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            with open(public_key_path, 'wb') as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            print("[+] RSA keys generated and saved")

        return private_key, public_key

    def _init_database(self):
        """Initialize SQLite database with encryption"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create agents table (codes are hashed for security)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS agents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code_hash TEXT UNIQUE NOT NULL,
                codename TEXT NOT NULL,
                active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP
            )
        ''')

        conn.commit()
        conn.close()
        print(f"[+] Database initialized: {self.db_path}")

    def _hash_code(self, code_words):
        """Hash the 4-word code for secure storage"""
        code_string = ' '.join(code_words).upper()
        return hashlib.sha256(code_string.encode()).hexdigest()

    def add_agent(self, code_words, codename):
        """Add a new agent with their code and codename"""
        code_hash = self._hash_code(code_words)

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO agents (code_hash, codename) VALUES (?, ?)',
                (code_hash, codename)
            )
            conn.commit()
            conn.close()
            print(f"[+] Agent added: {codename}")
            return True
        except sqlite3.IntegrityError:
            print(f"[-] Code already exists in database")
            return False

    def verify_code(self, code_words):
        """Verify code and return codename if valid"""
        code_hash = self._hash_code(code_words)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            'SELECT codename FROM agents WHERE code_hash = ? AND active = 1',
            (code_hash,)
        )
        result = cursor.fetchone()

        if result:
            # Update last used timestamp
            cursor.execute(
                'UPDATE agents SET last_used = CURRENT_TIMESTAMP WHERE code_hash = ?',
                (code_hash,)
            )
            conn.commit()

        conn.close()
        return result[0] if result else None

    def _aes_encrypt(self, plaintext, key):
        """Encrypt data using AES-256-GCM"""
        iv = os.urandom(12)  # GCM standard IV size
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

        # Return IV + tag + ciphertext (all needed for decryption)
        return base64.b64encode(iv + encryptor.tag + ciphertext).decode()

    def _aes_decrypt(self, encrypted_data, key):
        """Decrypt AES-256-GCM encrypted data"""
        try:
            data = base64.b64decode(encrypted_data)
            iv = data[:12]
            tag = data[12:28]
            ciphertext = data[28:]

            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode()
        except Exception as e:
            print(f"[-] Decryption error: {e}")
            return None

    def _rsa_decrypt(self, encrypted_data):
        """Decrypt RSA encrypted data"""
        try:
            ciphertext = base64.b64decode(encrypted_data)
            plaintext = self.private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plaintext
        except Exception as e:
            print(f"[-] RSA decryption error: {e}")
            return None

    def handle_client(self, client_socket, address):
        """Handle individual client connection"""
        print(f"[*] Connection from {address[0]}:{address[1]}")
        session_key = None
        codename = None

        try:
            # Step 1: Send public key to client
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            client_socket.send(public_pem)

            # Step 2: Receive encrypted authentication data
            encrypted_auth = client_socket.recv(4096).decode()

            # Step 3: Decrypt with RSA private key
            decrypted_data = self._rsa_decrypt(encrypted_auth)
            if not decrypted_data:
                client_socket.send(b"AUTH_FAILED")
                return

            # Parse authentication data (session_key + 4 words)
            auth_data = json.loads(decrypted_data.decode())
            session_key = base64.b64decode(auth_data['session_key'])
            code_words = auth_data['code_words']

            # Step 4: Verify code
            codename = self.verify_code(code_words)

            if codename:
                # Send encrypted welcome message
                welcome_msg = json.dumps({
                    'status': 'SUCCESS',
                    'message': f'Welcome {codename}',
                    'codename': codename
                })
                encrypted_welcome = self._aes_encrypt(welcome_msg, session_key)
                client_socket.send(encrypted_welcome.encode())

                print(f"[+] Agent authenticated: {codename} from {address[0]}")

                # Store session
                self.sessions[address] = {
                    'codename': codename,
                    'session_key': session_key
                }

                # Step 5: Enter secure communication mode
                self._secure_communication(client_socket, address, session_key, codename)
            else:
                error_msg = json.dumps({
                    'status': 'FAILED',
                    'message': 'Invalid authentication code'
                })
                encrypted_error = self._aes_encrypt(error_msg, session_key)
                client_socket.send(encrypted_error.encode())
                print(f"[-] Authentication failed from {address[0]}")

        except Exception as e:
            print(f"[-] Error handling client {address[0]}: {e}")
        finally:
            if address in self.sessions:
                del self.sessions[address]
            client_socket.close()
            print(f"[*] Connection closed: {address[0]}")

    def _secure_communication(self, client_socket, address, session_key, codename):
        """Handle encrypted communication with authenticated client"""
        print(f"[*] Entering secure communication mode with {codename}")

        while True:
            try:
                # Receive encrypted message
                encrypted_msg = client_socket.recv(4096).decode()
                if not encrypted_msg:
                    break

                # Decrypt message
                decrypted_msg = self._aes_decrypt(encrypted_msg, session_key)
                if not decrypted_msg:
                    break

                print(f"[{codename}]: {decrypted_msg}")

                # Check for disconnect command
                if decrypted_msg.strip().upper() == 'DISCONNECT':
                    goodbye_msg = f"Goodbye {codename}. Stay safe."
                    encrypted_goodbye = self._aes_encrypt(goodbye_msg, session_key)
                    client_socket.send(encrypted_goodbye.encode())
                    break

                # Echo back (in real implementation, add your logic here)
                response = f"Server received: {decrypted_msg}"
                encrypted_response = self._aes_encrypt(response, session_key)
                client_socket.send(encrypted_response.encode())

            except Exception as e:
                print(f"[-] Communication error with {codename}: {e}")
                break

    def start(self):
        """Start the server"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)

        print(f"""
╔═══════════════════════════════════════════╗
║         NIGHTACTION SERVER ACTIVE         ║
╚═══════════════════════════════════════════╝
[*] Listening on {self.host}:{self.port}
[*] Press Ctrl+C to stop
""")

        try:
            while True:
                client_socket, address = server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            print("\n[*] Server shutting down...")
        finally:
            server_socket.close()

def main():
    import argparse

    parser = argparse.ArgumentParser(description='NightAction Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=7777, help='Port to listen on')
    parser.add_argument('--db', default='nightaction.db', help='Database file path')

    args = parser.parse_args()

    server = NightActionServer(host=args.host, port=args.port, db_path=args.db)
    server.start()

if __name__ == '__main__':
    main()
