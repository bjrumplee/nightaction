#!/usr/bin/env python3
"""
NightAction Client
Secure client for covert communications with bidirectional support
"""

import socket
import json
import base64
import os
import threading
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class NightActionClient:
    def __init__(self):
        self.session_key = None
        self.server_public_key = None
        self.sock = None
        self.codename = None
        self.active = True
        self.receive_thread = None

    def _aes_encrypt(self, plaintext, key):
        """Encrypt data using AES-256-GCM"""
        iv = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
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
            return None

    def _rsa_encrypt(self, plaintext):
        """Encrypt data with server's public key"""
        try:
            ciphertext = self.server_public_key.encrypt(
                plaintext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return base64.b64encode(ciphertext).decode()
        except Exception as e:
            print(f"[-] RSA encryption error: {e}")
            return None

    def connect_and_authenticate(self, host, port, code_words):
        """Connect to server and authenticate"""
        try:
            # Connect to server
            print(f"[*] Connecting to {host}:{port}...")
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((host, port))
            print("[+] Connected to server")

            # Step 1: Receive server's public key
            public_key_pem = self.sock.recv(4096)
            self.server_public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
            print("[+] Received server public key")

            # Step 2: Generate session key
            self.session_key = os.urandom(32)  # 256-bit AES key

            # Step 3: Prepare authentication data
            auth_data = {
                'session_key': base64.b64encode(self.session_key).decode(),
                'code_words': [word.strip().upper() for word in code_words]
            }

            # Step 4: Encrypt with server's public key and send
            encrypted_auth = self._rsa_encrypt(json.dumps(auth_data).encode())
            if not encrypted_auth:
                print("[-] Failed to encrypt authentication data")
                return False

            self.sock.send(encrypted_auth.encode())
            print("[*] Authentication request sent...")

            # Step 5: Receive response
            encrypted_response = self.sock.recv(4096).decode()
            response = self._aes_decrypt(encrypted_response, self.session_key)

            if not response:
                print("[-] Failed to decrypt server response")
                return False

            response_data = json.loads(response)

            if response_data['status'] == 'SUCCESS':
                self.codename = response_data['codename']
                print(f"\n[+] {response_data['message']}")
                return True
            else:
                print(f"\n[-] Authentication failed: {response_data['message']}")
                return False

        except ConnectionRefusedError:
            print(f"[-] Connection refused. Is the server running at {host}:{port}?")
            return False
        except Exception as e:
            print(f"[-] Connection error: {e}")
            return False

    def send_message(self, message):
        """Send encrypted message to server"""
        try:
            encrypted_msg = self._aes_encrypt(message, self.session_key)
            self.sock.send(encrypted_msg.encode())
            return True
        except Exception as e:
            print(f"[-] Error sending message: {e}")
            self.active = False
            return False

    def receive_messages(self):
        """Continuously receive messages from server"""
        while self.active:
            try:
                encrypted_msg = self.sock.recv(4096).decode()
                if not encrypted_msg:
                    print("\n[*] Server disconnected")
                    self.active = False
                    break

                decrypted_msg = self._aes_decrypt(encrypted_msg, self.session_key)
                if not decrypted_msg:
                    print("\n[-] Decryption error")
                    self.active = False
                    break

                # Display message from server
                print(f"\r[SERVER]: {decrypted_msg}")
                print(f"[{self.codename}]> ", end='', flush=True)

            except Exception as e:
                if self.active:
                    print(f"\n[-] Receive error: {e}")
                self.active = False
                break

    def start_session(self):
        """Start interactive session with bidirectional communication"""
        print(f"""
╔═══════════════════════════════════════════╗
║      SECURE CHANNEL ESTABLISHED [{self.codename}]     ║
╚═══════════════════════════════════════════╝
Type your messages below. Type 'DISCONNECT' to exit.
""")

        # Start receive thread
        self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        self.receive_thread.start()

        # Main thread handles user input
        while self.active:
            try:
                message = input(f"[{self.codename}]> ").strip()

                if not self.active:
                    break

                if not message:
                    continue

                # Send message
                if not self.send_message(message):
                    break

                # Check for disconnect
                if message.upper() == 'DISCONNECT':
                    print("[*] Disconnecting...")
                    break

            except KeyboardInterrupt:
                print("\n[*] Sending disconnect...")
                self.send_message("DISCONNECT")
                break
            except EOFError:
                # Handle Ctrl+D
                break
            except Exception as e:
                print(f"[-] Input error: {e}")
                break

        # Cleanup
        self.active = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        print("[*] Connection closed")

def print_banner():
    """Print application banner"""
    banner = """
╔═══════════════════════════════════════════╗
║            NIGHTACTION CLIENT             ║
║        Secure Covert Communications       ║
╚═══════════════════════════════════════════╝
"""
    print(banner)

def main():
    print_banner()

    # Get target from user
    print("[*] Enter target server information")
    while True:
        target = input("Target (IP or domain): ").strip()
        if target:
            break
        print("[-] Target cannot be empty")

    # Parse target (handle port if provided)
    if ':' in target:
        host, port_str = target.rsplit(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            print("[-] Invalid port number, using default 7777")
            port = 7777
    else:
        host = target
        port = 7777

    # Get authentication code
    print("\n[*] Enter authentication code (4 words)")
    code_words = []
    for i in range(1, 5):
        while True:
            word = input(f"Word {i}: ").strip()
            if word:
                code_words.append(word)
                break
            print("[-] Word cannot be empty")

    print("\n" + "="*47)

    # Create client and connect
    client = NightActionClient()
    if client.connect_and_authenticate(host, port, code_words):
        client.start_session()
    else:
        print("[*] Connection terminated")

if __name__ == '__main__':
    main()
