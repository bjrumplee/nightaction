#!/usr/bin/env python3
"""
NightAction Server
Secure authentication server for covert communications with multi-agent support
"""

import socket
import threading
import json
import base64
import sqlite3
import hashlib
import os
import queue
import time
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class AgentSession:
    """Represents an active agent connection"""
    def __init__(self, codename, address, session_key, client_socket):
        self.codename = codename
        self.address = address
        self.session_key = session_key
        self.client_socket = client_socket
        self.message_queue = queue.Queue()  # Server->client messages
        self.chat_history = []  # List of tuples: (timestamp, sender, message)
        self.connected_at = datetime.now()
        self.active = True

    def add_message(self, sender, message):
        """Add message to chat history"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.chat_history.append((timestamp, sender, message))

class NightActionServer:
    def __init__(self, host='0.0.0.0', port=7777, db_path='nightaction.db'):
        self.host = host
        self.port = port
        self.db_path = db_path
        self.sessions = {}  # address -> AgentSession
        self.sessions_lock = threading.Lock()
        self.selected_agent = None  # Currently selected agent address
        self.ui_running = True

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
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

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
            cursor.execute(
                'UPDATE agents SET last_used = CURRENT_TIMESTAMP WHERE code_hash = ?',
                (code_hash,)
            )
            conn.commit()

        conn.close()
        return result[0] if result else None

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
            return None

    def handle_client(self, client_socket, address):
        """Handle individual client connection"""
        print(f"\n[*] Connection from {address[0]}:{address[1]}")
        session = None

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

            # Parse authentication data
            auth_data = json.loads(decrypted_data.decode())
            session_key = base64.b64decode(auth_data['session_key'])
            code_words = auth_data['code_words']

            # Step 4: Verify code
            codename = self.verify_code(code_words)

            if codename:
                # Create session
                session = AgentSession(codename, address, session_key, client_socket)

                with self.sessions_lock:
                    self.sessions[address] = session

                # Send encrypted welcome message
                welcome_msg = json.dumps({
                    'status': 'SUCCESS',
                    'message': f'Welcome {codename}',
                    'codename': codename
                })
                encrypted_welcome = self._aes_encrypt(welcome_msg, session_key)
                client_socket.send(encrypted_welcome.encode())

                print(f"[+] Agent authenticated: {codename} from {address[0]}")
                session.add_message("SYSTEM", f"{codename} connected")

                # Start threads for this client
                receive_thread = threading.Thread(
                    target=self._receive_from_client,
                    args=(session,),
                    daemon=True
                )
                send_thread = threading.Thread(
                    target=self._send_to_client,
                    args=(session,),
                    daemon=True
                )

                receive_thread.start()
                send_thread.start()

                # Keep connection alive
                receive_thread.join()

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
            # Clean up session and purge chat history
            if session:
                session.active = False
                with self.sessions_lock:
                    if address in self.sessions:
                        print(f"\n[*] {session.codename} disconnected - PURGING CHAT HISTORY")
                        # Clear chat history (burn after reading)
                        session.chat_history.clear()
                        del self.sessions[address]
                        # If this was the selected agent, deselect
                        if self.selected_agent == address:
                            self.selected_agent = None

            try:
                client_socket.close()
            except:
                pass

    def _receive_from_client(self, session):
        """Receive messages from client"""
        while session.active:
            try:
                encrypted_msg = session.client_socket.recv(4096).decode()
                if not encrypted_msg:
                    break

                decrypted_msg = self._aes_decrypt(encrypted_msg, session.session_key)
                if not decrypted_msg:
                    break

                # Add to chat history
                session.add_message(session.codename, decrypted_msg)

                # Check for disconnect
                if decrypted_msg.strip().upper() == 'DISCONNECT':
                    goodbye_msg = f"Goodbye {session.codename}. Stay safe."
                    encrypted_goodbye = self._aes_encrypt(goodbye_msg, session.session_key)
                    session.client_socket.send(encrypted_goodbye.encode())
                    break

            except Exception as e:
                break

        session.active = False

    def _send_to_client(self, session):
        """Send queued messages to client"""
        while session.active:
            try:
                # Wait for message in queue (with timeout to check active status)
                try:
                    message = session.message_queue.get(timeout=0.5)
                except queue.Empty:
                    continue

                # Encrypt and send
                encrypted_msg = self._aes_encrypt(message, session.session_key)
                session.client_socket.send(encrypted_msg.encode())

                # Add to chat history
                session.add_message("SERVER", message)

            except Exception as e:
                break

    def list_active_agents(self):
        """List all active agents"""
        with self.sessions_lock:
            if not self.sessions:
                print("\n[*] No active agents")
                return []

            print("\n" + "="*70)
            print(f"{'#':<4} {'CODENAME':<15} {'IP ADDRESS':<20} {'CONNECTED':<20}")
            print("="*70)

            agents = []
            for idx, (address, session) in enumerate(self.sessions.items(), 1):
                duration = datetime.now() - session.connected_at
                duration_str = str(duration).split('.')[0]  # Remove microseconds

                marker = ">>>" if address == self.selected_agent else "   "
                print(f"{marker} {idx:<4} {session.codename:<15} {address[0]:<20} {duration_str:<20}")
                agents.append((idx, address, session))

            print("="*70 + "\n")
            return agents

    def display_chat(self, session):
        """Display chat history for selected agent"""
        print("\n" + "="*70)
        print(f"CONVERSATION WITH {session.codename} ({session.address[0]})")
        print("="*70)

        if not session.chat_history:
            print("[No messages yet]")
        else:
            for timestamp, sender, message in session.chat_history:
                if sender == "SYSTEM":
                    print(f"[{timestamp}] *** {message} ***")
                elif sender == "SERVER":
                    print(f"[{timestamp}] YOU: {message}")
                else:
                    print(f"[{timestamp}] {sender}: {message}")

        print("="*70)
        print("Commands: 'back' to return | 'list' to show agents | Type message to send")
        print("="*70 + "\n")

    def user_interface(self):
        """Interactive UI for server operator"""
        print("\n" + "="*70)
        print("SERVER CONTROL PANEL")
        print("="*70)
        print("Commands:")
        print("  list          - Show active agents")
        print("  select <num>  - Select agent to communicate with")
        print("  back          - Return to main menu")
        print("  quit          - Shutdown server")
        print("="*70 + "\n")

        while self.ui_running:
            try:
                # Show prompt based on current state
                if self.selected_agent and self.selected_agent in self.sessions:
                    session = self.sessions[self.selected_agent]

                    # Check for new messages
                    if session.chat_history:
                        last_msg = session.chat_history[-1]
                        if last_msg[1] == session.codename:
                            # New message from agent - display it
                            timestamp, sender, message = last_msg
                            print(f"\r[{timestamp}] {sender}: {message}")

                    user_input = input(f"[{session.codename}]> ").strip()

                    if user_input.lower() == 'back':
                        self.selected_agent = None
                        print("\n[*] Returned to main menu\n")
                        continue
                    elif user_input.lower() == 'list':
                        self.list_active_agents()
                        continue
                    elif user_input:
                        # Send message to selected agent
                        session.message_queue.put(user_input)
                else:
                    user_input = input("SERVER> ").strip()

                    if user_input.lower() == 'list':
                        self.list_active_agents()

                    elif user_input.lower().startswith('select '):
                        try:
                            num = int(user_input.split()[1])
                            agents = self.list_active_agents()

                            if 1 <= num <= len(agents):
                                _, address, session = agents[num - 1]
                                self.selected_agent = address
                                self.display_chat(session)
                            else:
                                print(f"[-] Invalid agent number: {num}")
                        except (ValueError, IndexError):
                            print("[-] Usage: select <number>")

                    elif user_input.lower() == 'quit':
                        print("\n[*] Shutting down server...")
                        self.ui_running = False
                        break

                    elif user_input:
                        print("[-] Unknown command. Type 'list' to see agents or 'select <num>' to talk to an agent")

            except KeyboardInterrupt:
                print("\n[*] Use 'quit' to shutdown or 'back' to return to menu")
            except Exception as e:
                print(f"[-] Error: {e}")

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
[*] Type 'list' to see active agents
[*] Type 'select <num>' to talk to an agent
[*] Type 'quit' to shutdown
""")

        # Start network listener thread
        def accept_connections():
            while self.ui_running:
                try:
                    server_socket.settimeout(1.0)
                    try:
                        client_socket, address = server_socket.accept()
                        client_thread = threading.Thread(
                            target=self.handle_client,
                            args=(client_socket, address),
                            daemon=True
                        )
                        client_thread.start()
                    except socket.timeout:
                        continue
                except Exception as e:
                    if self.ui_running:
                        print(f"[-] Accept error: {e}")
            server_socket.close()

        network_thread = threading.Thread(target=accept_connections, daemon=True)
        network_thread.start()

        # Start UI in main thread
        try:
            self.user_interface()
        except KeyboardInterrupt:
            print("\n[*] Server shutting down...")
        finally:
            self.ui_running = False
            time.sleep(1)  # Give threads time to cleanup
            print("[*] Server stopped")

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
