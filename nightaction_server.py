#!/usr/bin/env python3
"""
NightAction Server - WebSocket Version
Secure authentication server for covert communications with Cloudflare compatibility
"""

import asyncio
import websockets
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
    def __init__(self, codename, address, session_key, websocket):
        self.codename = codename
        self.address = address
        self.session_key = session_key
        self.websocket = websocket
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
        self.sessions = {}  # websocket -> AgentSession
        self.sessions_lock = threading.Lock()
        self.selected_agent = None  # Currently selected agent websocket
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

    async def handle_client(self, websocket):
        """Handle individual client WebSocket connection"""
        # Get remote address - handle proxy scenarios
        try:
            remote_address = websocket.remote_address
            remote_ip = remote_address[0] if remote_address else "unknown"
            remote_port = remote_address[1] if remote_address else 0
        except:
            remote_ip = "proxied"
            remote_port = 0
            remote_address = (remote_ip, remote_port)

        print(f"\n[*] WebSocket connection from {remote_ip}:{remote_port}")
        session = None

        try:
            # Step 1: Send public key to client
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            try:
                await websocket.send(public_pem.decode())
            except Exception as e:
                print(f"[-] Error sending public key: {e}")
                raise

            # Step 2: Receive encrypted authentication data
            encrypted_auth = await websocket.recv()

            # Step 3: Decrypt with RSA private key
            decrypted_data = self._rsa_decrypt(encrypted_auth)
            if not decrypted_data:
                await websocket.send("AUTH_FAILED")
                return

            # Parse authentication data
            auth_data = json.loads(decrypted_data.decode())
            session_key = base64.b64decode(auth_data['session_key'])
            code_words = auth_data['code_words']

            # Step 4: Verify code
            codename = self.verify_code(code_words)

            if codename:
                # Create session
                session = AgentSession(codename, remote_address, session_key, websocket)

                with self.sessions_lock:
                    self.sessions[websocket] = session

                # Send encrypted welcome message
                welcome_msg = json.dumps({
                    'status': 'SUCCESS',
                    'message': f'Welcome {codename}',
                    'codename': codename
                })
                encrypted_welcome = self._aes_encrypt(welcome_msg, session_key)
                await websocket.send(encrypted_welcome)

                print(f"[+] Agent authenticated: {codename} from {remote_ip}")
                session.add_message("SYSTEM", f"{codename} connected")

                # Start send task
                send_task = asyncio.create_task(self._send_to_client(session))

                # Receive messages
                await self._receive_from_client(session)

                # Cancel send task when receive ends
                send_task.cancel()
                try:
                    await send_task
                except asyncio.CancelledError:
                    pass

            else:
                error_msg = json.dumps({
                    'status': 'FAILED',
                    'message': 'Invalid authentication code'
                })
                encrypted_error = self._aes_encrypt(error_msg, session_key)
                await websocket.send(encrypted_error)
                print(f"[-] Authentication failed from {remote_ip}")

        except websockets.exceptions.ConnectionClosed:
            pass
        except Exception as e:
            print(f"[-] Error handling client {remote_ip}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # Clean up session and purge chat history
            if session:
                session.active = False
                with self.sessions_lock:
                    if websocket in self.sessions:
                        print(f"\n[*] {session.codename} disconnected - PURGING CHAT HISTORY")
                        # Clear chat history (burn after reading)
                        session.chat_history.clear()
                        del self.sessions[websocket]
                        # If this was the selected agent, deselect
                        if self.selected_agent == websocket:
                            self.selected_agent = None

    async def _receive_from_client(self, session):
        """Receive messages from client"""
        while session.active:
            try:
                encrypted_msg = await session.websocket.recv()

                decrypted_msg = self._aes_decrypt(encrypted_msg, session.session_key)
                if not decrypted_msg:
                    break

                # Add to chat history
                session.add_message(session.codename, decrypted_msg)

                # Check for disconnect
                if decrypted_msg.strip().upper() == 'DISCONNECT':
                    goodbye_msg = f"Goodbye {session.codename}. Stay safe."
                    encrypted_goodbye = self._aes_encrypt(goodbye_msg, session.session_key)
                    await session.websocket.send(encrypted_goodbye)
                    break

            except websockets.exceptions.ConnectionClosed:
                break
            except Exception as e:
                break

        session.active = False

    async def _send_to_client(self, session):
        """Send queued messages to client"""
        while session.active:
            try:
                # Check queue with timeout
                try:
                    message = session.message_queue.get(timeout=0.1)
                except queue.Empty:
                    await asyncio.sleep(0.1)
                    continue

                # Encrypt and send
                encrypted_msg = self._aes_encrypt(message, session.session_key)
                await session.websocket.send(encrypted_msg)

                # Add to chat history
                session.add_message("SERVER", message)

            except websockets.exceptions.ConnectionClosed:
                break
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
            for idx, (websocket, session) in enumerate(self.sessions.items(), 1):
                duration = datetime.now() - session.connected_at
                duration_str = str(duration).split('.')[0]  # Remove microseconds

                marker = ">>>" if websocket == self.selected_agent else "   "
                print(f"{marker} {idx:<4} {session.codename:<15} {session.address[0]:<20} {duration_str:<20}")
                agents.append((idx, websocket, session))

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

    def _monitor_messages(self, displayed_count):
        """Background thread to display incoming messages in real-time"""
        import sys

        while self.ui_running:
            try:
                time.sleep(0.1)  # Check every 100ms

                if self.selected_agent and self.selected_agent in self.sessions:
                    session = self.sessions[self.selected_agent]

                    # Initialize message counter for this session if needed
                    if self.selected_agent not in displayed_count:
                        displayed_count[self.selected_agent] = len(session.chat_history)

                    # Display any new messages since last check
                    current_count = len(session.chat_history)
                    if current_count > displayed_count[self.selected_agent]:
                        # Move cursor to beginning of line and clear it
                        sys.stdout.write('\r\033[K')

                        # Display all new messages
                        for i in range(displayed_count[self.selected_agent], current_count):
                            timestamp, sender, message = session.chat_history[i]
                            if sender == session.codename:
                                print(f"[{timestamp}] {sender}: {message}")

                        # Update displayed count
                        displayed_count[self.selected_agent] = current_count

                        # Redraw prompt
                        sys.stdout.write(f"[{session.codename}]> ")
                        sys.stdout.flush()

            except Exception as e:
                pass

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

        # Track displayed messages per session
        displayed_count = {}

        # Start message monitoring thread
        monitor_thread = threading.Thread(target=self._monitor_messages, args=(displayed_count,), daemon=True)
        monitor_thread.start()

        while self.ui_running:
            try:
                # Show prompt based on current state
                if self.selected_agent and self.selected_agent in self.sessions:
                    session = self.sessions[self.selected_agent]
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
                                _, websocket, session = agents[num - 1]
                                self.selected_agent = websocket
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
        """Start the WebSocket server"""
        print(f"""
╔═══════════════════════════════════════════╗
║         NIGHTACTION SERVER ACTIVE         ║
║            (WebSocket Mode)               ║
╚═══════════════════════════════════════════╝
[*] Listening on ws://{self.host}:{self.port}
[*] Compatible with Cloudflare Proxy
[*] Type 'list' to see active agents
[*] Type 'select <num>' to talk to an agent
[*] Type 'quit' to shutdown
""")

        # Start WebSocket server in a separate thread
        async def websocket_server():
            async with websockets.serve(
                self.handle_client,
                self.host,
                self.port,
                ping_interval=30,
                ping_timeout=10
            ):
                await asyncio.Future()  # Run forever

        def run_websocket_server():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(websocket_server())

        ws_thread = threading.Thread(target=run_websocket_server, daemon=True)
        ws_thread.start()

        # Start UI in main thread
        try:
            self.user_interface()
        except KeyboardInterrupt:
            print("\n[*] Server shutting down...")
        finally:
            self.ui_running = False
            time.sleep(1)
            print("[*] Server stopped")

def main():
    import argparse

    parser = argparse.ArgumentParser(description='NightAction Server (WebSocket)')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=7777, help='Port to listen on')
    parser.add_argument('--db', default='nightaction.db', help='Database file path')

    args = parser.parse_args()

    server = NightActionServer(host=args.host, port=args.port, db_path=args.db)
    server.start()

if __name__ == '__main__':
    main()
