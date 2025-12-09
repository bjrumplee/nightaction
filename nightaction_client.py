#!/usr/bin/env python3
"""
NightAction Client - WebSocket Version
Secure client for covert communications with Cloudflare compatibility
"""

import asyncio
import websockets
import json
import base64
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class NightActionClient:
    def __init__(self):
        self.session_key = None
        self.server_public_key = None
        self.websocket = None
        self.codename = None
        self.active = True

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

    async def connect_and_authenticate(self, uri, code_words):
        """Connect to server and authenticate via WebSocket"""
        try:
            # Connect to WebSocket server
            print(f"[*] Connecting to {uri}...")
            self.websocket = await websockets.connect(uri, ping_interval=30, ping_timeout=10)
            print("[+] WebSocket connected")

            # Step 1: Receive server's public key
            public_key_pem = await self.websocket.recv()
            self.server_public_key = serialization.load_pem_public_key(
                public_key_pem.encode(),
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

            await self.websocket.send(encrypted_auth)
            print("[*] Authentication request sent...")

            # Step 5: Receive response
            encrypted_response = await self.websocket.recv()
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

        except websockets.exceptions.WebSocketException as e:
            print(f"[-] WebSocket error: {e}")
            return False
        except Exception as e:
            print(f"[-] Connection error: {e}")
            return False

    async def send_message(self, message):
        """Send encrypted message to server"""
        try:
            encrypted_msg = self._aes_encrypt(message, self.session_key)
            await self.websocket.send(encrypted_msg)
            return True
        except Exception as e:
            print(f"[-] Error sending message: {e}")
            self.active = False
            return False

    async def receive_messages(self):
        """Continuously receive messages from server"""
        while self.active:
            try:
                encrypted_msg = await self.websocket.recv()

                decrypted_msg = self._aes_decrypt(encrypted_msg, self.session_key)
                if not decrypted_msg:
                    print("\n[-] Decryption error")
                    self.active = False
                    break

                # Display message from server
                print(f"\r[NIGHT ACTION]: {decrypted_msg}")
                print(f"[{self.codename}]> ", end='', flush=True)

            except websockets.exceptions.ConnectionClosed:
                print("\n[*] Server disconnected")
                self.active = False
                break
            except Exception as e:
                if self.active:
                    print(f"\n[-] Receive error: {e}")
                self.active = False
                break

    async def send_user_input(self):
        """Handle user input and send to server"""
        loop = asyncio.get_event_loop()

        while self.active:
            try:
                # Use run_in_executor to make input() non-blocking
                message = await loop.run_in_executor(None, input, f"[{self.codename}]> ")
                message = message.strip()

                if not self.active:
                    break

                if not message:
                    continue

                # Send message
                if not await self.send_message(message):
                    break

                # Check for disconnect
                if message.upper() == 'DISCONNECT':
                    print("[*] Disconnecting...")
                    break

            except EOFError:
                # Handle Ctrl+D
                break
            except Exception as e:
                print(f"[-] Input error: {e}")
                break

        self.active = False

    async def start_session(self):
        """Start interactive session with bidirectional communication"""
        print(f"""
╔═══════════════════════════════════════════╗
║      SECURE CHANNEL ESTABLISHED [{self.codename}]     ║
╚═══════════════════════════════════════════╝
Type your messages below. Type 'DISCONNECT' to exit.
""")

        # Create tasks for sending and receiving
        receive_task = asyncio.create_task(self.receive_messages())
        send_task = asyncio.create_task(self.send_user_input())

        # Wait for either task to complete
        done, pending = await asyncio.wait(
            [receive_task, send_task],
            return_when=asyncio.FIRST_COMPLETED
        )

        # Cancel pending tasks
        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # Cleanup
        self.active = False
        if self.websocket:
            try:
                await self.websocket.close()
            except:
                pass
        print("[*] Connection closed")

def print_banner():
    """Print application banner"""
    banner = """
╔═══════════════════════════════════════════╗
║            NIGHTACTION CLIENT             ║
║        Secure Covert Communications       ║
║            (WebSocket Mode)               ║
╚═══════════════════════════════════════════╝
"""
    print(banner)

async def main():
    print_banner()

    # Get target from user
    print("[*] Enter target server information")
    while True:
        target = input("Target (domain or IP): ").strip()
        if target:
            break
        print("[-] Target cannot be empty")

    # Parse target and build WebSocket URI
    if target.startswith('ws://') or target.startswith('wss://'):
        # Full URI provided
        uri = target
    else:
        # Just domain/IP provided - build URI
        if ':' in target:
            # Port specified
            host, port = target.rsplit(':', 1)
            # Assume wss:// for domains, ws:// for localhost/IPs
            if 'localhost' in host or host.startswith('192.168.') or host.startswith('10.') or host.startswith('127.'):
                protocol = 'ws'
            else:
                protocol = 'wss'  # Use secure WebSocket for domains (Cloudflare)
            uri = f"{protocol}://{host}:{port}"
        else:
            # No port - use default 7777
            # Assume wss:// for domains, ws:// for localhost/IPs
            if 'localhost' in target or target.startswith('192.168.') or target.startswith('10.') or target.startswith('127.'):
                protocol = 'ws'
                uri = f"{protocol}://{target}:7777"
            else:
                protocol = 'wss'  # Use secure WebSocket for domains
                uri = f"{protocol}://{target}"

    print(f"[*] Using WebSocket URI: {uri}")

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
    if await client.connect_and_authenticate(uri, code_words):
        await client.start_session()
    else:
        print("[*] Connection terminated")

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")
