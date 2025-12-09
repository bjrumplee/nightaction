# NightAction

Secure covert communications system with encrypted client-server authentication.

**🚀 Now with WebSocket support for Cloudflare compatibility!**

## Features

- **Military-grade encryption**: RSA-2048 + AES-256-GCM hybrid encryption
- **Zero-knowledge authentication**: Server never stores plaintext codes (SHA-256 hashed)
- **Man-in-the-middle protection**: Public key cryptography prevents packet decryption
- **Secure session management**: Unique session keys per connection
- **Codename-based authentication**: 4-word authentication codes like "Pen Clock Door Fire"
- **Bidirectional communication**: Full two-way encrypted messaging between server and clients
- **Multi-agent support**: Server handles multiple simultaneous connections
- **Agent selection UI**: Choose which agent to communicate with in real-time
- **Session-based chat history**: View full conversation logs while connected
- **Auto-purge on disconnect**: All chat history permanently deleted when client disconnects ("burn after reading")
- **WebSocket transport**: Works through Cloudflare proxy, NGINX, and firewalls
- **Cloudflare compatible**: DDoS protection, IP hiding, and global CDN support

## Security Architecture

1. **Key Exchange**: Client receives server's RSA public key
2. **Authentication**: Client generates AES session key, encrypts it + 4-word code with RSA
3. **Verification**: Server decrypts, hashes code, validates against database
4. **Secure Channel**: All subsequent communication encrypted with AES-256-GCM
5. **Zero Storage**: Codes stored as SHA-256 hashes, never plaintext

### Why This Is Secure

- **RSA encryption**: Session key and authentication encrypted with 2048-bit RSA (industry standard)
- **AES-GCM encryption**: All messages encrypted with 256-bit AES in GCM mode (authenticated encryption)
- **Perfect Forward Secrecy**: Each session has unique AES key; compromising one session doesn't affect others
- **No plaintext transmission**: Everything after initial handshake is encrypted
- **Hash-based verification**: Codes stored as SHA-256 hashes; even database breach doesn't reveal codes

## Installation

### Prerequisites

- Python 3.7 or higher
- pip

### Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

That's it! Python and cryptography library are all you need.

## Usage

### 1. Start the Server

On the server machine:

```bash
python nightaction_server.py
```

Options:
- `--host 0.0.0.0` - Host to bind to (default: 0.0.0.0 for all interfaces)
- `--port 7777` - Port to listen on (default: 7777)
- `--db nightaction.db` - Database file path (default: nightaction.db)

Example:
```bash
python nightaction_server.py --host 0.0.0.0 --port 8888
```

The server will:
- Generate RSA key pair (saved as `server_private.pem` and `server_public.pem`)
- Initialize SQLite database
- Start listening for connections

### 2. Manage Agents

Before clients can connect, you need to add authorized agents:

```bash
python manage_agents.py
```

This opens an interactive menu:
1. **Add new agent** - Create new codename + 4-word code
2. **List all agents** - View all registered agents
3. **Deactivate agent** - Disable access without deleting
4. **Activate agent** - Re-enable deactivated agent
5. **Delete agent** - Permanently remove agent

Example session:
```
Select option: 1

[*] Add New Agent
Codename: OSPREY
Enter 4-word authentication code:
  Word 1: PEN
  Word 2: CLOCK
  Word 3: DOOR
  Word 4: FIRE

[+] Agent added successfully: OSPREY
    Code: PEN CLOCK DOOR FIRE
```

### 3. Connect with Client

On the client machine:

```bash
python nightaction_client.py
```

The client will prompt for:
1. **Target**: Server IP or domain (e.g., `192.168.1.100` or `server.example.com:7777`)
2. **4-word code**: Authentication code (e.g., PEN, CLOCK, DOOR, FIRE)

Example session:
```
╔═══════════════════════════════════════════╗
║            NIGHTACTION CLIENT             ║
║        Secure Covert Communications       ║
╚═══════════════════════════════════════════╝

[*] Enter target server information
Target (IP or domain): 192.168.1.100

[*] Enter authentication code (4 words)
Word 1: PEN
Word 2: CLOCK
Word 3: DOOR
Word 4: FIRE

===============================================
[*] Connecting to 192.168.1.100:7777...
[+] Connected to server
[+] Received server public key
[*] Authentication request sent...

[+] Welcome OSPREY

╔═══════════════════════════════════════════╗
║      SECURE CHANNEL ESTABLISHED [OSPREY]     ║
╚═══════════════════════════════════════════╝
Type your messages below. Type 'DISCONNECT' to exit.

[OSPREY]> Status report
[SERVER]: All systems operational
[OSPREY]> DISCONNECT
[SERVER]: Goodbye OSPREY. Stay safe.
[*] Connection closed
```

## Server Multi-Agent Operation

The server supports simultaneous communication with multiple agents:

```
SERVER> list
======================================================================
#    CODENAME        IP ADDRESS           CONNECTED
======================================================================
    1    OSPREY          192.168.1.50         0:05:23
    2    FALCON          192.168.1.51         0:02:15
======================================================================

SERVER> select 1
======================================================================
CONVERSATION WITH OSPREY (192.168.1.50)
======================================================================
[14:23:15] *** OSPREY connected ***
[14:23:20] OSPREY: Mission status?
[14:23:25] YOU: Proceed as planned
======================================================================

[OSPREY]> Copy that, moving to position
[OSPREY]> back

SERVER> select 2
[FALCON]> Support team, status report?
```

**Security Note:** When an agent disconnects, ALL chat history is immediately purged from memory. This "burn after reading" feature ensures no forensic recovery of conversations.

## Cloudflare Deployment

NightAction uses **WebSocket transport** and works seamlessly through Cloudflare's proxy:

**Client connects via:**
```
wss://nightaction.yourdomain.com
```

**Setup:**
1. Enable Cloudflare proxy (orange cloud) for your domain
2. Configure NGINX to proxy WebSocket connections
3. Set Cloudflare SSL mode to "Flexible"
4. Deploy and enjoy DDoS protection + IP hiding

**See `CLOUDFLARE_SETUP.md` for complete guide.**

**Security:** Even with Cloudflare proxy, all messages are **end-to-end encrypted** (RSA + AES-256). Cloudflare only sees encrypted WebSocket frames, not message content.

## File Structure

```
nightaction/
├── nightaction_server.py    # Server application (WebSocket)
├── nightaction_client.py    # Client application (WebSocket)
├── manage_agents.py         # Agent management utility
├── requirements.txt         # Python dependencies
├── README.md               # This file
├── CLOUDFLARE_SETUP.md     # Cloudflare deployment guide
├── USAGE_GUIDE.md          # Operational manual
├── QUICK_START.md          # 5-minute setup guide
├── nightaction.db          # SQLite database (generated)
├── server_private.pem      # Server RSA private key (generated)
└── server_public.pem       # Server RSA public key (generated)
```

## Security Notes

### Key Management

- **Server keys**: `server_private.pem` and `server_public.pem` are generated on first run
- **Keep private key secure**: Never share `server_private.pem`
- **Backup keys**: If you lose the private key, you'll need to regenerate and redistribute

### Database Security

- Codes are stored as SHA-256 hashes, not plaintext
- Even if database is compromised, codes cannot be recovered
- Keep `nightaction.db` secure to prevent unauthorized agent list access

### Network Security

- Use firewall rules to restrict access to server port
- Consider running over VPN for additional security layer
- Monitor server logs for suspicious authentication attempts

### Operational Security

- Destroy codes securely after memorization
- Change codes regularly
- Deactivate compromised agents immediately
- Use strong, random 4-word combinations

## Customization

### Changing Encryption Parameters

Edit the key sizes in the code:
- RSA: `key_size=2048` (can increase to 4096 for more security, but slower)
- AES: `os.urandom(32)` for 256-bit key (32 bytes)

### Adding Custom Commands

Modify the `_secure_communication()` method in `nightaction_server.py`:

```python
if decrypted_msg.strip().upper() == 'STATUS':
    response = "All systems operational"
    encrypted_response = self._aes_encrypt(response, session_key)
    client_socket.send(encrypted_response.encode())
```

## Troubleshooting

### Connection Refused

- Check if server is running
- Verify firewall allows connections on the port
- Confirm IP address and port are correct

### Authentication Failed

- Verify code is correct (case-insensitive)
- Check if agent is active: `python manage_agents.py` → option 2
- Ensure server database has the agent registered

### Decryption Errors

- May indicate man-in-the-middle attack or network corruption
- Disconnect immediately and verify server authenticity
- Check for network issues or proxies interfering

## Building Standalone Executables

To create .exe files (Windows) or standalone binaries:

### Using PyInstaller

```bash
pip install pyinstaller

# Build client
pyinstaller --onefile --name NightActionClient nightaction_client.py

# Build server
pyinstaller --onefile --name NightActionServer nightaction_server.py

# Build manager
pyinstaller --onefile --name NightActionManager manage_agents.py
```

Executables will be in the `dist/` folder.

## License

This is a custom security tool. Use responsibly and only for authorized purposes.

## Credits

Inspired by "The Night Agent" TV series.
