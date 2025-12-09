# NightAction Usage Guide

Complete guide for operating the NightAction secure communications system.

## Server Operation

### Starting the Server

```bash
python3 nightaction_server.py
```

You'll see:
```
╔═══════════════════════════════════════════╗
║         NIGHTACTION SERVER ACTIVE         ║
╚═══════════════════════════════════════════╝
[*] Listening on 0.0.0.0:7777
[*] Type 'list' to see active agents
[*] Type 'select <num>' to talk to an agent
[*] Type 'quit' to shutdown

SERVER>
```

### Server Commands

| Command | Description |
|---------|-------------|
| `list` | Show all active agents with their connection status |
| `select <num>` | Select an agent to communicate with |
| `back` | Return to main menu (when in conversation) |
| `quit` | Shutdown server gracefully |

### Managing Multiple Agents

#### 1. List Active Agents

Type `list` at the `SERVER>` prompt:

```
======================================================================
#    CODENAME        IP ADDRESS           CONNECTED
======================================================================
    1    OSPREY          192.168.1.50         0:05:23
    2    FALCON          192.168.1.51         0:02:15
>>> 3    EAGLE           192.168.1.52         0:00:45
======================================================================
```

The `>>>` marker shows which agent is currently selected.

#### 2. Select an Agent

To talk to an agent, use `select <number>`:

```
SERVER> select 1
```

This displays the conversation history and switches to that agent's chat:

```
======================================================================
CONVERSATION WITH OSPREY (192.168.1.50)
======================================================================
[14:23:15] *** OSPREY connected ***
[14:23:20] OSPREY: Status report
[14:23:25] YOU: All systems operational
[14:25:10] OSPREY: Requesting extraction coordinates
======================================================================
Commands: 'back' to return | 'list' to show agents | Type message to send
======================================================================

[OSPREY]>
```

#### 3. Send Messages

While an agent is selected, just type your message:

```
[OSPREY]> Coordinates: 40.7128 N, 74.0060 W
```

The message is encrypted and sent immediately. It also appears in the chat history.

#### 4. Switch Between Agents

Type `list` to see all agents, then `select <num>` to switch:

```
[OSPREY]> list

======================================================================
#    CODENAME        IP ADDRESS           CONNECTED
======================================================================
>>> 1    OSPREY          192.168.1.50         0:10:45
    2    FALCON          192.168.1.51         0:07:32
======================================================================

[OSPREY]> select 2

======================================================================
CONVERSATION WITH FALCON (192.168.1.51)
======================================================================
[14:20:30] *** FALCON connected ***
[14:21:00] FALCON: Ready for orders
======================================================================

[FALCON]>
```

#### 5. Return to Main Menu

Type `back` to deselect the current agent:

```
[OSPREY]> back

[*] Returned to main menu

SERVER>
```

### Chat History & Auto-Purge

**Important Security Feature:**

- Chat history is stored **in memory only** during the session
- When an agent disconnects, **all chat history is PURGED immediately**
- This implements "burn after reading" - conversations are not recoverable
- No logs are written to disk

Example of auto-purge:
```
[OSPREY]> This is sensitive information

[*] OSPREY disconnected - PURGING CHAT HISTORY

SERVER>
```

All messages exchanged with OSPREY are now permanently deleted.

### Handling Disconnections

If the agent you're talking to disconnects:

```
[OSPREY]> select 1

======================================================================
CONVERSATION WITH OSPREY (192.168.1.50)
======================================================================
[14:23:15] *** OSPREY connected ***
[14:23:20] OSPREY: Message here
======================================================================

[OSPREY]> Response message

[*] OSPREY disconnected - PURGING CHAT HISTORY

SERVER>
```

You're automatically returned to the main menu, and all conversation history is purged.

## Client Operation

### Connecting to Server

```bash
python3 nightaction_client.py
```

Enter server details and authentication code:

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

[OSPREY]>
```

### Sending and Receiving Messages

The client supports **full bidirectional communication**:

#### Send a message:
```
[OSPREY]> Status report requested
```

#### Receive messages from server:
```
[OSPREY]>
[SERVER]: All systems operational. Proceed with mission.
[OSPREY]> Acknowledged
```

Messages from the server appear in real-time, even while you're typing.

### Disconnecting

Type `DISCONNECT` or press `Ctrl+C`:

```
[OSPREY]> DISCONNECT
[*] Disconnecting...
[SERVER]: Goodbye OSPREY. Stay safe.
[*] Connection closed
```

## Example Scenarios

### Scenario 1: Single Agent Communication

**Server:**
```
SERVER> list
    1    OSPREY          192.168.1.50         0:01:00

SERVER> select 1
[OSPREY]> What's your status?
```

**Client (OSPREY):**
```
[OSPREY]>
[SERVER]: What's your status?
[OSPREY]> Mission accomplished. Returning to base.
```

**Server:**
```
[OSPREY]>
[14:25:30] OSPREY: Mission accomplished. Returning to base.
[OSPREY]> Excellent work. See you soon.
```

### Scenario 2: Multiple Agents

**Server manages 3 agents simultaneously:**

```
SERVER> list
    1    OSPREY          192.168.1.50         0:05:00
    2    FALCON          192.168.1.51         0:03:00
    3    EAGLE           192.168.1.52         0:01:00

SERVER> select 1
[OSPREY]> Team leader, report status
[OSPREY]> back

SERVER> select 2
[FALCON]> Support team, are you in position?
[FALCON]> back

SERVER> select 3
[EAGLE]> Recon team, what do you see?
```

Each agent receives only their messages. Complete isolation between agents.

### Scenario 3: Auto-Purge Security

**Server has sensitive conversation:**
```
SERVER> select 1
[OSPREY]> The package is at location: 40.7128 N, 74.0060 W
[OSPREY]> Mission code is: ALPHA-7-TANGO
[OSPREY]> Extract at 0300 hours

[*] OSPREY disconnected - PURGING CHAT HISTORY
```

**All sensitive information is now permanently deleted.** No recovery possible.

## Security Best Practices

### For Server Operators:

1. **Monitor Connections**: Use `list` regularly to see who's connected
2. **Verify Identity**: Confirm codenames before sharing sensitive info
3. **Purge Awareness**: Remember that disconnecting purges all history
4. **Network Security**: Run behind firewall, limit port access
5. **Physical Security**: Secure the server machine physically

### For Clients:

1. **Memorize Codes**: Don't write down your 4-word authentication code
2. **Verify Server**: Ensure you're connecting to the correct IP
3. **Secure Environment**: Use in private, secure locations
4. **Clean Disconnect**: Always use `DISCONNECT` command
5. **No Screenshots**: Avoid capturing sensitive communications

## Advanced Tips

### Running Server in Background (Linux)

```bash
# Using screen
screen -S nightaction
python3 nightaction_server.py
# Press Ctrl+A, then D to detach

# Reattach later
screen -r nightaction
```

### Running as systemd Service (Linux)

Create `/etc/systemd/system/nightaction.service`:

```ini
[Unit]
Description=NightAction Secure Server
After=network.target

[Service]
Type=simple
User=yourusername
WorkingDirectory=/path/to/nightaction
ExecStart=/usr/bin/python3 nightaction_server.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable nightaction
sudo systemctl start nightaction
```

### Port Forwarding for Remote Access

If server is behind NAT, forward port 7777:

**Router:**
- External port: 7777
- Internal IP: 192.168.1.100 (your server)
- Internal port: 7777
- Protocol: TCP

**Client connects to:**
- Your public IP address: `203.0.113.50:7777`

### Using Custom Ports

**Server:**
```bash
python3 nightaction_server.py --port 8888
```

**Client:**
```
Target (IP or domain): 192.168.1.100:8888
```

## Troubleshooting

### "No active agents" when selecting

The agent disconnected between when you ran `list` and `select`. Run `list` again.

### Messages not appearing in real-time

Check network connectivity. The system uses TCP, so any network interruption will cause issues.

### Chat history seems empty

Chat history starts when the agent connects. Messages before `select` was called are still visible in history.

### Agent won't disconnect cleanly

If `DISCONNECT` doesn't work:
- Server: Type `back` to deselect, then the agent can disconnect
- Client: Press `Ctrl+C`

### Can't see multiple agents

Each connection is isolated. Run `list` on the server to see all connected agents.

## Performance Notes

- **Concurrent Agents**: Server handles multiple agents simultaneously (tested with 50+)
- **Message Size**: Max 4096 bytes per message (encrypted)
- **Latency**: Sub-second for local network, depends on internet for remote
- **Memory**: ~1-2MB per active agent (includes chat history)

## What Gets Logged vs Purged

### ✅ Logged (Persistent):

- Agent registration (in database)
- Last authentication time (in database)
- Server startup/shutdown events (console only)

### ❌ Purged (Temporary):

- **All chat messages** (deleted on disconnect)
- Session keys (memory only)
- IP addresses of connected clients (memory only)
- Connection timestamps (memory only)

This ensures **zero forensic trail** of conversations.
