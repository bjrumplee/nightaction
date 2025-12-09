# NightAction Quick Start Guide

Get up and running in 5 minutes!

## Step 1: Install (30 seconds)

### Windows:
```bash
setup.bat
```

### Linux/Mac:
```bash
pip install -r requirements.txt
```

## Step 2: Start Server (1 minute)

Open a terminal and run:
```bash
python nightaction_server.py
```

You should see:
```
╔═══════════════════════════════════════════╗
║         NIGHTACTION SERVER ACTIVE         ║
╚═══════════════════════════════════════════╝
[*] Listening on 0.0.0.0:7777
```

**Leave this terminal open!**

## Step 3: Add an Agent (1 minute)

Open a **NEW** terminal and run:
```bash
python manage_agents.py
```

1. Select option `1` (Add new agent)
2. Enter codename: `OSPREY`
3. Enter 4 words:
   - Word 1: `PEN`
   - Word 2: `CLOCK`
   - Word 3: `DOOR`
   - Word 4: `FIRE`
4. Select option `6` to exit

## Step 4: Connect with Client (2 minutes)

Open a **NEW** terminal and run:
```bash
python nightaction_client.py
```

1. Enter target: `localhost` (or server IP)
2. Enter the 4 words:
   - Word 1: `PEN`
   - Word 2: `CLOCK`
   - Word 3: `DOOR`
   - Word 4: `FIRE`

You should see:
```
[+] Welcome OSPREY

╔═══════════════════════════════════════════╗
║      SECURE CHANNEL ESTABLISHED [OSPREY]     ║
╚═══════════════════════════════════════════╝
```

## Step 5: Test Bidirectional Communication! (2 minutes)

### On Client:
Type a message:
```
[OSPREY]> Status report requested
```

### On Server:
You'll see the message arrive. Now select the agent and reply:
```
SERVER> list
    1    OSPREY          192.168.1.50         0:00:30

SERVER> select 1
[OSPREY]> All systems operational. Ready for orders.
```

### On Client:
The message appears in real-time:
```
[OSPREY]>
[SERVER]: All systems operational. Ready for orders.
[OSPREY]> Acknowledged
```

### Both Ways:
Full two-way encrypted communication! Type `DISCONNECT` on client to exit.

**Security Feature:** When client disconnects, ALL chat history is purged from server memory.

## Remote Connection Setup

### On Server Machine:
1. Find your IP address:
   - Windows: `ipconfig`
   - Linux/Mac: `ifconfig` or `ip addr`

2. Start server (allow through firewall if prompted):
   ```bash
   python nightaction_server.py
   ```

### On Client Machine:
1. Run client:
   ```bash
   python nightaction_client.py
   ```

2. Enter server IP address when prompted:
   ```
   Target (IP or domain): 192.168.1.100
   ```

## Firewall Configuration

### Windows Firewall:
```powershell
netsh advfirewall firewall add rule name="NightAction" dir=in action=allow protocol=TCP localport=7777
```

### Linux (ufw):
```bash
sudo ufw allow 7777/tcp
```

### Linux (iptables):
```bash
sudo iptables -A INPUT -p tcp --dport 7777 -j ACCEPT
```

## Common Issues

### "Connection refused"
- Server not running → Start server first
- Wrong IP/port → Verify server IP with `ipconfig` or `ifconfig`
- Firewall blocking → Allow port 7777

### "Authentication failed"
- Wrong code → Double-check 4 words (case doesn't matter)
- Agent not added → Run `manage_agents.py` first
- Agent deactivated → Reactivate in manage_agents.py

### "Module not found"
- Dependencies not installed → Run `pip install -r requirements.txt`

## Security Reminder

🔒 **Everything is encrypted!**
- Authentication uses RSA-2048
- Messages use AES-256-GCM
- Codes stored as SHA-256 hashes
- No man-in-the-middle can decrypt your traffic

## What's Next?

- Read `README.md` for full documentation
- Add more agents with unique codes
- Customize the server logic for your use case
- Build standalone .exe files with PyInstaller

---

**Need help?** Check README.md for detailed troubleshooting and advanced features.
