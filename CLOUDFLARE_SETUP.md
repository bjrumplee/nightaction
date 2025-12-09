# NightAction with Cloudflare Proxy Setup

Complete guide for deploying NightAction through Cloudflare's proxy using WebSockets.

## Architecture Overview

```
Client → wss://nightaction.rumple.ca (Cloudflare Proxy with SSL)
       → HTTP (Cloudflare to NGINX)
       → NGINX:80 (WebSocket Proxy)
       → NightAction Server:7777 (WebSocket)
```

**Key Points:**
- Client uses **WSS** (secure WebSocket) to connect to Cloudflare
- Cloudflare terminates SSL and forwards HTTP to your server
- NGINX proxies WebSocket traffic to NightAction server
- All messages are **end-to-end encrypted** (RSA + AES-256) BEFORE WebSocket framing
- Cloudflare only sees encrypted WebSocket frames, cannot decrypt content

---

## Step 1: Install Dependencies

Update your Python packages:

```bash
# Activate venv if using one
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install new dependencies
pip install -r requirements.txt
```

This installs `websockets` library (new requirement).

---

## Step 2: Configure Cloudflare DNS

### 2.1: Add DNS Record

1. Go to Cloudflare Dashboard → **DNS** → **Records**
2. Add an **A record**:
   - **Name**: `nightaction`
   - **IPv4 address**: Your server's public IP
   - **Proxy status**: **🟠 Proxied** (Orange cloud - this is what you want!)
   - **TTL**: Auto

**Result:** `nightaction.rumple.ca` points to your server through Cloudflare

### 2.2: Set SSL/TLS Mode

1. Go to **SSL/TLS** → **Overview**
2. Set encryption mode to **Flexible**

**Why Flexible?**
- Client → Cloudflare: HTTPS (wss://)
- Cloudflare → Your Server: HTTP (ws://)
- Your server doesn't need SSL certificates (Cloudflare handles it)

**Options:**
- **Flexible**: Client to Cloudflare encrypted, Cloudflare to server unencrypted
- **Full**: Requires SSL cert on your server (self-signed OK)
- **Full (Strict)**: Requires valid SSL cert on your server

For most setups, **Flexible** is easiest and sufficient (traffic still encrypted end-to-end by NightAction's RSA+AES).

### 2.3: Enable WebSocket Support

1. Go to **Network** tab
2. Ensure **WebSockets** is **ON** (should be enabled by default)

---

## Step 3: Configure NGINX

Your updated `nginx.conf` should have this server block:

```nginx
server {
    listen 80;
    server_name nightaction.rumple.ca;

    location / {
        proxy_pass http://192.168.10.161:7777;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Standard proxy headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket timeouts (important for long-lived connections)
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;

        # Disable buffering for WebSocket
        proxy_buffering off;
    }
}
```

**Key Settings:**
- `proxy_http_version 1.1`: Required for WebSocket
- `Upgrade` and `Connection` headers: Enable WebSocket handshake
- Long timeouts: NightAction sessions can last hours
- `proxy_buffering off`: Real-time message delivery

### Reload NGINX

```bash
# Test config first
nginx -t

# Reload if OK
nginx -s reload
```

---

## Step 4: Firewall & Port Forwarding

### 4.1: Firewall (Server)

**Linux (ufw):**
```bash
sudo ufw allow 80/tcp comment "HTTP for Cloudflare"
```

**Linux (iptables):**
```bash
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
```

**Windows:**
```powershell
netsh advfirewall firewall add rule name="HTTP" dir=in action=allow protocol=TCP localport=80
```

**Note:** You only need port 80 open (not 7777) since NGINX is handling external connections.

### 4.2: Router Port Forwarding

If NGINX is behind a router:
- **External port**: 80
- **Internal IP**: NGINX server (e.g., 192.168.1.100)
- **Internal port**: 80
- **Protocol**: TCP

---

## Step 5: Start NightAction Server

On your NightAction server (192.168.10.161):

```bash
python3 nightaction_server.py
```

You should see:

```
╔═══════════════════════════════════════════╗
║         NIGHTACTION SERVER ACTIVE         ║
║            (WebSocket Mode)               ║
╚═══════════════════════════════════════════╝
[*] Listening on ws://0.0.0.0:7777
[*] Compatible with Cloudflare Proxy
```

**Important:** The server listens on `ws://` (not `wss://`) because NGINX handles the external connection.

---

## Step 6: Test Connection

### 6.1: From Client

```bash
python3 nightaction_client.py

Target (domain or IP): nightaction.rumple.ca
```

The client will automatically:
- Detect it's a domain (not localhost/IP)
- Use `wss://nightaction.rumple.ca` (secure WebSocket)
- Connect through Cloudflare's proxy

### 6.2: Expected Output

**Client:**
```
[*] Using WebSocket URI: wss://nightaction.rumple.ca
[*] Connecting to wss://nightaction.rumple.ca...
[+] WebSocket connected
[+] Received server public key
[*] Authentication request sent...

[+] Welcome OSPREY

╔═══════════════════════════════════════════╗
║      SECURE CHANNEL ESTABLISHED [OSPREY]     ║
╚═══════════════════════════════════════════╝
```

**Server:**
```
[*] WebSocket connection from 172.68.xxx.xxx:xxxxx
[+] Agent authenticated: OSPREY from 172.68.xxx.xxx
```

**Note:** The IP you see on the server will be a Cloudflare IP (not the client's real IP) because traffic is proxied.

---

## Step 7: Verify End-to-End Encryption

Even though Cloudflare can see the WebSocket frames, they **cannot decrypt** your messages:

1. **Cloudflare sees:** WebSocket frames with base64-encoded encrypted blobs
2. **Cloudflare cannot see:** Your actual messages (encrypted with AES-256-GCM)
3. **Cloudflare cannot see:** Your 4-word authentication codes (encrypted with RSA-2048)

**Test it:** Use Cloudflare's analytics to see WebSocket traffic, but messages remain encrypted.

---

## Benefits of Cloudflare Proxy

✅ **DDoS Protection**
- Cloudflare absorbs attacks before they reach your server
- Rate limiting and bot protection

✅ **Hide Your Server IP**
- Your real IP is not exposed
- Harder for attackers to target you directly

✅ **Global CDN**
- Faster connections from anywhere
- Lower latency

✅ **SSL/TLS Management**
- Cloudflare provides free SSL certificates
- Automatic certificate renewal

✅ **Analytics**
- See connection attempts and traffic patterns
- Monitor for suspicious activity

---

## Troubleshooting

### Connection Refused

**Check:**
1. NGINX is running: `systemctl status nginx` or `nginx -t`
2. NightAction server is running: `ps aux | grep nightaction`
3. Cloudflare proxy is enabled (orange cloud)
4. Firewall allows port 80

**Test NGINX directly:**
```bash
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" http://nightaction.rumple.ca/
```

Should return:
```
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
```

### WebSocket Upgrade Failed

**Check NGINX config:**
- `proxy_http_version 1.1` is set
- `Upgrade` and `Connection` headers are set
- NGINX reloaded after config change

**Check Cloudflare:**
- WebSockets enabled in Network settings
- SSL mode is Flexible (or higher)

### Messages Not Received

**Check WebSocket timeouts:**
- NGINX: `proxy_read_timeout` and `proxy_send_timeout`
- Cloudflare: Connections timeout after 100 seconds of inactivity (ping/pong handles this)

**Client shows:**
```
[*] Server disconnected
```

**Solution:** The websockets library sends automatic ping/pong keepalives every 30 seconds.

### Cloudflare Shows "Origin Server Not Reachable"

**Check:**
1. Port 80 is forwarded to NGINX
2. NGINX is listening on 0.0.0.0:80 (not 127.0.0.1)
3. DNS A record points to correct public IP
4. Firewall allows port 80 from Cloudflare IPs

---

## Security Considerations

### What Cloudflare Can See

- ✅ Connection metadata (timing, size, frequency)
- ✅ WebSocket handshake headers
- ✅ Encrypted message frames (base64 blobs)
- ❌ Message content (encrypted with AES-256)
- ❌ Authentication codes (encrypted with RSA-2048)

### What Cloudflare Cannot Do

- ❌ Decrypt your messages
- ❌ Impersonate the server (would need RSA private key)
- ❌ Man-in-the-middle attack (end-to-end encryption)

### Trust Model

You're trusting Cloudflare with:
- **Metadata**: They can see when/how often you connect
- **IP addresses**: They know who's connecting (but not what they're saying)

You're **NOT** trusting Cloudflare with:
- **Message content**: Encrypted before WebSocket layer
- **Authentication**: Codes are never sent in plaintext

### Advanced Security

**If you don't trust Cloudflare at all:**

1. **Tor Hidden Service**: Run NightAction as a .onion service
2. **VPN Tunnel**: Put NightAction behind a VPN
3. **Direct Connection**: Skip Cloudflare, use DNS-only mode (gray cloud)

But remember: NightAction's encryption is end-to-end. Even if Cloudflare is compromised, they cannot decrypt your messages.

---

## Performance Tuning

### NGINX Worker Processes

For high traffic:

```nginx
worker_processes auto;  # Use all CPU cores

events {
    worker_connections 4096;  # Increase from 1024
}
```

### Cloudflare Caching

Disable caching for NightAction:

1. Go to **Caching** → **Configuration**
2. Add Page Rule for `nightaction.rumple.ca/*`:
   - **Cache Level**: Bypass

WebSocket connections shouldn't be cached anyway, but this ensures it.

---

## Monitoring

### Server Logs

**NGINX Access Log:**
```bash
tail -f /var/log/nginx/access.log | grep nightaction
```

**NightAction Server:**
Already logs to console (connections, authentication, disconnects)

### Cloudflare Analytics

1. Go to **Analytics & Logs** → **Traffic**
2. Filter by `nightaction.rumple.ca`
3. See:
   - Requests per second
   - Bandwidth usage
   - Threats blocked

---

## Example Client Connection

**For testing locally (same network):**
```bash
python3 nightaction_client.py
Target: 192.168.10.161:7777
# Uses ws:// (unencrypted WebSocket)
```

**For production (through Cloudflare):**
```bash
python3 nightaction_client.py
Target: nightaction.rumple.ca
# Uses wss:// (encrypted WebSocket via Cloudflare)
```

The client automatically detects and uses the right protocol!

---

## Summary Checklist

- [ ] Install `websockets` library: `pip install -r requirements.txt`
- [ ] Configure Cloudflare DNS (orange cloud ON)
- [ ] Set Cloudflare SSL mode to Flexible
- [ ] Update `nginx.conf` with WebSocket proxy config
- [ ] Reload NGINX: `nginx -s reload`
- [ ] Open port 80 in firewall
- [ ] Forward port 80 in router (if needed)
- [ ] Start NightAction server: `python3 nightaction_server.py`
- [ ] Test with client: `python3 nightaction_client.py`

---

## What Changed from TCP Version?

| Aspect | Old (TCP) | New (WebSocket) |
|--------|-----------|-----------------|
| Protocol | Raw TCP sockets | WebSocket (over HTTP) |
| Cloudflare | Not compatible | ✅ Fully compatible |
| Encryption | RSA + AES-256 | Same (unchanged) |
| NGINX Config | `stream` block | `http` server block |
| Client URI | `192.168.1.100:7777` | `wss://nightaction.rumple.ca` |
| Port | 7777 | 7777 (proxied via 80/443) |
| Security | End-to-end | Same (unchanged) |

**Bottom line:** Same encryption, same security, now works through Cloudflare!
