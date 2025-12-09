# WebSocket Migration Summary

NightAction has been converted to use **WebSockets** for Cloudflare compatibility!

## What Changed?

### ✅ Same Security
- **Encryption unchanged**: Still uses RSA-2048 + AES-256-GCM
- **End-to-end encrypted**: Messages encrypted BEFORE WebSocket framing
- **Zero trust**: Cloudflare cannot decrypt your messages

### ✅ Same Features
- Bidirectional communication
- Multi-agent support
- Chat history with auto-purge
- Agent selection UI
- 4-word authentication

### 🔄 What's Different?

| Aspect | Before | After |
|--------|--------|-------|
| **Transport** | Raw TCP sockets | WebSocket (WS/WSS) |
| **Cloudflare** | ❌ Not compatible | ✅ Fully compatible |
| **Library** | `socket` | `websockets` |
| **Client URI** | `192.168.1.100:7777` | `wss://nightaction.rumple.ca` |
| **NGINX Config** | `stream` block | `http` server block |
| **Protocol** | Custom TCP | WebSocket over HTTP |

---

## Quick Start (Existing Setup)

If you already have NightAction running, here's how to upgrade:

### 1. Install New Dependency

```bash
# In your venv
pip install websockets
```

### 2. Update Server Files

Replace:
- `nightaction_server.py` - New WebSocket version
- `nightaction_client.py` - New WebSocket version

Your existing database (`nightaction.db`) and RSA keys work as-is!

### 3. Update NGINX Config

**Remove this (old TCP proxy):**
```nginx
stream {
    server {
        listen 7777;
        proxy_pass 192.168.10.161:7777;
    }
}
```

**Add this (WebSocket proxy):**
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

        # Headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        # Timeouts
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }
}
```

Reload NGINX:
```bash
nginx -s reload
```

### 4. Configure Cloudflare

1. **DNS**: Set `nightaction.rumple.ca` to **🟠 Proxied** (orange cloud)
2. **SSL/TLS**: Set to **Flexible** mode
3. **Network**: Ensure **WebSockets** is ON

### 5. Restart Server

```bash
python3 nightaction_server.py
```

You'll see:
```
╔═══════════════════════════════════════════╗
║         NIGHTACTION SERVER ACTIVE         ║
║            (WebSocket Mode)               ║
╚═══════════════════════════════════════════╝
[*] Listening on ws://0.0.0.0:7777
[*] Compatible with Cloudflare Proxy
```

### 6. Test Client

```bash
python3 nightaction_client.py

Target: nightaction.rumple.ca
```

The client will automatically use `wss://nightaction.rumple.ca` (secure WebSocket).

---

## For New Deployments

See **CLOUDFLARE_SETUP.md** for complete setup instructions.

---

## Connection Flow

### Before (TCP):
```
Client → Raw TCP → Server:7777
```

**Problem:** Cloudflare proxy doesn't support raw TCP

### After (WebSocket):
```
Client → WSS (SSL) → Cloudflare (proxy) → HTTP → NGINX:80 → WS → Server:7777
```

**Benefits:**
- ✅ Cloudflare DDoS protection
- ✅ IP hiding
- ✅ Free SSL certificates
- ✅ Global CDN
- ✅ Still end-to-end encrypted

---

## Client Auto-Detection

The client automatically detects the right protocol:

**Domain (Cloudflare):**
```
Input: nightaction.rumple.ca
Uses:  wss://nightaction.rumple.ca (secure WebSocket)
```

**Local network:**
```
Input: 192.168.10.161:7777
Uses:  ws://192.168.10.161:7777 (plain WebSocket)
```

**Localhost:**
```
Input: localhost:7777
Uses:  ws://localhost:7777
```

---

## Security Guarantees

### What Changed:
- **Transport layer**: TCP → WebSocket

### What DID NOT Change:
- ✅ **Encryption**: RSA + AES-256 (same as before)
- ✅ **Authentication**: SHA-256 hashed codes
- ✅ **Session keys**: Unique per connection
- ✅ **Forward secrecy**: Sessions independent
- ✅ **Man-in-the-middle protection**: Still impossible

### Cloudflare Can See:
- WebSocket handshake metadata
- Encrypted frame sizes and timing
- Connection IP addresses

### Cloudflare CANNOT See:
- ❌ Message content (AES-256 encrypted)
- ❌ Authentication codes (RSA-2048 encrypted)
- ❌ Session keys (encrypted in RSA blob)

**Bottom line:** Same security, now works through Cloudflare!

---

## Troubleshooting

### "WebSocket connection failed"

**Check:**
1. NGINX has WebSocket headers configured
2. Cloudflare proxy is ON (orange cloud)
3. Cloudflare SSL mode is Flexible or higher
4. WebSockets enabled in Cloudflare Network settings

**Test NGINX:**
```bash
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" http://nightaction.rumple.ca/
```

Should return `HTTP/1.1 101 Switching Protocols`.

### "Connection refused"

**Check:**
1. Server is running: `ps aux | grep nightaction`
2. Port 80 is open in firewall
3. NGINX is listening on port 80
4. Router forwards port 80 to NGINX

### Client shows wrong URI

The client builds the URI automatically:
- Domains → `wss://`
- Local IPs (192.168.x.x, 10.x.x.x) → `ws://`
- localhost → `ws://`

If you need to override, provide full URI:
```
Target: wss://custom.example.com:8080
```

---

## Performance

WebSocket adds minimal overhead:

- **Handshake**: ~1 RTT (once per session)
- **Frame headers**: 2-14 bytes per message
- **Ping/pong**: 30-second intervals (auto keepalive)

**Encryption overhead is unchanged** (same as TCP version).

---

## What to Keep

✅ **Keep these files:**
- `nightaction.db` - Your agent database
- `server_private.pem` - Your server private key
- `server_public.pem` - Your server public key

These work with the WebSocket version!

---

## Rollback Plan

If you need to go back to TCP version:

1. Restore old `nightaction_server.py` and `nightaction_client.py`
2. Restore `stream` block in NGINX config
3. Set Cloudflare to **DNS only** (gray cloud)
4. Restart server and NGINX

Your database and keys will still work.

---

## Benefits Summary

### You Get:
- ✅ Cloudflare DDoS protection
- ✅ Server IP hiding
- ✅ Free SSL/TLS certificates
- ✅ Global CDN (faster connections)
- ✅ Firewall/NAT compatibility
- ✅ Standard protocols (HTTP/WebSocket)

### You Keep:
- ✅ End-to-end encryption
- ✅ Same authentication system
- ✅ Same features and UI
- ✅ Same database and keys
- ✅ Same security guarantees

### No Compromises:
- ❌ No security reduction
- ❌ No feature loss
- ❌ No performance degradation

---

## Next Steps

1. **Read CLOUDFLARE_SETUP.md** for deployment guide
2. **Update your server and client** files
3. **Configure NGINX** for WebSocket proxying
4. **Enable Cloudflare proxy** (orange cloud)
5. **Test connection** from client

Welcome to WebSocket-powered NightAction! 🚀
