# Self-Hosting the Aegis Relay — $0, ~10 minutes

The relay is a blind courier: in-memory mailbox queues, no database, no
accounts, no logs. Hosting one is close to free — it needs ~50 MB RAM,
negligible CPU, and Python 3.10+ with **zero dependencies** (stdlib only).

> **The relay speaks plain WebSocket on localhost.** TLS termination is your
> job — the Caddy one-liner below does it with automatic Let's Encrypt.

---

## 1. Sixty-second local run

```bash
git clone https://github.com/phntm000/aegis && cd aegis/relay
python3 relay.py --self-test     # 16 built-in checks; expect "SELF-TEST OK"
python3 relay.py                 # listens on 127.0.0.1:8765
```

Point a client at `ws://127.0.0.1:8765` (loopback only — the iOS client
refuses cleartext anywhere else).

## 2. Production install (any Linux VPS / Raspberry Pi)

```bash
sudo mkdir -p /opt/aegis-relay
sudo cp relay.py /opt/aegis-relay/
sudo cp relay.service /etc/systemd/system/aegis-relay.service
sudo systemctl daemon-reload
sudo systemctl enable --now aegis-relay
sudo systemctl status aegis-relay   # expect "active (running)"
```

`relay.service` already hardens the process: runs as `nobody`, no new
privileges, read-only system, private tmp, 256 MB memory cap, restart on
failure.

### Configuration (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `AEGIS_HOST` | `127.0.0.1` | Bind address. Keep localhost behind a TLS proxy. |
| `AEGIS_PORT` | `8765` | WebSocket port. |
| `AEGIS_TOKEN` | *(empty)* | If set, clients must send `{"op":"auth","token":"…"}` first. **Set this if your relay is public.** Generate: `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `AEGIS_TTL_DEFAULT` | `604800` (7 d) | Envelope lifetime when the client sends TTL 0. |
| `AEGIS_TTL_MAX` | `1209600` (14 d) | Hard cap; larger client TTLs are clamped. |
| `AEGIS_MAX_QUEUE` | `1000` | Per-mailbox depth; oldest dropped beyond it. |
| `AEGIS_MAX_PAYLOAD_MB` | `5` | Max sealed payload per envelope. |
| `AEGIS_SEND_BURST` / `AEGIS_SEND_RATE` | `40` / `8.0` | Per-connection token bucket (burst / refill per second). |
| `AEGIS_METRICS` | `0` | Set `1` for aggregate stdout counters (no identifiers, ever). |

Edit with `sudo systemctl edit aegis-relay` (adds an override file), then
`sudo systemctl restart aegis-relay`.

## 3. Public TLS with Caddy (one-liner)

```bash
sudo apt install -y caddy   # or: https://caddyserver.com/docs/install
```

`/etc/caddy/Caddyfile`:

```
relay.example.com {
    reverse_proxy 127.0.0.1:8765
}
```

```bash
sudo systemctl reload caddy   # certificate is automatic via Let's Encrypt
```

Clients now use `wss://relay.example.com`. (Nginx works too — proxy WS with
`proxy_http_version 1.1` + `Upgrade`/`Connection` headers — but Caddy's
automatic certificates are why it's recommended here.)

## 4. Docker

```bash
cd relay
docker build -t aegis-relay .
docker run -d --name aegis-relay --restart unless-stopped \
  -e AEGIS_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
  -p 127.0.0.1:8765:8765 aegis-relay
```

Put Caddy (or your platform's edge TLS) in front as in §3. The image is
`python:3.12-slim` + one file; no `pip install` step exists because there are
no dependencies.

## 5. Free-tier hosts

The relay needs ~50 MB RAM and sips CPU. Free-tier offerings change, so treat
these as recipes, not promises — but any tier that runs a Dockerfile or a
Python process works.

**fly.io** (Dockerfile-native):

```bash
fly launch --no-deploy          # accept the Dockerfile detector
fly secrets set AEGIS_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
fly deploy
```

fly terminates TLS at its edge — your `wss://<app>.fly.dev` is encrypted to
the edge, plain WS inside (fine: it's your own host).

**Railway / Render / similar** (Dockerfile auto-detected): connect the repo,
set `AEGIS_TOKEN` in the environment tab, deploy. Use the provided
`https://` domain as your `wss://` URL.

**Raspberry Pi** (LAN or Tailscale): follow §2 directly. For a
friends-and-family relay, Tailscale in front of `127.0.0.1:8765` gives you
encrypted, authenticated access with zero open ports.

**Oracle Cloud free tier / any free VPS**: §2 + §3, total cost $0.

## 6. Pointing iOS clients at your relay

In the app: Settings → Relay → paste your `wss://` URL.

**Pin the certificate** (strongly recommended for any relay you don't
operate). Get the SHA-256 of the leaf certificate:

```bash
echo | openssl s_client -connect relay.example.com:443 -servername relay.example.com 2>/dev/null \
  | openssl x509 -outform DER \
  | openssl dgst -sha256 -binary | openssl base64
```

Paste the base64 output into the app's "certificate pin" field. The client
fails closed on mismatch — a hostile network can't silently substitute a
different relay, even with a valid CA-issued certificate.

Give clients your `AEGIS_TOKEN` out-of-band (QR code, in person, existing
encrypted channel) if you set one.

## 7. LAN-only mode (no relay at all)

Leave the relay URL empty. The app works entirely over MultipeerConnectivity:
BLE + Wi-Fi, zero internet. Honest scope: ~10 m over BLE, ~30–100 m over
Wi-Fi, foreground-first (iOS throttles background discovery), best for
same-room / same-household / classroom / protest / airplane use. Two phones
side by side message and call with no infrastructure whatsoever.

## 8. What you can and cannot see as an operator

| | |
|---|---|
| Plaintext messages | **Never.** Payloads are sealed before they reach you. |
| Who talks to whom | **Nothing.** No sender field exists on the wire; mailbox IDs are anonymous and rotate. |
| Timing / size / count | Per anonymous mailbox, yes — inherent to store-and-forward. |
| Client IPs | Yes, while connected (any TCP server sees this). |
| History after restart | **Nothing.** Memory-only; restart wipes everything. |
| Logs | There are none to read. Don't add any. |

If someone asks you to log, filter, or identify users: the honest answer is
that the software cannot do it — there is no knob for it, which is the point.

## 9. Operator hardening checklist

- [ ] Bind `127.0.0.1` and terminate TLS in a real proxy (§3). Never expose
      bare `ws://` to the internet (clients refuse it outside loopback).
- [ ] Set `AEGIS_TOKEN` on any public relay; distribute it out-of-band.
- [ ] Keep the box patched (`unattended-upgrades` on Debian/Ubuntu).
- [ ] Firewall: only 443 (and 80 for ACME) inbound.
- [ ] Leave `AEGIS_METRICS=0` unless you want aggregate counters; they never
      contain identifiers, but less is more.
- [ ] Backups: there is nothing to back up. (Say it again for the auditors:
      **nothing to back up.**)
- [ ] Optional: run two relays (e.g. home Pi + free-tier VPS) and tell
      clients about both — the app fans out across every configured relay.

## 10. Verifying your relay

```bash
python3 relay.py --self-test   # framing, TTL, queue depth, rate limiter, WS vector
```

Then connect a client, send a message with the app closed, and watch it
arrive on the next background wake — the whole point of the dead drop.
