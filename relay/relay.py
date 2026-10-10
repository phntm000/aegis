#!/usr/bin/env python3
"""Aegis dumb relay -- a blind courier for sealed envelopes.

The relay NEVER sees plaintext, sender identity, or recipient identity. It
holds opaque envelopes keyed by anonymous 256-bit mailbox IDs (a dead drop:
envelopes live until their TTL, any connection that binds the mailbox can
collect them, clients dedupe by envelope ID). No database, no accounts, no
auth (optional shared operator token), no logs of who-talked-to-whom.

In-memory ONLY. Restart wipes everything -- a seized relay yields nothing.

Stdlib only. `python3 relay.py --self-test` runs the built-in checks.
TLS termination is the operator's job (see ../docs/SELF_HOSTING.md).
"""

import argparse
import asyncio
import base64
import collections
import hashlib
import json
import os
import struct
import sys
import time

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# Wire frame: magic(2) ver(1) flags(1) to(32) id(16) ttl(4BE) len(4BE) payload
HEADER = struct.Struct(">2s B B 32s 16s I I")
HEADER_SIZE = HEADER.size  # 60
MAGIC, VERSION = b"AG", 1

def cfg(name, default, cast=str):
    v = os.environ.get(name)
    return cast(v) if v is not None else default

HOST = cfg("AEGIS_HOST", "127.0.0.1")
PORT = cfg("AEGIS_PORT", 8765, int)
MAX_PAYLOAD = cfg("AEGIS_MAX_PAYLOAD_MB", 5, int) * 1024 * 1024
MAX_QUEUE = cfg("AEGIS_MAX_QUEUE", 1000, int)
TTL_DEFAULT = cfg("AEGIS_TTL_DEFAULT", 7 * 24 * 3600, int)
TTL_MAX = cfg("AEGIS_TTL_MAX", 14 * 24 * 3600, int)
TOKEN = cfg("AEGIS_TOKEN", "")
SEND_BURST = cfg("AEGIS_SEND_BURST", 40, int)
SEND_RATE = cfg("AEGIS_SEND_RATE", 8.0, float)
METRICS = cfg("AEGIS_METRICS", "0") == "1"

# ------------------------------------------------------------- framing ---

def encode_frame(to, eid, ttl, payload, flags=0):
    return HEADER.pack(MAGIC, VERSION, flags, to, eid, ttl, len(payload)) + payload

def decode_frame(buf):
    if len(buf) < HEADER_SIZE:
        raise ValueError("frame shorter than header")
    magic, ver, flags, to, eid, ttl, ln = HEADER.unpack_from(buf)
    if magic != MAGIC or ver != VERSION:
        raise ValueError("bad magic/version")
    if ln > MAX_PAYLOAD:
        raise ValueError("payload exceeds relay maximum")
    if len(buf) != HEADER_SIZE + ln:
        raise ValueError("declared length != actual length")
    return {"to": to, "id": eid, "ttl": ttl, "flags": flags,
            "payload": buf[HEADER_SIZE:]}

def valid_mailbox(s):
    return (isinstance(s, str) and len(s) == 64
            and all(c in "0123456789abcdefABCDEF" for c in s))

# ------------------------------------------------------ minimal WebSocket ---

class WSProtocolError(Exception):
    pass

async def ws_handshake(reader, writer):
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
    except Exception:
        return False
    lines = head.decode("latin1").split("\r\n")
    if not lines[0].startswith("GET "):
        return False
    hdr = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            hdr[k.strip().lower()] = v.strip()
    if "websocket" not in hdr.get("upgrade", "").lower():
        return False
    key = hdr.get("sec-websocket-key")
    if not key:
        return False
    accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest())
    writer.write(b"HTTP/1.1 101 Switching Protocols\r\n"
                 b"Upgrade: websocket\r\n"
                 b"Connection: Upgrade\r\n"
                 b"Sec-WebSocket-Accept: " + accept + b"\r\n\r\n")
    await writer.drain()
    return True

def _unmask(raw, mask):
    n = len(raw)
    if n == 0:
        return b""
    rep = (mask * ((n + 3) // 4))[:n]
    return (int.from_bytes(raw, "big") ^ int.from_bytes(rep, "big")).to_bytes(n, "big")

class Conn:
    def __init__(self, reader, writer):
        self.r, self.w = reader, writer
        self.binds = set()
        self.bucket = TokenBucket(SEND_BURST, SEND_RATE)

    async def send_frame(self, opcode, data):
        n = len(data)
        hdr = bytes([0x80 | opcode])
        if n < 126:
            hdr += bytes([n])
        elif n < 65536:
            hdr += bytes([126]) + struct.pack(">H", n)
        else:
            hdr += bytes([127]) + struct.pack(">Q", n)
        self.w.write(hdr + data)
        await self.w.drain()

    async def send_text(self, s):
        await self.send_frame(0x1, s.encode())

    async def send_binary(self, b):
        await self.send_frame(0x2, b)

    async def recv(self):
        """Next message: ('text', str) | ('bin', bytes) | None on close."""
        opcode, parts = None, []
        while True:
            b1b2 = await self.r.readexactly(2)
            b1, b2 = b1b2[0], b1b2[1]
            fin, op = b1 & 0x80, b1 & 0x0F
            masked, ln = b2 & 0x80, b2 & 0x7F
            if not masked:
                raise WSProtocolError("client frames must be masked")
            if ln == 126:
                ln = struct.unpack(">H", await self.r.readexactly(2))[0]
            elif ln == 127:
                ln = struct.unpack(">Q", await self.r.readexactly(8))[0]
            if ln > MAX_PAYLOAD + 4096:
                raise WSProtocolError("frame too large")
            if not fin and op >= 0x8:
                raise WSProtocolError("fragmented control frame")
            mask = await self.r.readexactly(4)
            data = _unmask(await self.r.readexactly(ln), mask)
            if op == 0x8:
                return None
            if op == 0x9:
                await self.send_frame(0xA, data)
                continue
            if op == 0xA:
                continue
            if op in (0x1, 0x2):
                if opcode is not None:
                    raise WSProtocolError("interleaved message")
                opcode = op
            elif op == 0x0:
                if opcode is None:
                    raise WSProtocolError("stray continuation")
            else:
                raise WSProtocolError("bad opcode %r" % op)
            parts.append(data)
            if fin:
                payload = b"".join(parts)
                if opcode == 0x1:
                    try:
                        return ("text", payload.decode("utf-8", "strict"))
                    except UnicodeDecodeError:
                        raise WSProtocolError("text frame is not utf-8")
                return ("bin", payload)

# ------------------------------------------------------------ rate limit ---

class TokenBucket:
    """Blunt anti-spam: bursts pass, sustained floods get dropped.

    Honest note: the bucket is per-connection, so reconnecting buys a fresh
    one. This stops accidents and casual abuse, not a determined adversary.
    Real protection is the operator token (AEGIS_TOKEN) or a closed-group
    relay. Proof-of-work was evaluated and rejected: it taxes every iPhone
    battery per message while barely slowing a botnet -- duct tape."""

    def __init__(self, capacity, rate):
        self.cap, self.rate = capacity, rate
        self.tokens, self.t0 = float(capacity), time.monotonic()

    def take(self, n=1):
        now = time.monotonic()
        self.tokens = min(self.cap, self.tokens + (now - self.t0) * self.rate)
        self.t0 = now
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False

# ----------------------------------------------------------------- store ---

class Store:
    """In-memory dead drop. Nothing here ever touches disk."""

    def __init__(self, max_queue=MAX_QUEUE):
        self.max_queue = max_queue
        self.boxes = {}  # hex -> deque[(expire_at, raw_frame)]
        self.lock = asyncio.Lock()
        self.n_stored = self.n_dropped = self.n_expired = self.bytes_in = 0

    async def push(self, mb_hex, raw, ttl):
        async with self.lock:
            dq = self.boxes.setdefault(mb_hex, collections.deque())
            dq.append((time.monotonic() + ttl, raw))
            while len(dq) > self.max_queue:  # oldest-drop under flood
                dq.popleft()
                self.n_dropped += 1
            self.n_stored += 1
            self.bytes_in += len(raw)

    async def collect(self, mb_hex):
        """All live envelopes for a mailbox. They STAY until TTL expiry
        (multi-device friendly); clients dedupe by envelope ID."""
        now = time.monotonic()
        async with self.lock:
            return [raw for exp, raw in self.boxes.get(mb_hex, []) if exp > now]

    async def sweep(self):
        now = time.monotonic()
        async with self.lock:
            for mb in list(self.boxes):
                kept = collections.deque(
                    (e, r) for e, r in self.boxes[mb] if e > now)
                self.n_expired += len(self.boxes[mb]) - len(kept)
                if kept:
                    self.boxes[mb] = kept
                else:
                    del self.boxes[mb]

SUBSCRIBERS = {}  # mailbox hex -> set[Conn]
SUB_LOCK = asyncio.Lock()

async def unsubscribe_all(c):
    async with SUB_LOCK:
        for mb in c.binds:
            SUBSCRIBERS.get(mb, set()).discard(c)
        for mb in [m for m, s in SUBSCRIBERS.items() if not s]:
            del SUBSCRIBERS[mb]

def parse_op(text):
    try:
        op = json.loads(text)
        return op if isinstance(op, dict) else {}
    except Exception:
        return {}

async def handle_op(c, text, store):
    op = parse_op(text)
    name = op.get("op")
    if name == "bind":
        mb = op.get("mailbox", "")
        if not valid_mailbox(mb):
            await c.send_text(json.dumps({"error": {"code": "bad_mailbox"}}))
            return
        if not c.bucket.take(2):  # binds can trigger big drains; cost them
            await c.send_text(json.dumps({"error": {"code": "rate_limited"}}))
            return
        async with SUB_LOCK:
            SUBSCRIBERS.setdefault(mb, set()).add(c)
        c.binds.add(mb)
        for raw in await store.collect(mb):
            await c.send_binary(raw)
        await c.send_text(json.dumps({"drained": {"mailbox": mb}}))
    elif name == "unbind":
        mb = op.get("mailbox", "")
        async with SUB_LOCK:
            SUBSCRIBERS.get(mb, set()).discard(c)
        c.binds.discard(mb)
    elif name == "ping":
        await c.send_text(json.dumps({"pong": True}))
    else:
        await c.send_text(json.dumps({"error": {"code": "unknown_op"}}))

async def handle_binary(c, data, store):
    try:
        f = decode_frame(data)
    except ValueError as e:
        await c.send_text(json.dumps({"error": {"code": "bad_frame",
                                               "detail": str(e)}}))
        return
    if not c.bucket.take(1):
        await c.send_text(json.dumps({"error": {"code": "rate_limited"}}))
        return
    ttl = max(1, min(f["ttl"] or TTL_DEFAULT, TTL_MAX))
    mb = f["to"].hex()
    await store.push(mb, data, ttl)
    async with SUB_LOCK:
        targets = [x for x in SUBSCRIBERS.get(mb, ()) if x is not c]
    for t in targets:  # never let a slow peer block the sender
        asyncio.create_task(_forward(t, data))
    await c.send_text(json.dumps({"ack": {"id": f["id"].hex()}}))

async def _forward(t, data):
    try:
        await t.send_binary(data)
    except Exception:
        pass

async def handle_client(reader, writer, store):
    if not await ws_handshake(reader, writer):
        writer.close()
        return
    c = Conn(reader, writer)
    await c.send_text(json.dumps({"hello": {
        "v": 1, "max_payload": MAX_PAYLOAD, "ttl_default": TTL_DEFAULT,
        "ttl_max": TTL_MAX, "send_burst": SEND_BURST, "send_rate": SEND_RATE,
        "auth_required": bool(TOKEN)}}))
    if TOKEN:
        try:
            msg = await asyncio.wait_for(c.recv(), 10)
        except Exception:
            msg = None
        op = parse_op(msg[1]) if msg and msg[0] == "text" else {}
        if not (op.get("op") == "auth" and op.get("token") == TOKEN):
            try:
                await c.send_text(json.dumps({"error": {"code": "unauthorized"}}))
            finally:
                writer.close()
            return
    try:
        while True:
            msg = await c.recv()
            if msg is None:
                break
            if msg[0] == "text":
                await handle_op(c, msg[1], store)
            else:
                await handle_binary(c, msg[1], store)
    except (WSProtocolError, asyncio.IncompleteReadError,
            ConnectionResetError, BrokenPipeError):
        pass
    finally:
        await unsubscribe_all(c)
        try:
            writer.close()
        except Exception:
            pass

async def sweeper(store):
    while True:
        await asyncio.sleep(60)
        await store.sweep()

async def metrics_loop(store):
    while True:
        await asyncio.sleep(60)
        # Aggregate counters only -- no identifiers, no mailbox IDs, ever.
        print(json.dumps({"t": int(time.time()),
                          "envelopes_stored": store.n_stored,
                          "envelopes_dropped_depth": store.n_dropped,
                          "envelopes_expired": store.n_expired,
                          "bytes_in": store.bytes_in,
                          "live_mailboxes": len(store.boxes)}), flush=True)

async def amain():
    store = Store()
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, store), HOST, PORT)
    print("aegis relay on %s:%d (auth_required=%s)" % (HOST, PORT, bool(TOKEN)),
          flush=True)
    async with server:
        tasks = [asyncio.create_task(sweeper(store))]
        if METRICS:
            tasks.append(asyncio.create_task(metrics_loop(store)))
        await server.serve_forever()

# -------------------------------------------------------------- self-test ---

def self_test():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS " if cond else "FAIL ") + name, flush=True)
        ok = ok and bool(cond)

    to, eid = bytes(range(32)), bytes(range(16))
    raw = encode_frame(to, eid, 123, os.urandom(1000))
    f = decode_frame(raw)
    check("frame round-trip",
          f["to"] == to and f["id"] == eid and f["ttl"] == 123
          and f["flags"] == 0 and f["payload"] == raw[HEADER_SIZE:])
    for name, bad in [("bad magic", b"XX" + raw[2:]),
                      ("truncated header", raw[:59]),
                      ("truncated payload", raw[:-10]),
                      ("trailing garbage", raw + b"\x00")]:
        try:
            decode_frame(bad)
            check("frame rejects " + name, False)
        except ValueError:
            check("frame rejects " + name, True)
    tampered = bytearray(raw)
    tampered[56:60] = struct.pack(">I", 1024 * 1024)  # claim 1 MiB, carry 1 KiB
    try:
        decode_frame(bytes(tampered))
        check("frame rejects length mismatch", False)
    except ValueError:
        check("frame rejects length mismatch", True)

    async def store_tests():
        s = Store()
        mb = "ab" * 32
        ids = [bytes([i]) * 16 for i in range(5)]
        for i in ids:
            await s.push(mb, encode_frame(to, i, 60, b"x"), 60)
        out = await s.collect(mb)
        check("mailbox FIFO order",
              [decode_frame(r)["id"] for r in out] == ids)
        check("dead drop persists until TTL", len(await s.collect(mb)) == 5)
        await s.push(mb, encode_frame(to, ids[0], 1, b"x"), 0.05)
        await asyncio.sleep(0.12)
        check("TTL expiry", len(await s.collect(mb)) == 5)  # the 5 remain
        s2 = Store(max_queue=10)
        for i in range(15):
            await s2.push(mb, encode_frame(to, bytes([i]) * 16, 60, b"x"), 60)
        out = await s2.collect(mb)
        check("queue depth oldest-drop",
              len(out) == 10
              and [decode_frame(r)["id"][0] for r in out] == list(range(5, 15))
              and s2.n_dropped == 5)
        s3 = Store()
        await s3.push(mb, encode_frame(to, ids[0], 1, b"x"), 0.02)
        await asyncio.sleep(0.06)
        await s3.sweep()
        check("sweeper purges expired", mb not in s3.boxes)

    asyncio.run(store_tests())

    b = TokenBucket(5, 10.0)
    check("rate limiter burst",
          all(b.take() for _ in range(5)) and not b.take())
    time.sleep(0.25)  # ~2.5 tokens refill
    check("rate limiter refill", b.take() and b.take() and not b.take())

    key = "dGhlIHNhbXBsZSBub25jZQ=="  # RFC 6455 example vector
    accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest())
    check("websocket accept vector",
          accept == b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")

    check("mailbox validation",
          valid_mailbox("ab" * 32)
          and not valid_mailbox("zz" * 32)
          and not valid_mailbox("ab" * 31)
          and not valid_mailbox(123))

    print("SELF-TEST " + ("OK" if ok else "FAILED"), flush=True)
    return 0 if ok else 1

def main():
    ap = argparse.ArgumentParser(description="Aegis dumb relay (blind courier)")
    ap.add_argument("--self-test", action="store_true")
    if ap.parse_args().self_test:
        sys.exit(self_test())
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
