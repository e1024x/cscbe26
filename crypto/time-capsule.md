---
title: "Time Capsule"
difficulty: Easy
description: "Professor Langford's time capsule encryption service has been running since the early days of the internet. He claims that every message is sealed with a unique, unpredictable key -- locked away forever. We've intercepted a transmission from the service containing a classified secret. Can you unseal it?"
flag: "CSC{533Ds_B0Und_7O_TIm3_2TAmpS_4RE_n0_900D}"
---

# Time capsule

> *Professor Langford's time capsule encryption service has been running since the early days of the internet. He claims that every message is sealed with a unique, unpredictable key -- locked away forever. We've intercepted a transmission from the service containing a classified secret. Can you unseal it?*

server XORs the flag with a keystream from `random.Random` seeded with `int(time.time())`. here's the full server source:

```python
import os
import random
import socketserver
import time

HOST = "0.0.0.0"
PORT = 1339
FLAG = os.environ.get("FLAG", "CSC{REDACTED}")

BANNER = r"""
  +==========================================+
  |     TIME CAPSULE ENCRYPTION              |
  |  "Sealed with a unique, unbreakable key" |
  +==========================================+
"""

def encrypt(plaintext: bytes, seed: int) -> bytes:
    rng = random.Random(seed)
    keystream = bytes([rng.randint(0, 255) for _ in range(len(plaintext))])
    return bytes(a ^ b for a, b in zip(plaintext, keystream))

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        timestamp = int(time.time())
        ciphertext = encrypt(FLAG.encode(), timestamp)

        self.wfile.write(BANNER.encode())
        self.wfile.write(b"\n")
        self.wfile.write(f"Sealed message (hex) : {ciphertext.hex()}\n".encode())
        self.wfile.write(b"\nGood luck unsealing it!\n")
```

so the seed is literally `int(time.time())` at the moment of connection. just record the timestamp when we connect and try seeds around it.

```python
import random, time, socket

HOST, PORT = "target", 1339

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
t_connect = int(time.time())
data = s.recv(4096).decode()
s.close()

ct_hex = data.split("Sealed message (hex) : ")[1].split("\n")[0]
ct = bytes.fromhex(ct_hex)

for offset in range(-5, 5):
    seed = t_connect + offset
    rng = random.Random(seed)
    keystream = bytes([rng.randint(0, 255) for _ in range(len(ct))])
    pt = bytes(a ^ b for a, b in zip(ct, keystream))
    try:
        decoded = pt.decode('ascii')
        if 'CSC{' in decoded:
            print(f"Seed: {seed} (offset: {offset})")
            print(f"Flag: {decoded}")
            break
    except (UnicodeDecodeError, ValueError):
        continue
```

`CSC{533Ds_B0Und_7O_TIm3_2TAmpS_4RE_n0_900D}`
