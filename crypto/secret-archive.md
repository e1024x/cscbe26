---
title: "Secret Archive"
difficulty: Hard
description: "Any great service has both: performance and security. Ow, did I forget to give you the key?"
flag: "CSC{compression_oracle_flag}"
---

# Secret archive

> *Any great service has both: performance and security. Ow, did I forget to give you the key?*

[CRIME/BREACH](https://en.wikipedia.org/wiki/BREACH) style compression oracle. here's the server:

```python
from Crypto.Cipher import AES
import secrets
from gzip import compress
import socketserver

HOST, PORT = "0.0.0.0", 1339

with open("flag.gif", 'rb') as fin:
    IMAGE = fin.read()

class ChallengeHandler(socketserver.StreamRequestHandler):
    def handle(self):
        key = secrets.token_bytes(32)
        cipher = AES.new(key, AES.MODE_CTR)
        while True:
            try:
                archives = []

                self.request.sendall(b"Send me your files in hex format:\n> ")
                for _ in range(1000):
                    user_input = self.rfile.readline(5000).rstrip().decode()
                    if user_input == "":
                        break
                    input_file = bytes.fromhex(user_input)
                    archives.append(
                        cipher.encrypt(compress(IMAGE + input_file)).hex().encode()
                    )

                response = b"\n".join(archives)
                self.request.sendall(b"Here are your secret archives:\n")
                self.request.sendall(response + b"\n")

            except Exception as e:
                self.request.sendall(b"\nInvalid Input.\n")
```

so it concatenates user input with a secret GIF (that contains the flag), gzip-compresses the whole thing, encrypts with AES-CTR. CTR preserves exact length so ciphertext length = compressed size. when a guess matches bytes in the flag, gzip compresses harder, shorter output.

the problem is a single matching byte barely moves the needle with all the surrounding GIF data competing for gzip's attention.

the original [BREACH paper](http://breachattack.com/resources/BREACH%20-%20SSL,%20gone%20in%2030%20seconds.pdf) describes this problem. the fix is to repeat the candidate string many times so gzip's LZ77 back-references create a much larger length differential between correct and incorrect guesses. Sjoerd Langkemper has a [good writeup on this amplification technique](https://www.sjoerdlangkemper.nl/2024/11/13/breach-compression-amplification-attacks-against-padding/). we used `REPEAT=30` which gave a clear signal. here's the exploit:

```python
import socket, string, time

CHARSET = string.ascii_letters + string.digits + "_{}-!@#$%^&*().,;:?/\\|<>~`+= "
REPEAT = 30

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(20)
    s.connect((HOST, PORT))
    data = b""
    while b"> " not in data:
        data += s.recv(4096)
    return s

def oracle_batch(s, payloads):
    for p in payloads:
        s.sendall(p.hex().encode() + b"\n")
    s.sendall(b"\n")
    data = b""
    while True:
        try:
            chunk = s.recv(16384)
            if not chunk:
                break
            data += chunk
            if b"secret archives" in data and b"> " in data.split(b"secret archives")[-1]:
                break
        except socket.timeout:
            break
    return [len(line) // 2 for line in data.split(b"\n")
            if line.strip() and all(c in b'0123456789abcdef' for c in line.strip())]

def find_next_char(s, known_prefix, charset):
    payloads = []
    chars = []
    for c in charset:
        candidate = (known_prefix + c).encode()
        payload = (candidate * REPEAT)[:2400]
        payloads.append(payload)
        chars.append(c)
    lengths = oracle_batch(s, payloads)
    if len(lengths) != len(chars):
        return None, []
    results = sorted(zip(chars, lengths), key=lambda x: x[1])
    return results[0], results
```

server accepts up to 1000 hex-encoded inputs per round (terminated by empty line), so all charset candidates fit in a single round trip. the main loop:

```python
known = "CSC{"
s = connect()

while not known.endswith("}"):
    (best_char, best_len), results = find_next_char(s, known, CHARSET)
    margin = results[1][1] - results[0][1] if len(results) > 1 else 0

    print(f"[{len(known):2d}] Best: '{best_char}' "
          f"(len={best_len}, margin={margin})")

    if margin == 0:
        padding = b"\xff\xfe\xfd\xfc\xfb\xfa"
        better_results = []
        for c in CHARSET:
            candidate = (known + c).encode()
            p1 = (candidate + padding) * (REPEAT // 2)
            p2 = (padding + candidate) * (REPEAT // 2)
            p1 = p1[:2400]
            p2 = p2[:2400]
            lens = oracle_batch(s, [p1, p2])
            if len(lens) == 2:
                diff = lens[1] - lens[0]
                better_results.append((c, diff, lens[0]))

        better_results.sort(key=lambda x: (-x[1], x[2]))
        if better_results and better_results[0][1] > 0:
            best_char = better_results[0][0]
        else:
            s.close()
            time.sleep(1)
            s = connect()
            continue

    known += best_char
    print(f"  Current flag: {known}")

    if len(known) % 10 == 0:
        s.close()
        time.sleep(0.5)
        s = connect()
```

when margin hit zero (no clear winner), a padding trick broke the tie: compare `candidate+padding` vs `padding+candidate`. if that also failed, reconnecting for a fresh AES keystream usually resolved it.

`CSC{compression_oracle_flag}`
