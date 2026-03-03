---
title: "Broken Record"
difficulty: Easy
description: "Our field agents intercepted a coded radio transmission from a numbers station broadcasting on a loop. The signal repeats the same short pattern over and over -- almost like a broken record. Analysts believe the message contains classified operational intel."
flag: "CSC{rEP3ATED_X0R_KEYS_ArE_gRO221Y_FEE8L3}"
---

# Broken record

> *Our field agents intercepted a coded radio transmission from a numbers station broadcasting on a loop. The signal repeats the same short pattern over and over -- almost like a broken record. Analysts believe the message contains classified operational intel.*

numbers station broadcasting hex-encoded ciphertext on loop. 281 hex chars = 140 bytes. repeating-key XOR.

here's the full ciphertext:

```
8ae212fefe079dff078a8d6ff38d0787e811fee20c92f448d4ec25bbc336f28d
36b6c862b1dd27accc36b7c22cbfc162aecc31addd2aaccc31bb8d3bb1d862ac
c833abc831aac826fec523ad8d20bbc82cfece2db0cb2bacc027ba83488bde27
fed92abb8d24b1c12eb1da2bb0ca62bddf27bac82caac423b28d24b1df62aac5
27fec327a6d962aec523adc878feee119dd6309bfd719ff9079af21aeeff1d95
e81b8df203ace81db9ff0dec9f7387f2049be87a929e3fd4a706bbde36acc23b
fed92ab7de62b3c831adcc25bb8d23b8d927ac8d30bbcc26b7c325f0a706b18d
2cb1d962adc523acc862a9c436b68d23b0d42db0c862b1d836adc426bb8d36b6
c862b1dd27accc36b7c22cf0a748f380629dc22caadf2db2a7
```

standard [hamming distance](https://en.wikipedia.org/wiki/Hamming_distance) key length analysis. top candidates: 15, 18, 12, 9, 6 -- all multiples of 3. so the real key length is 3.

split into three single-byte XOR streams, frequency analysis on each. key: `0xDE 0xAD 0x42`.

```python
from itertools import cycle

ct = bytes.fromhex("8ae212fefe079dff078a8d6ff38d0787e811fee20c92f448d4ec25bbc336f28d36b6c862b1dd27accc36b7c22cbfc162aecc31addd2aaccc31bb8d3bb1d862acc833abc831aac826fec523ad8d20bbc82cfece2db0cb2bacc027ba83488bde27fed92abb8d24b1c12eb1da2bb0ca62bddf27bac82caac423b28d24b1df62aac527fec327a6d962aec523adc878feee119dd6309bfd719ff9079af21aeeff1d95e81b8df203ace81db9ff0dec9f7387f2049be87a929e3fd4a706bbde36acc23bfed92ab7de62b3c831adcc25bb8d23b8d927ac8d30bbcc26b7c325f0a706b18d2cb1d962adc523acc862a9c436b68d23b0d42db0c862b1d836adc426bb8d36b6c862b1dd27accc36b7c22cf0a748f380629dc22caadf2db2a7")
key = bytes([0xDE, 0xAD, 0x42])
print(bytes(a ^ b for a, b in zip(ct, cycle(key))).decode())
```

`CSC{rEP3ATED_X0R_KEYS_ArE_gRO221Y_FEE8L3}`
