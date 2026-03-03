---
title: "Bill's Gates"
difficulty: Hard
description: "My friend Bill wanted to prove that he's richer than me without telling me his wealth. So he sent me this crazy circuit and made me do something called oblivious transfer. Now I know that he is richer, but I want to know more! He's famous for his low-quality software, though, so maybe he left a vulnerability."
flag: "FLAG{7h3Se_T4ble5_aR3_d3RAn9eD}"
---

# Bill's gates

> *My friend Bill wanted to prove that he's richer than me without telling me his wealth. So he sent me this crazy circuit and made me do something called oblivious transfer. Now I know that he is richer, but I want to know more! He's famous for his low-quality software, though, so maybe he left a vulnerability.*

challenge gives us a zip with `chal.py`, a garbled circuit output file, and some wire labels. the description says something about two millionaires comparing wealth without revealing their amounts, that's [Yao's Millionaire Problem](https://en.wikipedia.org/wiki/Yao%27s_Millionaires%27_problem), typically solved with [Garbled Circuits](https://en.wikipedia.org/wiki/Garbled_circuit).

reading `chal.py`, it implements garbled circuits using AES double-encryption. we get the garbled tables, both parties' wire labels, our plaintext wealth (1,000,000), and the flag encrypted as `AES-ECB(Bill's_wealth, FLAG)`. so we need to recover Bill's 64-bit wealth to decrypt.

the circuit itself is compiled from Rust using `garble_lang`:

```rust
use garble_lang::compile;

fn main() {
    let code = "pub fn main(x: u64, y: u64) -> bool { x <= y }";
    let prg = compile(code).map_err(|e| e.prettify(&code)).unwrap();
    println!("{:?}", prg.circuit.gates);
}
```

so it's a 64-bit less-than-or-equal comparison. `x` is Bill's wealth, `y` is ours. wires 0-63 are Bill's input bits, 64-127 are ours.

here's the garbling code from `chal.py`:

```python
from Crypto.Cipher import AES
import secrets
from collections import namedtuple

FLAG = open('flag.txt').read().strip()
WEALTH_BILL = int(open('wealth-bill.txt').read().strip())

def gen_key() -> bytes:
    return int.to_bytes(secrets.randbits(16*8), 16)

Gate = namedtuple('Gate', ['type', 'in_wires', 'out_wire', 'truth_table'])

class GarbledCircuit:
    def __init__(self):
        self.gates = []
        self.num_wires = 0

    def add_gate(self, gate_type, in_wires, out_wire):
        if gate_type == 'AND':
            tt = {(0, 0): 0, (0, 1): 0, (1, 0): 0, (1, 1): 1}
        elif gate_type == 'NAND':
            tt = {(0, 0): 1, (0, 1): 1, (1, 0): 1, (1, 1): 0}
        elif gate_type == 'XOR':
            tt = {(0, 0): 0, (0, 1): 1, (1, 0): 1, (1, 1): 0}
        else:
            raise RuntimeError(f'Unknown gate type {gate_type}')
        self.gates.append(Gate(gate_type, in_wires, out_wire, tt))
        self.num_wires = max(self.num_wires, out_wire + 1)

    def garble(self):
        labels = {w: (gen_key(), gen_key()) for w in range(self.num_wires)}
        garbled_tables = []

        for gate in self.gates:
            A, B = gate.in_wires
            Z = gate.out_wire
            table = []
            for a in (0, 1):
                for b in (0, 1):
                    out_bit = gate.truth_table[a, b]
                    plaintext = labels[Z][out_bit] + b"\0" * 16
                    ciphertext = AES.new(labels[B][b], AES.MODE_ECB).encrypt(
                        AES.new(labels[A][a], AES.MODE_ECB).encrypt(plaintext)
                    )
                    table.append(ciphertext)
            n = len(table)
            for i in range(-1, -n, -1):
                j = secrets.randbelow(n+i)-n
                table[i], table[j] = table[j], table[i]

            garbled_tables.append((gate, table))

        return garbled_tables, labels
```

## the bug

looking at the shuffle in the garbling code, it's supposed to be [Fisher-Yates](https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle) but the indexing is wrong. lines 49-52:

```python
n = len(table)
for i in range(-1, -n, -1):
    j = secrets.randbelow(n+i)-n
    table[i], table[j] = table[j], table[i]
```

tracing through with n=4:

- `i=-1`: `j = randbelow(3) - 4`, so j in {-4, -3, -2}. position -1 swaps with {-4, -3, -2}. never itself.
- `i=-2`: `j = randbelow(2) - 4`, so j in {-4, -3}. never itself.
- `i=-3`: `j = randbelow(1) - 4`, always -4. always swaps with -4.

no element can stay in its original position. derangement, not uniform permutation. this leaks info: for each gate, the original index at the found position was NOT that position.

## constraint propagation

the original table ordering is deterministic: position `i` encodes `(a=i>>1, b=i&1)`. evaluate the circuit normally. try all four entries per gate, the one that decrypts (verified by 16 null padding bytes) reveals the shuffled position. then use the derangement constraint.

here's the full solve:

```python
from Crypto.Cipher import AES
from collections import namedtuple

Gate = namedtuple(
    'Gate', ['type', 'in_wires', 'out_wire', 'truth_table']
)

MY_WEALTH = 1_000_000
MY_BITS = list(map(int, bin(MY_WEALTH)[2:].rjust(64, '0')))

def try_decrypt(ciphertext, label_a, label_b):
    step1 = AES.new(label_b, AES.MODE_ECB).decrypt(ciphertext)
    step2 = AES.new(label_a, AES.MODE_ECB).decrypt(step1)
    return step2

def evaluate_circuit(garbled_tables, input_labels):
    labels = dict(input_labels)
    positions = []

    for gate, table in garbled_tables:
        A, B = gate.in_wires
        La = labels[A]
        Lb = labels[B]

        for pos, ct in enumerate(table):
            pt = try_decrypt(ct, La, Lb)
            if pt[-16:] == b'\x00' * 16:
                labels[gate.out_wire] = pt[:16]
                positions.append((gate, pos))
                break

    return labels, positions

def deduce_bits(positions):
    wire_bits = {}

    for i in range(64):
        wire_bits[64 + i] = MY_BITS[i]

    gate_for_output = {}
    for gate, pos in positions:
        gate_for_output[gate.out_wire] = (gate, pos)

    changed = True
    while changed:
        changed = False

        for gate, pos in positions:
            A, B = gate.in_wires
            Z = gate.out_wire

            a_known = A in wire_bits
            b_known = B in wire_bits
            z_known = Z in wire_bits

            if a_known and b_known and not z_known:
                wire_bits[Z] = gate.truth_table[
                    (wire_bits[A], wire_bits[B])
                ]
                changed = True
                z_known = True

            possible_indices = set()
            for idx in range(4):
                if idx == pos:
                    continue
                a_candidate = idx >> 1
                b_candidate = idx & 1
                if a_known and wire_bits[A] != a_candidate:
                    continue
                if b_known and wire_bits[B] != b_candidate:
                    continue
                possible_indices.add(idx)

            if len(possible_indices) == 1:
                idx = list(possible_indices)[0]
                a_val = idx >> 1
                b_val = idx & 1
                if not a_known:
                    wire_bits[A] = a_val
                    changed = True
                    a_known = True
                if not b_known:
                    wire_bits[B] = b_val
                    changed = True
                    b_known = True
                if not z_known:
                    wire_bits[Z] = gate.truth_table[(a_val, b_val)]
                    changed = True

            if z_known and a_known and not b_known:
                a_val = wire_bits[A]
                z_val = wire_bits[Z]
                possible_b = set()
                for bv in (0, 1):
                    if gate.truth_table[(a_val, bv)] == z_val:
                        possible_b.add(bv)
                filtered_b = set()
                for bv in possible_b:
                    idx = a_val * 2 + bv
                    if idx != pos:
                        filtered_b.add(bv)
                if len(filtered_b) == 1:
                    wire_bits[B] = list(filtered_b)[0]
                    changed = True

            if z_known and b_known and not a_known:
                b_val = wire_bits[B]
                z_val = wire_bits[Z]
                possible_a = set()
                for av in (0, 1):
                    if gate.truth_table[(av, b_val)] == z_val:
                        possible_a.add(av)
                filtered_a = set()
                for av in possible_a:
                    idx = av * 2 + b_val
                    if idx != pos:
                        filtered_a.add(av)
                if len(filtered_a) == 1:
                    wire_bits[A] = list(filtered_a)[0]
                    changed = True

    return wire_bits
```

so: for each gate, the derangement rules out one of the four original indices. combined with our known 64 bits, many gates have only one possible assignment for Bill's bits. learning one bit constrains downstream gates, which reveal more bits. tried forward-only propagation first but left too many unknowns. adding backward propagation (known output bit + one input bit = deduce the other) was the key. after both passes, fewer than 25 bits remained unknown.

brute-forced the rest against the encrypted flag:

```python
bill_bits = []
unknown = []
for i in range(64):
    if i in wire_bits:
        bill_bits.append(wire_bits[i])
    else:
        bill_bits.append(None)
        unknown.append(i)

for combo in range(1 << len(unknown)):
    bits = list(bill_bits)
    for j, pos in enumerate(unknown):
        bits[pos] = (combo >> (len(unknown) - 1 - j)) & 1

    wealth = int(''.join(str(b) for b in bits), 2)
    ct_bytes = int.to_bytes(ct_int, 32)
    key = int.to_bytes(wealth, 16)
    pt = AES.new(key, AES.MODE_ECB).decrypt(ct_bytes)

    try:
        decoded = pt.decode('utf-8')
        if 'FLAG' in decoded:
            print(f"Wealth: {wealth}")
            print(f"Flag: {decoded.strip()}")
            break
    except (UnicodeDecodeError, ValueError):
        continue
```

`FLAG{7h3Se_T4ble5_aR3_d3RAn9eD}`
