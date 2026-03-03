---
title: "Fortune Teller"

difficulty: Hard
description: "It's easy to see the present, Harder still to glimpse the future, But impossible to see the unseen past."
flag: "CSC{23Ems_11kE_y0u_AR3_quIT3_7h3_fOR7unE_7E1L3R_1nd3Ed}"
---

# Fortune teller

> *It's easy to see the present, Harder still to glimpse the future, But impossible to see the unseen past.*

Flask app with 2FA backed by a global [LCG](https://en.wikipedia.org/wiki/Linear_congruential_generator). two hardcoded accounts: `seer` (admin, sees the flag at `/fortune`) and `messenger` (normal user, gets their 2FA code emailed). the LCG state is shared between requests.

here's the relevant server code. first the LCG:

```python
LCG_A = 6364136223846793005
LCG_M = 2**64
LCG_C = 1442695040888963407

timestamp_ms = int(time.time() * 1000)
entropy = int.from_bytes(os.urandom(18), 'big')
lcg_seed = (timestamp_ms + entropy) % LCG_M

def lcg_next(seed):
    x = (LCG_A * seed + LCG_C) % LCG_M
    MASK_64 = (1 << 64) - 1
    x = (x ^ (x << 21)) & MASK_64
    x = (x ^ (x >> 35)) & MASK_64
    x = (x ^ (x << 4)) & MASK_64
    return x

def generate_2fa_code(seed):
    code_num = lcg_next(seed)
    code = str(code_num % 10**20).zfill(20)
    return code, code_num
```

And the login handler where admin vs non-admin code paths update `lcg_seed` in different order:

```python
@app.route('/login', methods=['GET', 'POST'])
def login():
    global lcg_seed

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        user = get_user_by_username(username)
        if not user or user['password_hash'] != hash_password(password):
            return render_template('login.html', error="Invalid credentials"), 401

        is_admin = (username == "seer")

        if is_admin:
            timestamp_ms = int(time.time() * 1000)
            entropy = int.from_bytes(os.urandom(18), 'big')
            lcg_seed = (timestamp_ms + entropy) % LCG_M
            code, lcg_seed = create_2fa_code(user['id'], lcg_seed)
        else:
            timestamp_ms = int(time.time() * 1000)
            entropy = int.from_bytes(os.urandom(18), 'big')
            code, lcg_seed = create_2fa_code(user['id'], lcg_seed)
            lcg_seed = (timestamp_ms + entropy) % LCG_M
            send_email(user['email'],
                      "Your Sacred Code for Fortune Teller",
                      f"Your Sacred Code is: {code}\n...")
```

So for admin: reseed THEN generate code. `lcg_seed` ends up as `seer_code_num`. for non admin: generate code THEN reseed. messenger's code uses whatever `lcg_seed` was before the reseed.

so the attack: login as seer, server reseeds and generates seer's code, `lcg_seed = seer_code_num`. then immediately login as messenger: messenger's code is `lcg_next(seer_code_num)`. read messenger's code from webmail, invert the LCG, recover seer's code.

all the XOR-shift steps and the LCG are invertible (A is odd so the modular inverse exists). undo in reverse order.

important detail: the 2FA code is `code_num % 10^20`, displayed as a 20-digit string. but `2^64 = 18446744073709551616 < 10^20`. the modulo is a no op. no information lost.

here's the inversion code:

```python
LCG_A = 6364136223846793005
LCG_M = 2**64
LCG_C = 1442695040888963407
MASK_64 = (1 << 64) - 1
LCG_A_INV = pow(LCG_A, -1, LCG_M)

def invert_xor_lshift(val, shift):
    x = val
    pos = shift
    while pos < 64:
        chunk_mask = ((1 << shift) - 1) << pos
        x = x ^ ((x << shift) & chunk_mask & MASK_64)
        pos += shift
    x &= MASK_64
    return x

def invert_xor_rshift(val, shift):
    x = val
    pos = 64 - shift
    while pos > 0:
        chunk_start = max(pos - shift, 0)
        chunk_bits = pos - chunk_start
        chunk_mask = ((1 << chunk_bits) - 1) << chunk_start
        x = x ^ ((x >> shift) & chunk_mask)
        pos = chunk_start
    x &= MASK_64
    return x

def lcg_prev(code_num):
    x = code_num
    x = invert_xor_lshift(x, 4)
    x = invert_xor_rshift(x, 35)
    x = invert_xor_lshift(x, 21)
    seed = ((x - LCG_C) * LCG_A_INV) % LCG_M
    return seed
```

`CSC{23Ems_11kE_y0u_AR3_quIT3_7h3_fOR7unE_7E1L3R_1nd3Ed}`
