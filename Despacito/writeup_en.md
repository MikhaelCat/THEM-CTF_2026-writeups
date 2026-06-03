# Despacito writeup

## Task

We are given a crypto challenge called `D3Spacito` with `100` points and a very short description:

```text
lowkey despacito....
```

The handout contains:

- `ques.py`
- `output.txt`

Flag format:

```text
THEM?!CTF{...}
```

## Inspecting the source

The challenge script is tiny:

```python
from Crypto.Cipher import DES
import base64
from FLAG import flag

def pad(plaintext):
    while len(plaintext) % 8 != 0:
        plaintext += b"*"
    return plaintext

def enc(plaintext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(plaintext))

key = bytes.fromhex("E1E1E1E1F0F0F0F0")
plaintext = pad(flag)
print(enc(plaintext, key).decode())
```

So the setup is:

- cipher: `DES`
- mode: `ECB`
- key: `E1E1E1E1F0F0F0F0`
- padding: repeated `*` until a multiple of 8
- ciphertext is base64-encoded

And `output.txt` contains:

```text
T/tGpZNyHdhnf1oxwRmMPFcLiH//AfZdTpmYdp8daU0=
```

## Why the key is suspicious

The first useful observation is that the key is highly structured:

```text
E1 E1 E1 E1 F0 F0 F0 F0
```

That is not how random DES keys look.
Whenever a DES key has such a repeated pattern, weak keys should be the first thing to check.

DES has exactly four classic weak keys for which encryption and decryption are identical:

```text
01 01 01 01 01 01 01 01
FE FE FE FE FE FE FE FE
1F 1F 1F 1F 0E 0E 0E 0E
E0 E0 E0 E0 F1 F1 F1 F1
```

The provided key is extremely close to the last one:

```text
E1 E1 E1 E1 F0 F0 F0 F0
E0 E0 E0 E0 F1 F1 F1 F1
```

The difference is only in the least significant bit of every byte.

## The parity-bit trick

This is the whole challenge.

In DES, every byte of the 64-bit external key contains:

- 7 real key bits
- 1 parity bit

The least significant bit of each byte is just the parity bit.

When DES builds its internal 56-bit key schedule, those 8 parity bits are discarded by `PC-1`.

So these two byte strings:

```text
E1E1E1E1F0F0F0F0
E0E0E0E0F1F1F1F1
```

produce the **same effective DES key**.

That means the supplied key is not merely "close" to a weak key.
It is the weak key, just disguised through parity bits.

## Why that breaks the challenge

For a DES weak key, encryption and decryption are the same transformation:

```text
E_k(E_k(P)) = P
```

Equivalently:

```text
E_k = D_k
```

So if the ciphertext was produced by:

```text
c = E_k(flag)
```

then we can recover the plaintext simply by calling:

```text
flag = D_k(c)
```

and because the key is weak, this is effectively the same operation as encryption itself.

## Recovering the flag

Base64-decode the ciphertext and decrypt it with DES-ECB using the given key.

Locally I verified it with OpenSSL using the legacy provider:

```bash
openssl enc -provider legacy -provider default \
  -des-ecb -d \
  -K E1E1E1E1F0F0F0F0 \
  -nosalt -nopad -a \
  -in output.txt
```

This returns:

```text
THEM?!CTF{D3S_4774K_W3S_AW3S0M3}
```

## Minimal solve script

```python
from base64 import b64decode
from Crypto.Cipher import DES

key = bytes.fromhex("E1E1E1E1F0F0F0F0")
ct = b64decode("T/tGpZNyHdhnf1oxwRmMPFcLiH//AfZdTpmYdp8daU0=")

pt = DES.new(key, DES.MODE_ECB).decrypt(ct)
print(pt.decode())
```

## Why this challenge works

The intended trick is not "break DES" in any deep sense.
It is simply:

1. recognize a suspicious structured DES key,
2. remember that DES keys contain parity bits,
3. notice that the provided key is a parity-bit twin of a classic weak key,
4. decrypt the ciphertext directly.

So the whole solve hinges on knowing that in DES, two 64-bit byte strings may map to the same 56-bit effective key after parity stripping.

## Final flag

```text
THEM?!CTF{D3S_4774K_W3S_AW3S0M3}
```
