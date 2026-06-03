# 🦀? writeup

## Challenge

We are given:

```text
crabbymonty.exe
```

Category: `reverse`

Description:

```text
Time for some rusty business
```

Flag format:

```text
THEM?!CTF{...}
```

## Final flag

```text
THEM?!CTF{a_sn4k3_4nd_a_cr4b_c4n_b3_g00d_fr13nd5}
```

## High-level solution idea

This challenge is not a normal native Rust flag checker. The executable contains an XOR-obfuscated `Python 3.12 .pyc` file, and the real flag validation logic lives there.

So the solution path is:

1. identify the binary as Rust;
2. find a suspicious large blob in `.rdata`;
3. notice that it is decoded with a simple `xor 0x69`;
4. recover a valid `pyc`;
5. disassemble the bytecode;
6. reconstruct `check_flag()`;
7. invert the transformation to recover the original passphrase.

## Initial binary analysis

First, check the file type:

```bash
file crabbymonty.exe
```

Result:

```text
PE32+ executable for MS Windows 6.00 (console), x86-64, 5 sections
```

So this is a 64-bit Windows PE.

### Imports and overall profile

A quick header dump is useful:

```bash
objdump -x crabbymonty.exe
```

Important observations:

- entrypoint: `0x1400284b0`
- standard Windows API imports;
- lots of Rust panic/runtime strings;
- `rust_rev.pdb` appears in the string table.

The binary is clearly Rust-based because of strings like:

```text
called `Result::unwrap()` on an `Err` value
/rustc/.../library\std\src\...
mainRUST_MIN_STACK
rust_panic
```

That strongly suggests that blindly reading `main` will include plenty of runtime noise, so it is better to search for constants and unusual data references first.

## Dynamic attempt

Trying to execute it under `wine` did not give a usable runtime path:

```text
[FATAL] CRITICAL EXCEPTION: 0x80040154
Unhandled memory fault ...
Subsystem initialization failed. Core dumped.
```

So instead of spending time on Windows emulation issues, static analysis is the fastest route here.

## Finding the suspicious data blob

Ordinary strings such as success/failure messages are not especially helpful. The important clue is a strange large data region in `.rdata`.

Relevant disassembly:

```asm
140001765: leaq 0x29e9d(%rip), %rbx   # 0x14002b609
...
140001780: xorb $0x69, %r15b
...
14000179c: cmpq $0xc2b, %r14
```

This tells us:

- there is a blob starting at `0x14002b609`;
- a loop processes `0xc2b` bytes;
- every byte is XORed with `0x69`.

That is a classic embedded-file pattern.

## Extracting the blob from `.rdata`

I extracted it directly from the PE using `pefile`.

```python
import pefile
from pathlib import Path

pe = pefile.PE("crabbymonty.exe")
rva = 0x2b609
size = 0xc2b

for s in pe.sections:
    va = s.VirtualAddress
    vs = s.Misc_VirtualSize
    raw = s.PointerToRawData
    if va <= rva < va + vs:
        off = raw + (rva - va)
        data = pe.__data__[off:off + size]
        break
else:
    raise RuntimeError("blob not found")

decoded = bytes(b ^ 0x69 for b in data)
Path("chall.pyc").write_bytes(decoded)
print(decoded[:16].hex())
```

After decoding, the first bytes became:

```text
cb0d0d0a000000003c50ee6906080000
```

That already looks like a valid `pyc` header.

## Why this is definitely Python bytecode

The bytes after the header match a marshalled code object:

```text
e3 00 00 00 ...
```

Loading it with `xdis` gives clean metadata:

- version: `Python 3.12.0`
- embedded filename: `chall.py`
- source size: `2054 bytes`

So the Rust executable really contains a hidden `chall.pyc`.

## Disassembling the `.pyc`

My local default `dis` was running on a newer Python version, so the cleanest route was using `uv` with Python 3.12.

```bash
uv run --python 3.12 python - <<'PY'
import marshal, dis
from pathlib import Path

b = Path("chall.pyc").read_bytes()
co = marshal.loads(b[16:])
dis.dis(co)
for c in co.co_consts:
    if hasattr(c, "co_name"):
        print("SUBCODE:", c.co_name)
        dis.dis(c)
PY
```

This reveals the module body and, more importantly, `check_flag`.

## Reconstructing `check_flag`

The function can be restored almost directly from the bytecode:

```python
import base64

def check_flag(user_input):
    target = [
        241, 250, 126, 93, 101, 32, 92, 189, 201, 144, 156, 157,
        61, 197, 242, 125, 64, 195, 80, 221, 116, 218, 238, 61,
        89, 80, 154, 29, 13, 138, 66, 253, 209, 112, 64, 93,
        69, 211, 66, 189, 41, 42, 242, 157, 29, 79, 204, 125,
        161, 28, 162, 221, 85, 95, 192, 61, 184, 252, 246, 29,
        109, 63, 170, 253, 48, 220, 178, 93, 165, 47, 180, 189,
        8, 188, 198, 157, 125, 255, 40, 125, 129, 138, 142, 221,
        181, 239, 36, 61, 153, 106, 194, 29, 77, 143, 156, 253,
        17, 74, 146, 93, 133, 140, 130, 189, 104, 60, 38, 157,
        93, 122, 26, 125, 225, 63, 240, 221, 149, 90, 22, 61,
        248, 252, 54, 29, 173, 63, 248, 253, 113, 255, 224, 93,
        229, 26, 226, 189, 72, 188, 10, 157, 189, 207, 108, 125,
        193, 138, 252, 221, 244, 204, 106, 61, 216, 124, 6, 29,
        141, 186, 194, 253, 81, 127, 192, 93, 197, 154, 212, 189,
        169, 60, 110, 157, 156, 108, 70, 125, 32, 28, 34, 221,
        213, 95, 64, 61, 57, 234, 118, 29, 236, 44, 56, 253,
        177, 131, 62, 14
    ]

    hex_str = user_input.encode().hex()
    spaced = " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))

    std_alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    cust_alpha = b"HIJKLMNOPQRSTUVWXYZABCDEFGhijklmnopqrstuvwxyzabcdefg6789012345+/"

    b64 = base64.b64encode(spaced.encode())
    custom_b64 = b64.translate(bytes.maketrans(std_alpha, cust_alpha)).decode()

    _pavel = True
    _damwan = (_pavel << 3) | (_pavel << 2) | _pavel
    _tao = (_pavel << 3) - _pavel
    _felon = (_pavel << 1) | _pavel
    _them = (_pavel << 8) | (_pavel << 7) | (_pavel << 5) | (_pavel << 2)

    encoded = []
    for i, c in enumerate(custom_b64):
        poly_key = (
            _damwan * (i ** _felon) +
            _felon * (i ** (_pavel << _pavel)) +
            _tao * i +
            _them
        ) & 255
        encoded.append(ord(c) ^ poly_key)

    if len(encoded) != len(target):
        return False
    return encoded == target
```

## Simplifying the constants

The funny variable names are just noise. Since `_pavel = True`, and in Python `True == 1`, we can simplify everything:

- `_damwan = (1 << 3) | (1 << 2) | 1 = 13`
- `_tao = (1 << 3) - 1 = 7`
- `_felon = (1 << 1) | 1 = 3`
- `_them = (1 << 8) | (1 << 7) | (1 << 5) | (1 << 2) = 420`
- `(_pavel << _pavel) = (1 << 1) = 2`

So the polynomial becomes:

```python
poly_key = (13 * (i ** 3) + 3 * (i ** 2) + 7 * i + 420) & 255
```

The full forward pipeline is therefore:

1. take user input;
2. convert it to bytes;
3. turn it into hex;
4. insert spaces between every byte;
5. base64-encode that spaced string;
6. swap the standard base64 alphabet for a custom one;
7. XOR each character with an index-dependent polynomial key;
8. compare the result with `target`.

## Inverting the check

The whole pipeline is reversible.

Forward direction:

```text
user_input
 -> hex
 -> spaced hex
 -> base64
 -> custom alphabet
 -> xor with poly_key
 -> target
```

Reverse direction:

```text
target
 -> xor with poly_key
 -> custom base64 string
 -> translate back to standard alphabet
 -> base64 decode
 -> remove spaces
 -> bytes.fromhex(...)
 -> original input string
```

## Solver script

Here is the full solve:

```python
import base64

target = [
    241, 250, 126, 93, 101, 32, 92, 189, 201, 144, 156, 157,
    61, 197, 242, 125, 64, 195, 80, 221, 116, 218, 238, 61,
    89, 80, 154, 29, 13, 138, 66, 253, 209, 112, 64, 93,
    69, 211, 66, 189, 41, 42, 242, 157, 29, 79, 204, 125,
    161, 28, 162, 221, 85, 95, 192, 61, 184, 252, 246, 29,
    109, 63, 170, 253, 48, 220, 178, 93, 165, 47, 180, 189,
    8, 188, 198, 157, 125, 255, 40, 125, 129, 138, 142, 221,
    181, 239, 36, 61, 153, 106, 194, 29, 77, 143, 156, 253,
    17, 74, 146, 93, 133, 140, 130, 189, 104, 60, 38, 157,
    93, 122, 26, 125, 225, 63, 240, 221, 149, 90, 22, 61,
    248, 252, 54, 29, 173, 63, 248, 253, 113, 255, 224, 93,
    229, 26, 226, 189, 72, 188, 10, 157, 189, 207, 108, 125,
    193, 138, 252, 221, 244, 204, 106, 61, 216, 124, 6, 29,
    141, 186, 194, 253, 81, 127, 192, 93, 197, 154, 212, 189,
    169, 60, 110, 157, 156, 108, 70, 125, 32, 28, 34, 221,
    213, 95, 64, 61, 57, 234, 118, 29, 236, 44, 56, 253,
    177, 131, 62, 14
]

std_alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
cust_alpha = b"HIJKLMNOPQRSTUVWXYZABCDEFGhijklmnopqrstuvwxyzabcdefg6789012345+/"

reverse_table = bytes.maketrans(cust_alpha, std_alpha)

custom_b64 = bytes(
    t ^ ((13 * (i ** 3) + 3 * (i ** 2) + 7 * i + 420) & 0xff)
    for i, t in enumerate(target)
)

std_b64 = custom_b64.translate(reverse_table)
spaced_hex = base64.b64decode(std_b64).decode()
hex_str = spaced_hex.replace(" ", "")
flag = bytes.fromhex(hex_str).decode()

print(flag)
```

Output:

```text
THEM?!CTF{a_sn4k3_4nd_a_cr4b_c4n_b3_g00d_fr13nd5}
```

## Local verification

I also verified the recovered string by running it back through the forward logic:

```python
assert check_flag("THEM?!CTF{a_sn4k3_4nd_a_cr4b_c4n_b3_g00d_fr13nd5}")
```

The assertion passes, so the solution is correct.

## Why this challenge is nice

This is a fun reverse task because it is not about deep crypto or huge native control flow. It is mostly about spotting the right abstraction layer:

- the outer wrapper is a Rust PE;
- inside it is a hidden Python bytecode blob;
- that blob is protected only by a tiny XOR layer;
- the flag check itself is just a reversible transformation chain.

Once the `xor 0x69`-encoded embedded file is identified, the task stops being “hard Rust reverse engineering” and becomes “extract and invert a Python checker”.
