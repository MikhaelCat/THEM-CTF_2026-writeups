# Cascadino Chain writeup

## Task

We are given a crypto challenge called `Cascading Chain` with `100` points and the following prompt:

```text
I built an unbreakable encryption chain, each key protects the next and the last loops back to the start. There's no way in... right?
```

We also get four hex strings:

```text
c1 = 36273f225d4e393b2414025f1030025f1030025f10301907035e145e0c082508520a0930001d081d1012
c2 = 0e021b000e021b000e021b000e021b000e021b000e021b000e021b000e021b000e021b000e021b000e02
c3 = 180504021805040218050402180504021805040218050402180504021805040218050402180504021805
c4 = 202020204b49263932131d5d06371d5d06371d5d0637060515590b5c1a0f3a0a440d1632161a171f0615
```

Flag format:

```text
THEM?!CTF{...}
```

## Observations

All four blobs have the same length, so this strongly suggests XOR rather than block ciphers or hashes.

The challenge text also tells us the structure:

- one key protects the next
- the last loops back to the start

That naturally translates to a closed XOR chain:

```text
c1 = flag ^ k1
c2 = k1   ^ k2
c3 = k2   ^ k3
c4 = k3   ^ flag
```

## Immediate invariant

If we XOR all four equations together, every secret value appears exactly twice:

```text
c1 ^ c2 ^ c3 ^ c4
= (flag ^ k1) ^ (k1 ^ k2) ^ (k2 ^ k3) ^ (k3 ^ flag)
= 0
```

And indeed:

```python
assert bytes(a ^ b ^ c ^ d for a, b, c, d in zip(c1, c2, c3, c4)) == b"\x00" * len(c1)
```

So the chain is internally consistent.

But this also shows the main problem:

- with only `c1..c4`, the system is underdetermined
- there are infinitely many valid `(flag, k1, k2, k3)`

So the challenge is **not** solvable from pure algebra alone.
We need one external constraint.

## The external constraint: flag format

We already know the flag must start with:

```text
THEM
```

From the first equation:

```text
c1 = flag ^ k1
```

we immediately get:

```text
k1[0:4] = c1[0:4] ^ b"THEM"
```

Let's compute it:

```python
>>> bytes(a ^ b for a, b in zip(c1[:4], b"THEM"))
b'bozo'
```

That is a huge hint.
The first 4 bytes of the first key are not random garbage but the very recognizable word:

```text
bozo
```

Since `c2` and `c3` clearly repeat with period 4, it is natural to try a 4-byte repeating key.

So we test:

```text
k1 = b"bozo" repeated
```

## Recovering the flag

Now the first equation becomes trivial:

```python
flag = c1 ^ (b"bozo" * 11)
```

because the ciphertext length is `42`, and `42 / 4 = 10` remainder `2`, so repeating the key is enough.

Running that gives:

```text
THEM?!CTF{x0r_x0r_x0r_cha1n1ng_g0es_brrrr}
```

## Verifying the full chain

To make sure this is not a coincidence, we can derive the other keys too:

```text
k2 = k1 ^ c2 = "lmao"
k3 = k2 ^ c3 = "them"
```

and then verify:

```text
k3 ^ flag == c4
```

Everything matches.

## Solve script

```python
c1 = bytes.fromhex("36273f225d4e393b2414025f1030025f1030025f10301907035e145e0c082508520a0930001d081d1012")

k1 = b"bozo" * 11
flag = bytes(a ^ b for a, b in zip(c1, k1))

print(flag.decode())
```

## Why the scheme fails

The author's claim is half-right:

- if we had no extra information, the closed XOR loop really would not reveal a unique plaintext
- but CTF flags always provide a strong known-plaintext crib

Once we know the flag starts with `THEM`, the first key leaks immediately.
And once one key leaks in a pure XOR chain, the whole construction collapses.

## Final flag

```text
THEM?!CTF{x0r_x0r_x0r_cha1n1ng_g0es_brrrr}
```
