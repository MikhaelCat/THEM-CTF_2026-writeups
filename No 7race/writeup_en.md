# No 7race writeup

## Task

We are given a crypto challenge called `No 7race`.

The handout contains a single script:

- `challenge.py`

Flag format:

```text
THEM?!CTF{...}
```

## Reading the challenge

The entire logic is:

```python
flag = open("flag.txt","rb").read()
if len(flag) > 50:
    exit()

a = int.from_bytes(open("flag.txt","rb").read(), byteorder='big')

b = a << 77777
b = str(b)
if not b.endswith('03081127692533913997381228658418928780421416188103339458770036280397929450297959557812089439331054492922876854076547798835969658432397983993314299716042752'):
    exit()
```

So the challenge gives us a condition on the decimal suffix of:

```text
a << 77777
```

where `a` is the big-endian integer representation of the flag.

## Rewriting the condition

Left shift by `77777` is just multiplication by `2^77777`, so:

```text
b = a * 2^77777
```

The condition:

```text
str(b).endswith(target)
```

means exactly:

```text
b ≡ target (mod 10^155)
```

because the target suffix has `155` decimal digits.

So we get:

```text
a * 2^77777 ≡ target (mod 10^155)
```

This is now a modular arithmetic problem.

## Split the modulus with CRT

We factor:

```text
10^155 = 2^155 * 5^155
```

and analyze the equation modulo each part.

### Modulo `2^155`

Since:

```text
2^77777
```

contains far more than `155` factors of 2, we have:

```text
2^77777 ≡ 0 (mod 2^155)
```

So:

```text
a * 2^77777 ≡ 0 (mod 2^155)
```

This tells us only that the target suffix must also be `0 mod 2^155`.
It gives no information about `a`.

### Modulo `5^155`

Here the situation is different.
Because `gcd(2, 5) = 1`, the value `2^77777` is invertible modulo `5^155`.

So we can solve:

```text
a ≡ target * (2^77777)^(-1) (mod 5^155)
```

In Python this is just:

```python
inv = pow(2, -77777, 5**155)
a = (target * inv) % (5**155)
```

## Why the solution is unique in practice

Formally, this only gives `a` modulo `5^155`.

But the challenge also says the flag length is at most `50` bytes.
That means `a` is small enough that the valid ASCII flag is the only realistic candidate in that residue class.

Once converted back to bytes, the result is immediately recognizable.

## Solve script

```python
target = int("03081127692533913997381228658418928780421416188103339458770036280397929450297959557812089439331054492922876854076547798835969658432397983993314299716042752")

mod5 = 5**155
inv = pow(2, -77777, mod5)
a = (target * inv) % mod5

flag = a.to_bytes((a.bit_length() + 7) // 8, "big")
print(flag.decode())
```

Running this yields:

```text
THEM?!CTF{NUMB3R_TH30R3M_1S_FUN}
```

## Final flag

```text
THEM?!CTF{NUMB3R_TH30R3M_1S_FUN}
```
