# checker writeup

## Task

We are given a binary called `checker`.
The flag format is `THEM?!CTF{...}`.

## Initial analysis

Running `file` immediately shows that the binary is:

- `PE32+ executable`
- `x86-64`
- Windows console program

String extraction and metadata strongly suggest it was built with Go:

- lots of `runtime.*`
- `fmt.*`
- symbols like `main.(*nodeA).Check`

That is important because the validation logic is not deeply obfuscated. Instead, it is split into several small Go functions.

## Program behavior

Running the binary under `wine` shows that the flag must be passed as a command-line argument:

```text
Usage: ./chall '<flag>'
```

Invalid input produces:

```text
Wrong!
```

## Useful functions

Using Go metadata and `pclntab`, we can recover the relevant functions:

- `main.(*nodeA).Check`
- `main.(*nodeB).Check`
- `main.(*nodeC).Check`
- `main.(*nodeD).Check`
- `main.(*nodeE).Check`
- `main.buildMaze`
- `main.main`

From there, the challenge becomes reconstructing what each `Check` function does.

## Overall structure

`main.main` allocates a `0x28 = 40` byte buffer and copies `min(len(arg), 40)` bytes from the user input.

Then it creates 5 nodes, each validating one 8-byte chunk.

So the flag is checked as 5 independent blocks:

```text
[0:8] [8:16] [16:24] [24:32] [32:40]
```

## Node A

The first function uses two 8-byte immediates and checks:

```text
input[i] XOR const1[i] == const2[i]
```

This directly recovers the first block:

```text
THEM?!CT
```

## Node B

The second function reads a table from `.rdata` corresponding to `F{n0rm4L` and compares values after `rol 3`.

Since the same rotate-left-by-3 transformation is applied to both the input byte and the constant byte, the block can be read directly:

```text
F{n0rm4L
```

## Node C

The third function uses the table `_g0r0ut1`.

Its check has two parts:

1. the sum of all input bytes must match the sum of the constant bytes
2. the XOR relation between input and constant bytes must also match

This confirms the third block:

```text
_g0r0ut1
```

## Node D

This was the trickiest part.

The function uses the 8-byte sequence:

```text
b0 a1 92 d5 d7 cd 9d 95
```

At first glance it is easy to misread this as a cumulative sum check, which leads to garbage.
The correct logic is:

- initial previous value: `0x42`
- each step compares `input[i] + previous_input`
- then `previous_input` becomes the current `input[i]`

In other words:

```text
x0 + 0x42 = 0xb0
x1 + x0   = 0xa1
x2 + x1   = 0x92
...
```

Solving this correctly yields:

```text
n3_val1d
```

## Node E

The fifth function validates a transformation of the form:

```text
y = (7 * x) mod 251
```

The 8 bytes stored on the stack are:

```text
b1 3b 55 2d 7a 00 00 00
```

This recovers the final meaningful block:

```text
at0r}
```

followed by three zero bytes, because the actual flag is shorter than 40 bytes and the buffer was zero-initialized.

So the meaningful tail is:

```text
at0r}
```

## Reconstructing the flag

Now concatenate the 5 blocks:

```text
THEM?!CT
F{n0rm4L
_g0r0ut1
n3_val1d
at0r}
```

Which gives:

```text
THEM?!CTF{n0rm4L_g0r0ut1n3_val1dat0r}
```

## Verification

Running:

```text
wine checker 'THEM?!CTF{n0rm4L_g0r0ut1n3_val1dat0r}'
```

produces:

```text
Correct!
```

## Flag

```text
THEM?!CTF{n0rm4L_g0r0ut1n3_val1dat0r}
```
