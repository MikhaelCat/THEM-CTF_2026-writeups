# Last dance

## Task

> A virtualized and packed Lua malware loader was recovered from a compromised CI worker. Reverse the custom VM and extract the real flag.

Flag format: `THEM?!CTF{...}`

## Files

- `n00t.lua`

The file looked like a virtualized Lua checker with a custom VM, but that was mostly a decoy.

## Initial unpacking

The outer script was a wrapper around an embedded blob:

1. Extract the large base64 payload from `n00t.lua`.
2. Decode it.
3. XOR the decoded bytes with the hardcoded key.
4. Save the result as `payload_stage1.luac`.

That gives a Lua 5.1 bytecode chunk.

## Stage 1 analysis

Since the environment did not have a matching Lua 5.1 disassembler, the chunk had to be parsed manually.

The important prototypes were:

- `root.15` - final flag validator
- `root.17` - custom VM interpreter
- `root.8` - helper that strips the `THEM?!CTF{...}` wrapper
- `root.9` to `root.14` - helper runners and decoys

## Important observation

At first glance the intended path looked like full VM reversal.
After reconstructing the closure wiring, the real flow became clear:

- `root.15` checks that the candidate is a string
- it verifies total length `48`
- it checks the prefix `THEM?!CTF{`
- it checks the trailing `}`
- then it extracts the inner part with `candidate:sub(11, -2)`

So the unknown core has length `37`.

## The VM was mostly bait

The bytecode really contained a custom VM with:

- opcode tables
- segmented memory descriptions like `text`, `data`, `heap`
- host API names such as `open`, `read`, `mmap`, `socket`
- extra wrappers using `coroutine`, `xpcall`, `__gc`, and metatables

But the real flag check did not require solving the VM itself.

## Real checker logic

The meaningful path reduced to a linear system over modulo `257`.

Two transformation functions were recovered from the chunk:

```lua
f1(v, i) = ((v - 91) - i) * 121 % 257
f2(v, i) = ((v - 91) - i * 3) * 121 % 257
```

From the root chunk it was possible to reconstruct:

- a `37 x 37` coefficient matrix
- a target vector of length `37`

This gave a system of the form:

```text
A * x = b (mod 257)
```

where `x` is the 37-byte inner flag string.

Solving it with Gaussian elimination modulo `257` produced the plaintext core.

## Recovered core

```text
m37474bl35_4r3_cur53d_ok_ok;;!!_ok;:!
```

## Final flag

```text
THEM?!CTF{m37474bl35_4r3_cur53d_ok_ok;;!!_ok;:!}
```

## Takeaway

The main trick of the challenge was to avoid getting trapped inside the fake-heavy VM path.
The fastest route was:

1. unpack `n00t.lua`
2. parse the Lua 5.1 bytecode
3. identify the real validator
4. reduce the checker to modular linear algebra
5. solve for the 37-character core

