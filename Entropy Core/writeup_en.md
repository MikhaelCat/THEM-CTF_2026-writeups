# Entropy Core writeup

## Task

We are given a Windows binary called `entropy_core.exe`.

From strings, the program presents itself as:

```text
[Entropy Core v1] quantum lattice primed -- insert star key:
```

and prints either:

```text
[Entropy Core] starlight conduit aligned. access accepted.
```

or:

```text
[Entropy Core] CRITICAL: warp drift -- reactor SCRAM.
```

Flag format:

```text
THEM?!CTF{...}
```

## First observations

This is not a normal "compare input with static string" crackme.

The binary wraps a custom VM:

- 16 registers
- 64-bit arithmetic
- a jump-table style opcode dispatcher
- an embedded bytecode program in `.rdata`

The interesting string:

```text
EntropyCoreV1!
```

is a trap if you overinterpret it.
There is a fake RC4-looking structure in the binary, but it is not the real obstacle.

The real problem is understanding the VM.

## VM layout

After reversing the dispatcher, the program turns out to:

1. read a candidate flag,
2. feed it byte-by-byte into a bytecode interpreter,
3. update a 16-register VM state,
4. compare the low byte of a derived value against a 36-byte target sequence embedded in the bytecode.

So this is essentially a custom verifier:

- each input byte influences VM state
- the bytecode transforms the state
- the result must match the hardcoded target bytes

## The two traps

This challenge is annoying mainly because of two reversing traps.

### 1. The fake key material

There is an RC4-looking region and the string `EntropyCoreV1!`, which makes it tempting to believe the whole challenge is a normal stream-cipher wrapper.

That wastes time.

The actual verification logic lives in the VM, not in a standard crypto primitive.

### 2. Shift operands are immediate bytes

The most important reversing detail is that operations such as:

- `ROL`
- `ROR`
- `SHL`
- `SHR`

do **not** use a register value as the shift amount.

Instead, the shift count is stored directly in the bytecode as the third operand byte.

If you misread this and treat the third byte as a register index, the whole semantics drift and every candidate solver fails.

This is exactly the kind of tiny operand-decoding mistake that makes a VM challenge feel impossible until corrected.

## Solving strategy

Once the VM semantics are reconstructed correctly, the checker becomes deterministic.

The practical path is:

1. disassemble the reachable opcodes,
2. emulate the embedded bytecode,
3. model how one input byte changes the VM state,
4. check the produced output byte against the corresponding target byte,
5. recover the flag one position at a time.

A greedy first-match approach does not work well because some early positions admit multiple printable bytes.

The reliable approach is depth-first search with backtracking over printable candidates.

That is enough because:

- the flag length is fixed by the checker,
- each position sharply constrains future state,
- bad branches die quickly.

## Recovered flag

After correcting the shift decoding and running a backtracking solver over printable ASCII, the unique valid input is:

```text
THEM?!CTF{Entr0py_C0r3_VM_S0_Funny!}
```

## Final flag

```text
THEM?!CTF{Entr0py_C0r3_VM_S0_Funny!}
```
