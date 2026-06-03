# phantom writeup

## Task

We are given a service called `phantom`.
It accepts hex-encoded bytecode for a custom VM.

Flag format:

```text
THEM?!CTF{...}
```

## Initial analysis

Strings immediately show that this is not a classic menu-based pwn, but a custom bytecode interpreter:

```text
"The dead speak in bytecode..."
Submit your phantom script as hex-encoded bytecode.
Max code size: 2048 bytes (4096 hex chars)
```

The built-in error messages are also very useful:

```text
invalid register
truncated PUSH
truncated POP
truncated JMP
truncated JZ
truncated JNZ
truncated PUSHR
truncated MOV
truncated INC
truncated PEEK
truncated POKE
unknown opcode
```

`checksec` shows:

- `NX enabled`
- `PIE disabled`
- `statically linked`
- `stripped`

That makes exploitation easier:

- code addresses are fixed
- we can build `ROP` directly from the main binary

## Program behavior

The program prints a banner, reads one hex string, decodes it into bytecode, and executes it:

```text
phantom> [*] Loaded %zd bytes of bytecode. Executing...
```

The decoded bytecode is limited to `2048` bytes.

## VM reconstruction

The main interpreter is located at `0x4019ee`.

Reconstructing the dispatch logic gives the following rough opcode map:

- `0x01` - `HALT`
- `0x02` - `PUSH imm64`
- `0x03` - `POP reg`
- `0x04` - `ADD`
- `0x05` - `SUB`
- `0x06..0x0b` - arithmetic / bitwise ops
- `0x0c` - comparison, result stored in an internal flag
- `0x0d` - `JMP imm16`
- `0x0e` - `JZ imm16`
- `0x0f` - `JNZ imm16`
- `0x10` - print top of stack
- `0x11` - `DUP`
- `0x12` - `SWAP`
- `0x13` - `PUSHR reg`
- `0x14` - `INC reg`
- `0x15` - `PEEK reg`
- `0x16` - `POKE reg`
- `0x17` - `MOV dst, src`

The important part is that the entire VM state lives inside the interpreter's local stack frame:

- register area
- VM stack
- `ip/sp` counters
- the decoded bytecode buffer

That makes `PEEK` and `POKE` the most interesting instructions.

## Vulnerability

The critical bug is that `PEEK` and `POKE` use a register value as an index into a stack-slot array, but **do not perform bounds checking** on that index.

In simplified form, the logic is basically:

```c
value = frame[reg[idx] + CONST];      // PEEK
frame[reg[idx] + CONST] = value;      // POKE
```

The VM only validates:

- whether the register number is in `0..15`
- whether the VM stack has enough elements for the instruction itself

It does **not** validate whether the register-derived index stays within the intended array.

This gives us:

- out-of-bounds read via `PEEK`
- out-of-bounds write via `POKE`

## Why this becomes code execution

Because the interpreter is a normal function, its stack frame contains:

- saved `RBP`
- saved `RIP`
- local variables
- decoded bytecode

With OOB access we can:

1. read the saved `RBP`
2. derive useful stack addresses
3. overwrite the saved return address
4. place a `ROP` chain right after it

So in the end this becomes a regular stack-based `ROP` exploit, except the write primitive comes from the VM bug rather than a classic overflow.

## Useful offsets

During debugging, the relevant stack slots turned out to be:

- `saved rbp` at index `0x4e`
- `saved rip` at index `0x4f`

That is enough to:

- leak the current frame base with `PEEK 0x4e`
- overwrite the return path with `POKE 0x4f` and onward

## Exploitation strategy

The exploit has 3 stages.

### 1. Recover stack addresses

The bytecode first:

- reads `saved rbp`
- computes the current stack frame base
- derives absolute addresses for:
  - the `/home/flag.txt` string
  - a read buffer on the stack

### 2. Write controlled data onto the stack

Using `POKE`, we place:

- the string `/home/flag.txt\x00`
- a buffer for `read`
- the `ROP` chain itself

### 3. Hijack the interpreter return

Since the saved return address is overwritten, once the VM finishes, execution flows into our `ROP` chain.

The chain performs:

1. `open("/home/flag.txt", 0, 0)`
2. `read(3, buf, 0x100)`
3. `write(1, buf, 0x100)`
4. `exit(0)`

## ROP chain

Because the binary is non-PIE and statically linked, all gadgets were taken directly from `phantom`.

For example:

- `pop rdi ; ret`
- `pop rsi ; ret`
- `pop rdx ; pop rbx ; ret`
- `pop rax ; ret`
- `syscall ; ret`

That is enough for a syscall-based `ROP` chain.

## Local validation

Before using the remote service, the exploit was validated locally against a readable file such as `/etc/hostname`.

Once the stack offsets were adjusted correctly, the bytecode successfully opened the file and printed its contents.

That confirmed that:

- the OOB read/write primitive works
- the saved `RIP` is controllable
- the `ROP` chain executes correctly

## Remote exploitation

The same payload was then sent to the service:

```text
nc 45.130.164.173 30207
```

The service returned the flag:

```text
THEM?!CTF{ph4nt0m_byt3c0d3_vm_3sc4p3_m4st3r}
```

## Flag

```text
THEM?!CTF{ph4nt0m_byt3c0d3_vm_3sc4p3_m4st3r}
```
