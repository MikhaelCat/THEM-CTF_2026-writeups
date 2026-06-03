# Eyes Chico writeup

## Task

We are given a Windows binary called `1983.exe`.

The relevant strings are:

```text
flag>
correct
wrong
```

So this is a flag checker.

Flag format:

```text
THEM?!CTF{...}
```

## Initial analysis

At first glance this looks like an ordinary crackme, but static analysis becomes messy very quickly.

The reason is that the checker logic is hidden behind a custom VM with:

- flattened control flow
- a jump-table dispatcher
- state mutation during dispatch itself

So even before the opcode body runs, the dispatcher is already changing internal state.

That makes a pure static reconstruction unnecessarily painful.

## Why static reversing hurts here

The VM does not behave like a clean switch on opcode values.

The effective behavior depends on prior state because the dispatch layer mutates parts of the state vector while deciding where to go next.

So:

- the same opcode byte can behave differently at different moments
- decompiler output becomes noisy
- control-flow flattening adds a large amount of fake structure

This is exactly the kind of binary where dynamic emulation is faster than heroic static cleanup.

## Practical solution path

The key idea is that we do **not** actually need to understand every opcode semantically.

The binary's job is to eventually fill a stack buffer with the expected bytes and then compare user input against that buffer.

So the simplest route is:

1. map the PE sections at their preferred virtual addresses,
2. recreate the same initial register and stack setup as `main`,
3. start emulation at the VM entry point,
4. hook writes into the stack buffer used for the comparison,
5. stop when execution returns to the prompt path,
6. read the fully populated buffer.

In other words, instead of solving the VM logically, we let the program compute the answer for us and just observe the resulting bytes.

## Why this works

The checker ultimately compares user input against a 113-byte buffer assembled by the VM.

Once emulation reaches the point where the prompt would be shown again, that buffer is already complete.

So the challenge reduces to:

- emulate one run,
- dump the final expected bytes,
- use them as the flag.

This bypasses the worst parts of the flattening and the mutating dispatcher.

## Recovered flag

Reading the final comparison buffer yields:

```text
THEM?!CTF{R3V3R53_3X3CU710N_VM_W17H_MU7471NG_R3G1573R5_4ND_C0N7R0L_FL0W_FL4773N1NG_M4K35_57471C_4N4LY515_P41NFUL}
```

The flag itself describes the defensive technique used by the crackme.

## Final flag

```text
THEM?!CTF{R3V3R53_3X3CU710N_VM_W17H_MU7471NG_R3G1573R5_4ND_C0N7R0L_FL0W_FL4773N1NG_M4K35_57471C_4N4LY515_P41NFUL}
```
