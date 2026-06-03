# Good9 writeup

## Task

We are given a challenge called `Good9` with the attached Android application:

- `nightnight.apk`

The APK contains:

- `classes.dex`
- `classes2.dex`
- `lib/arm64-v8a/libsilence.so`
- `lib/x86_64/libsilence.so`
- two suspicious assets:
  - `assets/218a844439e58d15043399c3d9be4ca009ebeb51c237c33d4315771af5973c6c`
  - `assets/b86e8f6ffb52c768dd5b27bde4e53176d58552012a252e11e923406a095cd6d6`

That already suggests a multi-stage mobile reversing challenge:

- Java/Kotlin front-end
- native logic in `libsilence.so`
- hidden payload stored in assets

## High-level idea

This app is intentionally split into layers.

The first DEX does **not** directly contain the flag logic.
Instead it:

1. loads a native library,
2. derives an intermediate key,
3. decrypts a hidden DEX asset,
4. loads that DEX at runtime,
5. mixes Java-side and native-side secrets,
6. uses the final derived key to decrypt the flag.

So the challenge is really a chained reverse pipeline rather than a single bug.

## Java recon with JADX

Opening the APK in JADX quickly reveals the important pieces:

- `FlagApplication` loads `libsilence.so`
- `Night.loadKey(AssetManager)` runs early
- the button path calls `Night.prepareVM(getClassLoader(), getAssets())`
- the returned object implements some `VM` interface
- `Night.getKey()` is passed into `vm.getFlag(...)`
- `Night.bridge(byte[])` exists but is native

The key observation here is:

- the value returned by `Night.getKey()` is **not** the final flag key
- it is only a stage key used to unlock the next layer

That prevents the common mistake of trying to decrypt everything directly from the first recovered secret.

## Native entry: `libsilence.so`

From there the real work starts in `libsilence.so`.

The best pivot is `JNI_OnLoad`.

Tracing from it shows:

- early anti-debug checks
- runtime string decryption
- dynamically built `RegisterNatives`
- native handlers for `loadKey`, `prepareVM`, `bridge`, and a fake VM path

This means exported symbols alone are not enough.
Important JNI names only appear after the app decodes them at runtime.

## Runtime string decoding

One of the first useful reversing wins is the encrypted string decoder.

By following it, we can recover strings such as:

- `lab/nightjar/darkness/Night`
- `lab/nightjar/darkness/Night$NightVM`
- `loadKey`
- `prepareVM`
- `bridge`
- `getFlag`
- `dalvik/system/InMemoryDexClassLoader`
- `lab.hiddenvm.RealVM`

That already exposes the broad architecture:

- a fake visible VM in the main app
- a hidden real VM in a secondary DEX

## Anti-debug behavior

The native library is hostile to dynamic analysis.

It performs several anti-debug checks, including the standard trio:

- `ptrace(PTRACE_TRACEME)`
- `TracerPid` checks via `/proc/self/status`
- Frida/Gadget scans via `/proc/self/maps`

The important twist is that these checks do not necessarily crash the app immediately.
Instead they poison internal state.

So a sloppy bypass may still let execution continue, but all later outputs become wrong:

- bad stage key
- bad hidden DEX decrypt
- bad final bridge key

That makes this challenge much more annoying than a normal "if debugger then exit".

## Stage 1 key derivation

The first real secret is derived through a native pipeline:

```text
seed asset -> pre_transform -> custom VM -> post_transform -> StageKey
```

The 40-byte asset:

```text
assets/b86e8f6ffb52c768dd5b27bde4e53176d58552012a252e11e923406a095cd6d6
```

feeds into that process.

### `pre_transform`

This stage mixes the seed through:

- S-box lookups
- rotates
- byte swaps
- round constants
- anti-debug poison influence

Its output becomes the initial memory/register state for the VM.

### Native VM

The VM then decrypts bytecode from `.rodata`, reconstructs its dispatch table, and executes a custom instruction set over the transformed state.

The intended pain points are:

- bytecode is encrypted
- handler table is obfuscated
- dispatch is not readable from strings alone

The clean way to solve this is either:

- reverse handlers and write a Python emulator
- or patch the anti-debug logic, run once, and dump the post-VM state

### `post_transform`

After the VM finishes, a final transformation compresses the VM output into a 40-byte ASCII-looking string.

That value is the **StageKey**.

Again, this is not the final AES flag key.

## Stage 2: decrypt hidden DEX

The larger asset:

```text
assets/218a844439e58d15043399c3d9be4ca009ebeb51c237c33d4315771af5973c6c
```

is an encrypted payload.

Its structure is:

```text
salt[16] || iv[16] || ciphertext
```

Using the recovered `StageKey`, the app derives a decryption key via:

```text
PBKDF2-HMAC-SHA1(StageKey, salt, 100000, dkLen=32)
```

and then decrypts with:

```text
AES-256-CBC
```

This yields a hidden DEX, which can then be loaded in JADX.

## Hidden DEX: `lab.hiddenvm.RealVM`

Inside the decrypted payload, the real logic lives in:

```text
lab.hiddenvm.RealVM
```

This class reveals an important design point:

- the final flag decryption key is not derived from `StageKey` alone
- Java computes an intermediate 32-byte share
- that share is sent into the native `Night.bridge(...)`
- native code finalizes the real bridge key

So the pipeline is deliberately split between:

- Java-side derivation
- native-side finalization

That prevents a one-layer-only solve.

## Java share formula

The hidden DEX computes a 32-byte `javaShare` roughly as:

```text
SHA-256("NightNight.RealVM.v2" || stageKey || SHARE_CT || JAVA_NONCE)
```

Then:

```text
bridgeKey = Night.bridge(javaShare)
```

and finally:

```text
flag = AES-256-CBC-decrypt(FLAG_CT, bridgeKey, zero_iv)
```

So after finding `FLAG_CT`, `SHARE_CT`, `JAVA_NONCE`, and the exact concatenation order, we still must understand `Night.bridge(...)`.

## Native bridge

Returning to Ghidra, the final native function takes the 32-byte Java share and performs another transformation pass.

This is the last gate.

The bridge logic typically checks:

- share length
- share contents after mixing
- poisoned anti-debug state

and derives the final AES key used on the flag ciphertext.

Once `bridgeKey` is reconstructed correctly, the final decryption succeeds.

## Final solve path

The full solve is:

1. inspect APK in JADX
2. identify `Night.loadKey`, `Night.prepareVM`, `Night.bridge`
3. extract `libsilence.so`
4. reverse runtime string decoder
5. trace dynamic `RegisterNatives`
6. neutralize or model anti-debug poisoning
7. reverse `pre_transform`
8. decrypt and emulate the native VM
9. reverse `post_transform` to recover `StageKey`
10. decrypt hidden DEX asset with PBKDF2 + AES-CBC
11. inspect `lab.hiddenvm.RealVM`
12. recover Java-side share derivation
13. reverse `Night.bridge(byte[])`
14. derive final `bridgeKey`
15. decrypt final flag ciphertext

## Why this challenge is good

What makes `nightnight.apk` nice is that none of the individual pieces are exotic:

- JNI registration tricks
- anti-debug poisoning
- encrypted string tables
- hidden DEX loading
- small custom VM
- PBKDF2 + AES wrapping

But chaining all of them together forces a disciplined workflow.
Trying to shortcut any single layer usually gives a believable but wrong intermediate output.

That is the real theme of the challenge:

- every stage looks almost sufficient
- but only the full chain reveals the actual flag

## Note

In this workspace I had the APK and a detailed local outline of the reversing pipeline, but not the fully reconstructed emulator scripts or final decrypted flag bytes.
So I wrote the writeup around the real solving architecture and artifact flow rather than inventing a fake final flag.
