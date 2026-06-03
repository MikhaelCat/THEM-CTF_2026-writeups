# Ancient Signals writeup

## Task

We are given a challenge called `Ancient Signals` with `100` points and the following description:

```text
Our field agents recovered a secure comms package from an enemy operative. They built a makeshift tool to translate the weird signals into an audible frequency, but the extraction corrupted the software. Can you help us in fixing this software so we can hear what's on the tape?
```

The handout contains two files:

- `player.exe`
- `transmission.dat`

Flag format:

```text
THEM?!CTF{...}
```

## Initial analysis

The description tries to push us toward "repairing" the software and listening to the tape.
That is only partially true.

There are actually two separate things to inspect:

- the encrypted tape data in `transmission.dat`
- the Windows player binary `player.exe`

At first glance, the intended path seems to be:

1. fix the player,
2. decode the tape,
3. play the audio,
4. recover the flag from the sound.

But this challenge is a misdirection: the decoded audio is just a joke, and the **real flag is hidden inside the player binary**.

## Analyzing `transmission.dat`

The tape file does not look like a normal audio container.
It does not start with a `RIFF` header and appears to be encrypted.

After checking byte patterns, the key observation is that the data behaves like:

- 8-bit unsigned PCM
- XOR-encrypted with a repeating 128-byte key

For 8-bit unsigned PCM, silence is represented by `0x80`.

That gives a very useful known-plaintext primitive:

```python
key[i % 128] = data[i] ^ 0x80
```

if we can find a region that should decode to silence.

There is such a region in the file.
The block around `0x50..0xCF` repeats again immediately after it, which strongly suggests both decode to the same constant waveform, i.e. silence.

So the solution is:

1. recover the 128-byte XOR key from the silent area,
2. XOR-decrypt the whole file,
3. save the result as a wave file.

After decryption, the file starts with:

```text
RIFF .... WAVE
```

So the tape is valid audio after all.

## The tape is a red herring

Once decoded, the audio turns out to be a Rick Astley rickroll.

So even if we successfully "fix the software" and recover the audio, that does **not** give the flag.

This is the main trap in the challenge:

- the tape is solvable,
- the audio is real,
- but it is not the secret we actually need.

## Analyzing `player.exe`

The real flag is recovered from the Windows binary.

Looking through the data section reveals a short encrypted blob stored in `.data`.
That blob is not plaintext and is not derived from the audio output directly.

Further reversing shows that the player computes an XOR key from its own code:

- it takes a small slice of `.text`
- hashes it with `FNV-1a`
- uses the hash bytes as the XOR key for the hidden blob

In particular, the relevant helper is a small anti-tamper style function that checks whether the first bytes of the input are `"RIFF"`.

So the real workflow is:

1. identify the encrypted blob in `.data`,
2. identify the `.text` bytes used for hashing,
3. compute the `FNV-1a` hash of that code slice,
4. XOR-decrypt the blob with the derived key.

## Why "fixing the player" is unnecessary

The prompt says the software is corrupted and asks us to make the tape audible.
But the player is not really the obstacle.

The binary contains logic that checks whether the raw input starts with `RIFF`.
The encrypted `transmission.dat` obviously does not, so the program never reaches any useful "success" path for the actual challenge.

That means trying to patch the player into a working audio tool is extra work with no payoff.

The shortest route is to reverse the binary directly and extract the protected blob.

## Recovering the flag

After computing the correct `FNV-1a` value and XORing the hidden bytes, we obtain:

```text
THEM?!CTF{1mag1n3_gett1ng_r1ckr0ll3d_1n_tH3M?!C7F_xDDD}
```

## Final flag

```text
THEM?!CTF{1mag1n3_gett1ng_r1ckr0ll3d_1n_tH3M?!C7F_xDDD}
```
