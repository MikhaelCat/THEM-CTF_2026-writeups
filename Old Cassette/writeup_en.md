# Old Cassette writeup

## Task

We are given a challenge called `Old Cassette`.

The handout contains a single file:

- `main.bin`

Flag format:

```text
THEM?!CTF{...}
```

## First look

The file size is only about `3.2 KB`, which is a strong hint that this is not a native executable but some kind of VM or console ROM.

A quick hex dump immediately gives it away:

```text
00E0 1280
```

In CHIP-8 notation this is:

- `00E0` - clear screen
- `1280` - jump to `0x280`

So this challenge is a CHIP-8 ROM.

That already tells us a lot:

- code is mapped starting at `0x200`
- graphics are simple monochrome sprites
- there is probably no anti-debugging or OS-specific trickery
- the solution is likely pure ROM analysis

## General structure of the ROM

After disassembling the ROM, the important pieces are:

- `0x2c0` - the core state transition routine
- `0x322` - a table dispatcher that selects one of several data regions
- `0x900` - the main routine that performs all rounds and paints characters
- `0xdd2` - a drawing helper that maps character codes to CHIP-8 glyph sprites

The key observation is that the program never asks for input.
Its only purpose is to **compute characters and draw them onto the screen**.

So instead of trying to "play" the ROM, we only need to answer:

1. how is each character produced?
2. where is each character drawn?

## The main routine at `0x900`

The code at `0x900` clears the display, initializes a two-byte state, and then repeats the same pattern 32 times.

The initial state is:

```text
VA = 0xA7
VB = 0xC3
```

Each round does three things:

1. advance the internal state many times,
2. derive one printable character from the new state,
3. draw that character at some `(x, y)` position.

The repeated blocks are easy to spot because they all look like:

```text
set a counter
call 0x282 / 0x2ac
derive a byte from tables
call 0xdd2 to draw it
```

The first 16 rounds use explicit counters:

```text
1, 4, 16, 64, 256, 1024, ...
```

So these are simply powers of 4.

The last 16 rounds use a wrapper that repeatedly runs the same transition with all counter bytes set to `0xff`, which looks terrifying if you read it naively.

That is the intended scare factor of the challenge.

## The state machine at `0x2c0`

The subroutine at `0x2c0` transforms the 16-bit state `(VA, VB)` into a new pair `(VA', VB')`.

At a high level it does:

1. copy the current state into working registers,
2. read one byte from a lookup table at `0x800 + VB`,
3. XOR that byte with `VB`,
4. XOR again with a constant chosen from the top two bits of `VB`,
5. add the result into `VB`,
6. mix and shift the 16-bit intermediate state five times,
7. produce the next `(VA, VB)`,
8. store the new state bytes at `0x58b` and `0x58c`.

This routine is a **pure function** of only 16 bits of state.
That matters much more than the arithmetic itself.

Because there are only `2^16 = 65536` possible states, repeated application of the function must eventually enter a cycle.

So even if the ROM asks for absurd numbers of iterations, the trajectory cannot keep producing new states forever.

## Why brute force is the wrong approach

If we literally emulate every call count, the later rounds are enormous.

The helper at `0x2ac` effectively performs:

```text
255 * (2^32 - 1)
```

state transitions per round.

That is far too much for straightforward emulation.

But once we remember that the state space is tiny, the correct strategy is:

1. iterate the state machine from `(0xA7, 0xC3)`,
2. record the first time each state appears,
3. detect the eventual cycle,
4. answer `state_after(N)` in O(1).

When I did that, the trajectory looked like this:

- tail length: `329`
- cycle length: `34`

So after only a few hundred transitions, every future state is periodic.

That completely collapses the challenge.

## Reconstructing `state_after(N)`

Let:

- `prefix` be the non-repeating part,
- `cycle` be the repeating part.

Then:

```python
def state_after(n):
    if n < tail_len:
        return states[n]
    return states[tail_len + ((n - tail_len) % cycle_len)]
```

With this shortcut, even "astronomical" rounds become trivial.

## How one character is computed

After advancing the state for a round, the ROM derives one character code from the new `(VA, VB)`.

The relevant sequence is:

```text
V0 = VA
V1 = 7
V0 &= 7
call 0x322
V1 = offset
I += V1
V0 = mem[I]
V9 = V0
V9 ^= VA
V9 ^= VB
```

So the produced character is:

```text
char = mem[BASE[VA & 7] + offset] ^ VA ^ VB
```

where `BASE[...]` comes from the dispatcher at `0x322`.

That dispatcher selects one of these regions:

```text
0 -> 0x400
1 -> 0x460
2 -> 0x4c0
3 -> 0x520
4 -> 0x600
5 -> 0x660
6 -> 0x6c0
7 -> 0x720
```

Each round also hardcodes:

- one `offset`
- one `(x, y)` draw position

So once we can compute the final state for each round, the rest is straightforward.

## Extracting all 32 characters

The ROM contains 32 repeated draw blocks.

For each one I extracted:

- the iteration count,
- the offset into the selected table,
- the screen coordinates.

Then the solve logic becomes:

1. start from `(VA, VB) = (0xA7, 0xC3)`,
2. advance the state by the round's counter,
3. compute the character byte,
4. place it at the recorded `(x, y)`,
5. sort all characters top-to-bottom and left-to-right.

The recovered screen text is:

```text
THEM?!CTF{
0LD_T4P3_N
3V3R_D1E5K
7}
```

## Final flag

```text
THEM?!CTF{0LD_T4P3_N3V3R_D1E5K7}
```

## Takeaway

The challenge looks like a nightmare because it disguises a small-state recurrence behind huge counters.

But the real lesson is simple:

- if a transformation is deterministic,
- and the state space is small,
- then repeated execution is a cycle problem, not a performance problem.

Once the state machine is modeled correctly, the rest is just extracting coordinates and table offsets from the main routine.
