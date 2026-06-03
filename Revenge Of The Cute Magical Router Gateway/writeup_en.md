# Revenge Of The Cute Magical Router Gateway writeup

## Task

We are given a high-value challenge called `Revenge of the Cute Magical Router Gateway` with the following story:

```text
Yet another router was found in the backrooms of THEM hq.
...
I strongly feel that the password might contain the string "them"
...
hint 1: ... rock is really popular in the password cracking scene. Maybe you should use rock too!
hint 2: I randomly tried a rlly long username, and somehow it took a lot longer for the router to respond.
hint 3: The Username and Password are both in the famous rockyou database leak.
```

The important facts are:

- both `username` and `password` are in `rockyou.txt`
- the password likely contains `them`
- response time changes depending on what we submit
- this is not really a normal web exploitation challenge

## Main idea

This challenge is a **timing side-channel over a login check**.

The hints point in exactly that direction:

- `rock` clearly means `rockyou`
- the long-username behavior means the router is probably doing a slow character-by-character comparison
- both username and password being in `rockyou` turns the problem from brute force over all strings into dictionary search over a known candidate set

So instead of attacking the web interface logically, we treat it like an oracle:

```text
send candidate -> measure latency -> infer how much of the comparison matched
```

## What the long username hint means

The second hint is the giveaway.

If sending a very long username makes the request noticeably slower, then the backend is probably using a comparison function whose running time depends on how many bytes it processes before stopping.

Typical bad patterns look like:

```c
strcmp(user_input, real_username)
strncmp(user_input, real_username, strlen(user_input))
memcmp(...)
for (...) if (a[i] != b[i]) return fail;
```

When this happens, latency often depends on:

- how long the submitted string is
- how many prefix characters match
- whether the username check is performed before the password check

That is enough to turn authentication into an information leak.

## Why `rockyou` matters so much

Without the wordlist, the side-channel would still be exploitable but painfully large.

With `rockyou.txt`, the search space collapses:

- valid username is one of the `rockyou` entries
- valid password is one of the `rockyou` entries

So the solve becomes:

1. identify the username using timing
2. lock in the correct username
3. identify the password using timing

This is much more like side-channel-assisted dictionary cracking than traditional web exploitation.

## Stage 1. Recover the username

The cleanest way is to submit:

- candidate username from `rockyou`
- fixed wrong password

and measure average response time over several trials.

If the server checks username first and only then checks password, the correct username should take longer because execution goes one step deeper into the login path before failing.

In practice I would:

1. deduplicate `rockyou`
2. batch requests over a subset first
3. repeat each candidate several times
4. rank candidates by median latency instead of single-shot latency

Median or trimmed mean is important because network jitter is noisy.

Pseudo-code:

```python
for username in rockyou:
    timings = []
    for _ in range(N):
        t0 = now()
        login(username, "definitely_wrong_password")
        timings.append(now() - t0)
    score[username] = median(timings)

best_usernames = top_k(score)
```

Usually only a very small set of usernames survives this filter.

## Stage 2. Refine with prefix grouping

If the implementation leaks character-by-character progress, we can do even better.

Instead of testing every word independently, we group candidates by prefix and compare group timings.

For example:

- all usernames starting with `a`
- all usernames starting with `b`
- ...

Then recursively:

- `th`
- `the`
- `them`

This turns the timing leak into a trie search.

Because both credentials are guaranteed to come from `rockyou`, prefix filtering is especially effective.

## Stage 3. Recover the password

Once the correct username is known, keep it fixed and repeat the same process for passwords.

Now the side-channel is cleaner because the server no longer fails at the username stage.

This is where the clue:

```text
the password might contain the string "them"
```

becomes useful.

So for the password search, I would prioritize:

- passwords containing `them`
- then the rest of `rockyou` if needed

That reduces request count and makes the attack much faster.

Pseudo-code:

```python
for password in prioritized_rockyou:
    timings = []
    for _ in range(N):
        t0 = now()
        login(real_username, password)
        timings.append(now() - t0)
    score[password] = median(timings)
```

Again, the best candidate is the one whose request consistently takes the longest or returns the success path.

## Practical notes

A few things matter a lot in real runs:

- use many repetitions per candidate
- prefer median over average
- sleep a little between requests
- keep the connection pattern stable
- test promising candidates again in a second pass

If the service is remote, naive single-request timing is too noisy.
The intended solve is statistical, not magical.

## Why this is not really a web challenge

The challenge text explicitly warns about this, and that is accurate.

The web page is just a convenient frontend for the oracle.
The real bug is:

- secret-dependent comparison time
- plus a small wordlist-constrained search space

So conceptually this is closer to:

- side-channel analysis
- dictionary cracking

than to normal web bugs like SQLi, XSS, or auth bypass.

## Final takeaway

The core lesson is simple:

- timing leaks are devastating when secrets come from a small dictionary
- splitting authentication into sequential checks makes the leak stronger
- even a tiny clue like "contains `them`" can collapse the remaining search space

This challenge is a nice example of how an apparently weak timing leak becomes fully practical once paired with `rockyou`.

## Note

The exact recovered `username/password` pair depends on interacting with the live instance and measuring its timing oracle.
In this local workspace I only had the writeup files and `rockyou.txt`, not the router service itself, so I documented the real solve path rather than fabricating final credentials.
