## DVWA Weak Session IDs Writeup
**Difficulty Levels Covered:** Low | Medium | High
**Vulnerability Class:** CWE-330 — Use of Insufficiently Random Values
**Tools Used:** Browser DevTools, Burp Suite Repeater/Sequencer, Python (requests, hashlib)

### What is a Weak Session ID Vulnerability?

Session IDs are supposed to be the one thing that stands between an attacker and impersonating a logged-in user — if you can guess or predict a valid session ID, you don't need a password at all. A session ID is only as strong as its unpredictability. If it's generated from a small, guessable, or sequential source (a counter, a timestamp, a weak hash of either), an attacker who can observe a handful of legitimate session IDs can work out the pattern and compute a future or past one that belongs to someone else.

The DVWA Weak Session IDs module issues a `dvwaSession` cookie each time the "Generate" button is clicked, and each difficulty level changes how that value is derived.

---

### Low Security

**What the Code Does Wrong**

The Low level uses a **simple incrementing counter** as the session ID:

```php
$_COOKIE['dvwaSession'] = $last_session_id + 1;
```

Each click of "Generate" just adds 1 to whatever the last value was. There is no randomness in the value at all — it's a plain sequential integer.

**Exploitation**

Step 1 — Observe the pattern

Click "Generate" a few times and record the cookie value after each click using browser DevTools (Application → Cookies) or Burp Suite Proxy history:

```
dvwaSession=1000
dvwaSession=1001
dvwaSession=1002
```

Step 2 — Predict a session

Once the increment-by-one pattern is confirmed, any other session ID in that range can simply be guessed — no computation needed:

```
dvwaSession=1003
```

Step 3 — Hijack

Set the browser's cookie to a guessed value for a session that should belong to another (authenticated) user and reload an authenticated page. If that ID was ever issued to a logged-in session, the guess grants that session's access.

**Result:** Any session ID in the observed range is trivially predictable — no tooling beyond a browser required.

**Why Low Was Exploitable**

The "session ID" carries zero entropy. A counter is deterministic by definition; observing two consecutive values reveals the entire generation algorithm.

---

### Medium Security

**What Changed**

Medium replaces the raw counter with an **MD5 hash of the counter**:

```php
$_COOKIE['dvwaSession'] = md5($last_session_id + 1);
```

At first glance an MD5 hash looks random — 32 hex characters gives no obvious pattern like `1000`, `1001`, `1002` does.

**Exploitation**

The weakness isn't in MD5 itself — it's that the **input space being hashed is tiny and predictable**. MD5 is a hash function, not a source of randomness: if the input is a small incrementing integer, the output is exactly as predictable as the integer was, just obfuscated in appearance.

Step 1 — Observe a value and infer the counter

Generate a session and note the hash, e.g.:

```
dvwaSession=1679091c5a880faf6fb5e6087eb1b2dc
```

Step 2 — Brute-force the small input space

Since the underlying value is just an incrementing integer, an attacker doesn't need to reverse MD5 (which is one-way) — they just need to **hash a range of plausible counter values themselves** and compare:

```python
import hashlib

target = "1679091c5a880faf6fb5e6087eb1b2dc"

for i in range(0, 100000):
    if hashlib.md5(str(i).encode()).hexdigest() == target:
        print(f"Counter value: {i}")
        break
```

Because the input space is small (a counter, not a random 128-bit value), this brute force completes almost instantly. Once the counter is recovered, the *next* session ID is just `md5(counter + 1)` — fully predictable again.

**Result:** The hash adds visual obfuscation but no real entropy; the underlying sequential value is recovered in a trivial local brute force, and future session IDs are predicted the same way as in Low.

**Why Medium Was Still Exploitable**

Hashing a low-entropy input does not create high entropy output — it just disguises it. MD5 is also fast to compute by design, making brute-forcing a small input space (like a counter that might realistically be in the thousands or millions) computationally trivial. Security here depends entirely on the *unpredictability of the input*, which was never addressed.

---

### High Security

**What Changed**

High hashes the counter **combined with the server's current time**:

```php
$_COOKIE['dvwaSession'] = md5($last_session_id + 1 . time());
```

The intent is to add entropy from the timestamp so the hash can't be brute-forced from the counter alone.

**Exploitation**

`time()` returns Unix time in whole seconds — a value that is itself easy to know within a very small margin, since an attacker observing the request also knows roughly what time it was sent (to within a second or two, accounting for latency and clock differences).

Step 1 — Capture a session ID and the approximate request time

Note both the `dvwaSession` value and the timestamp of the request (from Burp's request log, or simply the local time at the moment "Generate" was clicked).

Step 2 — Brute-force the reduced search space

Instead of brute-forcing an unbounded range, the attacker only needs to try:
- A small range of plausible counter values (as in Medium)
- A small window of Unix timestamps around the known request time (e.g. ±5 seconds to account for latency/clock skew)

```python
import hashlib
import time

target = "e99a18c428cb38d5f260853678922e03"
approx_time = int(time.time())  # captured near the moment of the request

for t in range(approx_time - 5, approx_time + 5):
    for counter in range(0, 10000):
        candidate = f"{counter}{t}"
        if hashlib.md5(candidate.encode()).hexdigest() == target:
            print(f"Counter: {counter}, Time: {t}")
            break
```

This turns what looks like a large search space (counter × all possible timestamps ever) into a small, tractable one (counter × a handful of seconds around a known moment), because the timestamp component contributes far less real uncertainty than it appears to.

**Result:** With a captured session ID and a reasonably accurate idea of when it was issued, the value is still brute-forceable in a short, bounded search.

**Why High Was Still Exploitable**

Adding a timestamp increases the *apparent* entropy of the input without adding much *real* unpredictability from the attacker's perspective — if you can observe roughly when a request happened, you've already narrowed the timestamp component down to a handful of candidates. The fundamental problem carries over from Medium: hashing predictable, low-entropy, or partially-known inputs never produces a cryptographically unpredictable output, no matter how many such inputs are combined.

---

### How to Actually Fix This

```php
// Use a cryptographically secure random value with real entropy — not a hash of predictable inputs
$_COOKIE['dvwaSession'] = bin2hex(random_bytes(32)); // 256 bits of real randomness

// Set proper cookie security attributes
setcookie('dvwaSession', $session_id, [
    'httponly' => true,
    'secure'   => true,
    'samesite' => 'Strict',
]);

// Expire and rotate the session ID after login and periodically during use
session_regenerate_id(true);
```

A complete defence includes:

- **Cryptographically secure random generation** — `random_bytes()` / `CSPRNG`-backed generators, never counters, timestamps, or hashes of either
- **Sufficient length/entropy** — at minimum 128 bits of real randomness so brute-forcing the space is computationally infeasible
- **Session regeneration** — issue a fresh session ID after login and at privilege changes, so a leaked pre-auth ID is useless post-auth
- **`HttpOnly`, `Secure`, `SameSite` cookie flags** — reduce the ways a valid session ID could be captured or replayed in the first place
- **Session expiry/timeout** — bound the window during which any given ID is even valid, limiting the value of successfully predicting one

### Key Takeaway

A "random-looking" value is not the same as a random value. Hashing something predictable — a counter, a timestamp, or both together — only changes the *appearance* of the session ID, not its true entropy. Every level in this module fails for the same underlying reason: the generation algorithm derives session IDs from inputs an attacker can observe, narrow down, or brute-force, rather than from a properly seeded cryptographic random number generator. Real session ID security starts and ends with using a CSPRNG with adequate length — everything else is decoration.

---
*Part of the [DVWA Writeup Series](../README.md)*  
*Previous: [CSRF](../csrf.md)*
