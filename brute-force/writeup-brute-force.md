# DVWA Brute Force Writeup

**Difficulty Levels Covered:** Low | Medium | High  
**Vulnerability Class:** CWE-307 — Improper Restriction of Excessive Authentication Attempts  
**Tools Used:** Burp Suite Intruder, Hydra, Python (requests)

---

## What is a Brute Force Attack?

A brute force attack is the process of systematically trying every possible password combination until the correct one is found. It is the "try everything until something works" approach to authentication bypass.

In practice, attackers don't generate random guesses — they use **wordlists**: precompiled lists of commonly used passwords, leaked credential databases, and dictionary words. The attack becomes dangerous when a login form places no restrictions on how many attempts can be made, how fast, or from where.

The effectiveness of brute force entirely depends on what the application does to make it costly — rate limiting, account lockout, CAPTCHA, CSRF tokens, and sleep delays are the common defences. DVWA demonstrates exactly what happens when these are missing or poorly implemented.

---

## Low Security

### What the Code Does Wrong

The Low level login form is a plain GET request with no protections of any kind:

- No rate limiting — requests can be sent as fast as the server can receive them
- No account lockout — failed attempts have no consequence
- No CAPTCHA — no human verification required
- No CSRF token — requests are completely stateless and replayable

The attacker can send thousands of password attempts per second with zero friction.

### Exploitation — Burp Suite Intruder

Burp Suite's Intruder tool automates the process of sending modified requests with different payloads on each attempt.

**Step 1 — Intercept a login attempt**

1. Open Burp Suite and launch its built-in browser
2. Navigate to the DVWA Brute Force page
3. Enable Intercept under the Proxy tab
4. Enter any username and password and click Login
5. The GET request appears in Burp Suite before it is sent

**Step 2 — Send to Intruder**

Right-click the intercepted request and select **Send to Intruder**.

**Step 3 — Configure the attack**

In the Intruder tab:

- Select the **Sniper** attack type — this tests a single field with the wordlist. Sniper is the correct choice here because we are targeting one specific parameter (password) while keeping everything else fixed
- Highlight the password value in the request and click **Add §** to mark it as the injection point

The request should look like:

```
GET /vulnerabilities/brute/?username=admin&password=§test§&Login=Login
```

**Step 4 — Load the wordlist**

Navigate to the **Payloads** tab and load your wordlist. RockYou (`rockyou.txt`) is the standard choice — it contains over 14 million real-world leaked passwords and is freely available. It comes pre-installed on Kali Linux at `/usr/share/wordlists/rockyou.txt`.

**Step 5 — Identify the successful attempt**

Start the attack. Watch the **Length** column in the results — a successful login returns a different page (with a welcome message) than a failed one, so the response length will be noticeably different from all the failed attempts. Click on the outlier to confirm the correct password in the response.

**Result:** Login credentials obtained with no resistance from the application.

### Why Low Was Exploitable

Zero friction for the attacker. No delays, no lockouts, no tokens. The application processes every request identically whether it is the first attempt or the ten-thousandth.

---

## Medium Security

### What Changed

Medium introduces one change in the source code:

```php
sleep(2);
```

A 2-second delay is added after every failed login attempt. The intent is to slow down brute force attacks — if every attempt takes 2 seconds, a 1 million entry wordlist would take weeks.

The problem: Burp Suite Community Edition sends requests **sequentially** — one at a time. With a 2-second sleep per request, Burp becomes impractically slow. However, tools like Hydra send requests in parallel across multiple threads, making the sleep delay far less effective.

### Exploitation — Hydra

Hydra is a parallelized login cracker that can send multiple simultaneous requests, effectively dividing the sleep penalty across threads.

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
localhost http-get-form \
"/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:H=Cookie: PHPSESSID=YOUR_SESSION_ID; security=medium:F=Username and/or password incorrect"
```

Breaking down the flags:

- `-l admin` — sets the username to test (lowercase L for a single username)
- `-P /usr/share/wordlists/rockyou.txt` — the wordlist file to use for passwords
- `http-get-form` — specifies the request type. Medium uses GET, so this matches
- The form string has three parts separated by `:` — the path, the parameters (`^USER^` and `^PASS^` are Hydra's placeholders), and `F=` which defines the failure string Hydra looks for to identify wrong passwords
- `H=Cookie:` — passes the session cookie so DVWA recognises the request as authenticated

Since we know the password is common, using a trimmed version of the wordlist saves time. Hydra's parallel threads absorb the 2-second sleep across multiple simultaneous connections.

**Result:** Valid password found significantly faster than Burp Suite would allow at this difficulty.

### Why Medium Was Still Exploitable

A sleep delay is a speed bump, not a wall. It raises the time cost of sequential attacks but is neutralised by parallel tools. Real rate limiting happens at the network or application layer — tracking attempts per IP, per session, or per account — not by delaying individual responses.

---

## High Security

### What Changed

High level introduces two protections on top of the sleep delay:

1. **CSRF token** — every page load generates a unique `user_token` value that must be submitted with each login attempt. The token changes after every request, making it impossible to replay the same request repeatedly
2. **Sleep delay** — still present from Medium

This breaks both Burp Intruder and Hydra in their standard configurations — they cannot automatically fetch a new token before each attempt. Burp Suite Professional handles this with its Macro feature, but the free Community Edition cannot.

The solution is a **custom Python script** that handles the token fetching manually before each password attempt.

### Exploitation — Custom Python Script

The script works in a loop:

1. Fetch the login page
2. Extract the `user_token` from the HTML
3. Submit a login attempt with that token and a password from the wordlist
4. Check the response for a success message
5. Repeat with a fresh token for the next password

```python
import requests
import re

session = requests.Session()

base_url = "http://localhost/vulnerabilities/brute/"
cookies = {"PHPSESSID": "YOUR_SESSION_ID", "security": "high"}

def get_token():
    r = session.get(base_url, cookies=cookies)
    match = re.search(r"user_token'\s+value='([a-f0-9]+)'", r.text)
    return match.group(1) if match else None

# Load from a file for real attacks:
# with open("/usr/share/wordlists/rockyou.txt", "r", errors="ignore") as f:
#     wordlist = [line.strip() for line in f]

wordlist = ["password", "letmein", "123456", "admin", "dvwa"]

for pw in wordlist:
    token = get_token()

    if not token:
        print("Could not extract token — check your session cookie")
        break

    r = session.get(base_url, params={
        "username": "admin",
        "password": pw,
        "Login": "Login",
        "user_token": token
    }, cookies=cookies)

    print(f"Tried: {pw}")

    if "Welcome to the password protected area" in r.text:
        print(f"\n>>> Found password: {pw}")
        break
```

**Key points about the script:**

- `requests.Session()` maintains cookies across requests automatically — the same session that fetched the token sends the login attempt
- The regex `user_token'\s+value='([a-f0-9]+)'` extracts the token from the raw HTML. This pattern matches DVWA's token field format
- The success condition checks for `"Welcome to the password protected area"` in the response — what the page displays on correct login
- The wordlist is hardcoded here for demonstration. For real use, replace it with the commented file-reading block to load `rockyou.txt` line by line

**To run:**

1. Log into DVWA and copy your `PHPSESSID` cookie from the browser's Developer Tools
2. Paste it into the script
3. Run with `python3 script.py`

**Result:** Script fetches a fresh token before each attempt, bypasses the CSRF protection, and identifies the correct password.

### Why High Was Still Exploitable

CSRF tokens protect against cross-site request forgery — an attacker on a different origin tricking a user's browser into submitting requests. They are not designed to prevent brute force from someone who can read the page directly. Since the script fetches the login page legitimately before each attempt, it receives a valid token just like a real user would. The token provides no protection against an attacker who can make GET requests to the same page.

---

## How to Actually Fix This

Proper brute force protection requires multiple layers working together:

```php
// Account lockout after N failed attempts
if ($failed_attempts >= 5) {
    // Lock account for 15 minutes
    // Alert the legitimate user via email
}

// Rate limiting per IP
if ($requests_per_minute > 10) {
    http_response_code(429);
    die("Too many requests");
}
```

A complete defence includes:

- **Account lockout** — disable login after a set number of failed attempts (typically 5–10) for a fixed period
- **Rate limiting** — restrict the number of login attempts per IP address per minute at the server or WAF level
- **CAPTCHA** — require human verification after a threshold of failed attempts. Unlike CSRF tokens, CAPTCHA is specifically designed to block automated requests
- **Multi-factor authentication** — even a correct password is not enough without the second factor, making the entire brute force effort useless
- **Credential stuffing detection** — monitor for known leaked password lists being tested against accounts

---

## Key Takeaway

Brute force protection is not one feature — it is a stack of controls. A sleep delay alone is beaten by parallel tools. A CSRF token alone is beaten by scripts that fetch tokens legitimately. Real protection requires rate limiting and lockout at the infrastructure level combined with MFA so that even a correct password is not sufficient for access.

---

*Part of the [DVWA Writeup Series](../README.md)*  
*Previous: [SQL Injection (Blind)](../sql-injection(blind)/writeup-blind.md)*  
*Read on MEDIUM: [MEDIUM](https://medium.com/@khanmughees587/brute-force-014d5491787c?postPublishedType=repub)*
