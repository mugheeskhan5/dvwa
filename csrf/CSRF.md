## DVWA CSRF Writeup
**Difficulty Levels Covered:** Low | Medium | High
**Vulnerability Class:** CWE-352 — Cross-Site Request Forgery
**Tools Used:** Browser, Burp Suite, self-hosted HTML page

### What is CSRF?

Cross-Site Request Forgery abuses the fact that browsers automatically attach cookies (including session cookies) to any request sent to a domain, regardless of which site the request originated from. If a logged-in user's browser visits a malicious page, that page can silently submit a request to the target application — and the browser will happily send the user's valid session cookie along with it. The application sees what looks like a legitimate, authenticated request and processes it.

The DVWA CSRF module simulates a password-change form. The vulnerability isn't in how the password is changed — it's that the form accepts the change request with no proof that the *user* intended to submit it, only that a valid session cookie was attached.

The payload used below is from my own lab folder — `exploit.html`, an auto-submitting form pointed at the DVWA password-change endpoint:

```html
<!DOCTYPE html>
<html>
<body onload="document.forms[0].submit()">
  <form action="http://localhost/vulnerabilities/csrf/" method="GET">
    <input type="hidden" name="password_new" value="hacked123">
    <input type="hidden" name="password_conf" value="hacked123">
    <input type="hidden" name="Change" value="Change">
  </form>
</body>
</html>
```

---

### Low Security

**What the Code Does Wrong**

The Low level password-change form has no protections whatsoever:

```php
if ($password_new == $password_conf) {
    $password_new = md5($password_new);
    // update password directly — no token check, no referer check
}
```

- No CSRF token — the request needs nothing but the two password fields and the session cookie
- No `Referer`/`Origin` check — the server doesn't care where the request came from
- The endpoint accepts `GET` requests — meaning the entire attack can even be delivered as a plain link, not just an auto-submitting form

**Exploitation**

Step 1 — Confirm the request shape

Change the password normally through the DVWA UI and observe the request in Burp Suite. It's a simple GET:

```
GET /vulnerabilities/csrf/?password_new=test123&password_conf=test123&Change=Change#
```

Step 2 — Host the malicious page

`exploit.html` reproduces that exact request as an auto-submitting form. When the `onload` handler fires, it submits the form to `http://localhost/vulnerabilities/csrf/` with `password_new` and `password_conf` both set to `hacked123`.

Step 3 — Deliver it to a logged-in victim

If a user who is currently authenticated to DVWA opens `exploit.html` in the same browser (e.g. via a phishing link, or simply hosting it and getting them to click through), their browser automatically attaches the DVWA session cookie to the forged request. The server has no way to distinguish this from the user intentionally changing their own password.

**Result:** The victim's DVWA password is silently changed to `hacked123` with no interaction beyond loading a page.

**Why Low Was Exploitable**

The server validates *that* a valid session made the request, but never validates *that the user meant to*. Since GET requests carry no built-in protection against forgery and the endpoint requires nothing session-specific beyond the cookie itself, any page the victim's browser loads can trigger the state change.

---

### Medium Security

**What Changed**

Medium adds a check on the `Referer` header:

```php
if (stripos($_SERVER['HTTP_REFERER'], $_SERVER['SERVER_NAME']) !== false) {
    // process password change
}
```

The server checks that the `Referer` header *contains* the application's own hostname somewhere in the string before accepting the request.

**Exploitation**

The check uses `stripos()` to look for the server's hostname as a **substring anywhere** in the `Referer` value — it doesn't validate that the Referer's actual origin matches, just that the hostname text appears somewhere in it.

This can be defeated by naming the attacker-controlled host or path to include the target's hostname as a substring. Serving the exploit page from a path or subdomain like:

```
http://localhost.attacker.com/exploit.html
```

or, when testing locally, simply hosting `exploit_localhost.html` from a directory path containing the string `localhost` satisfies `stripos()` even though the request did not originate from the real application.

The same `exploit.html`/`exploit_localhost.html` payload is reused unmodified — the bypass is entirely about *where* the page is hosted, not about changing the form itself:

```html
<body onload="document.forms[0].submit()">
  <form action="http://localhost/vulnerabilities/csrf/" method="GET">
    <input type="hidden" name="password_new" value="hacked123">
    <input type="hidden" name="password_conf" value="hacked123">
    <input type="hidden" name="Change" value="Change">
  </form>
</body>
```

**Result:** Password changed exactly as in Low, once the exploit page's URL contains the expected hostname substring.

**Why Medium Was Still Exploitable**

Substring matching on `Referer` is not origin validation. An attacker who controls any part of a URL — subdomain, path, or query string — can include the target's hostname as text without the request actually originating from the target's origin. `Referer` is also a client-supplied header in general and can be stripped or spoofed outright in some contexts, making it a weak signal on its own.

---

### High Security

**What Changed**

High introduces a genuine **CSRF token**:

```php
// On page load
$_SESSION['session_token'] = md5(uniqid(mt_rand(), true));

// On form submission
if ($_SESSION['session_token'] != $_REQUEST['user_token']) {
    die('CSRF token is incorrect');
}
```

Every time the password-change page is loaded, the server generates a fresh, unpredictable `user_token` and embeds it as a hidden field. The form submission must include the exact same token the server just issued to that session, or the request is rejected.

**Exploitation**

This is the point where `exploit.html` as written **stops working** — it has no way to know or include a valid `user_token`, since that value is unique per page-load and tied server-side to the victim's session. A static, pre-built HTML form simply cannot forge it in advance.

Genuinely defeating a properly implemented, per-request CSRF token this way generally requires a *second* vulnerability to leak the token — for example:

- An **XSS** flaw somewhere on the same origin that lets a script read the token out of the DOM before submitting the forged request itself (at which point it's really the XSS doing the work, not CSRF)
- A **subdomain takeover or misconfigured CORS** policy that lets an attacker-controlled origin read the token from the page
- Overly permissive **token validation** (e.g. accepting a blank/missing token, or one scoped globally rather than per-session) — which is a specific implementation bug, not a property of tokens in general

None of these apply to DVWA's High level as implemented — the token is properly random, tied to session, and checked with a strict comparison, so `exploit.html` correctly gets rejected with `CSRF token is incorrect` when tested against it.

**Result:** The forged request fails. This is the expected, correct outcome — High demonstrates what a working mitigation looks like rather than another bypass.

**Why High Resists This Class of Attack**

A CSRF token works because it's something the forged page cannot possibly know: it's generated server-side, unique per session/request, and never predictable from outside information the attacker has. Unlike the `Referer` check in Medium, a strict token comparison isn't fooled by clever URL construction — the attacker's page is simply missing information it has no way to obtain, short of a completely separate vulnerability.

---

### How to Actually Fix This

```php
// Generate a fresh, random token per session/page and store it server-side
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));

// Embed it in every state-changing form
// <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

// Validate with a constant-time comparison before processing
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'] ?? '')) {
    die('Invalid CSRF token');
}
```

A complete defence includes:

- **Anti-CSRF tokens** — unique, unpredictable, session-bound, and checked with a constant-time comparison on every state-changing request
- **SameSite cookies** — setting `SameSite=Lax` or `SameSite=Strict` on session cookies prevents browsers from attaching them to cross-site requests in the first place
- **Require POST for state changes** — never let sensitive actions (password change, fund transfer, account settings) be triggerable via a plain GET/link
- **Re-authentication for sensitive actions** — require the current password to change it, which a forged request can't supply
- **Proper origin validation** — check `Origin`/`Referer` as defence-in-depth only, using exact origin matching rather than substring checks, never as the sole control

### Key Takeaway

CSRF exploits the browser's default trust — cookies get attached automatically regardless of who asked for the request. Low showed what happens with no protection at all; Medium showed that origin checks are only as good as how strictly they compare (substring matching is not the same as exact matching); High showed what actually closes the gap: a value the forged page structurally cannot know in advance. `SameSite` cookies now provide a strong baseline in modern browsers, but a proper server-side token remains the most reliable control because it doesn't depend on browser/cookie configuration at all.

---
*Part of the DVWA Writeup Series*
*Previous: File Upload*
