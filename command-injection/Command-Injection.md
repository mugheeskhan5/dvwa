## DVWA Command Injection Writeup
**Difficulty Levels Covered:** Low | Medium | High
**Vulnerability Class:** CWE-78 — Improper Neutralization of Special Elements used in an OS Command
**Tools Used:** Browser (manual testing), Burp Suite Repeater, Netcat

### What is Command Injection?

Command injection happens when an application takes user input and passes it directly into a system shell command without properly sanitizing it. If the backend concatenates user-supplied data into a call like `system()`, `exec()`, `shell_exec()`, or `passthru()`, an attacker can append their own shell operators (`;`, `&&`, `|`, `||`, backticks, `$()`) to the input and get the underlying operating system to run arbitrary commands — not just the one the application intended.

The DVWA Command Injection module simulates a "ping a host" utility: the app takes an IP address, runs it through `ping`, and prints the result. The vulnerability lies in *how* that IP address reaches the shell.

---

### Low Security

**What the Code Does Wrong**

The Low level takes the `ip` parameter and concatenates it straight into a shell command with no filtering:

```php
$cmd = shell_exec('ping -c 4 ' . $target);
```

There is no input validation, no character blacklist, and no escaping. Anything appended after a valid IP is passed straight to the shell.

**Exploitation**

Step 1 — Confirm normal behaviour

Enter a valid IP (e.g. `127.0.0.1`) and submit. The page returns standard `ping` output, confirming the input reaches a real shell command.

Step 2 — Inject a chained command

Since the backend uses `shell_exec` with no sanitisation, shell metacharacters are passed through untouched. Submitting:

```
127.0.0.1 && whoami
```

causes the server to run `ping -c 4 127.0.0.1` **and then** `whoami`, appending the output of both to the page.

Other useful operators to test:

- `;` — runs the second command regardless of whether the first succeeds
- `&&` — runs the second command only if the first succeeds
- `|` — pipes the output of the first command into the second
- `` ` `` or `$()` — command substitution, runs inline

Step 3 — Escalate

Once command execution is confirmed, standard reconnaissance and payload commands work as if typed directly into a shell:

```
127.0.0.1 && id
127.0.0.1 && cat /etc/passwd
127.0.0.1 && uname -a
```

**Result:** Full arbitrary command execution as the web server user, with zero obstruction.

**Why Low Was Exploitable**

User input reaches `shell_exec` with no validation whatsoever. Any shell metacharacter is honoured exactly as it would be in a terminal.

---

### Medium Security

**What Changed**

Medium introduces a **blacklist** that strips out a couple of specific strings before the command is built:

```php
$substitutions = array(
    '&&' => '',
    ';'  => '',
);
$target = str_replace(array_keys($substitutions), $substitutions, $target);
```

Only `&&` and `;` are removed. The filter is a simple string replace, not a proper parser, and it only accounts for two of the many shell operators available.

**Exploitation**

Since the blacklist only blocks `&&` and `;`, every other chaining operator still works untouched:

```
127.0.0.1 | whoami
127.0.0.1 || whoami
```

`|` pipes command output and is not on the blacklist at all, so it works exactly as in Low.

It's also possible to defeat the blacklist for the *blocked* characters themselves, because `str_replace` only removes the literal substring once — inserting a duplicate around it leaves one copy behind:

```
127.0.0.1 &&& whoami
```

Here `&&` is stripped out of `&&&`, leaving a single `&` behind, which is itself a valid (if less clean) shell operator for backgrounding/chaining a command.

**Result:** Command execution restored using an operator the blacklist never accounted for.

**Why Medium Was Still Exploitable**

Blacklisting specific substrings is a losing game — the shell has far more metacharacters (`|`, single `&`, backticks, `$()`, newlines) than any short blacklist will ever cover, and naive string replacement can be defeated by simply duplicating the blocked token.

---

### High Security

**What Changed**

High uses a **regex-based blacklist** and only allows input matching an expected IP-like pattern before further processing, blocking a much larger set of characters:

```php
$substitutions = array(
    '&'  => '',
    ';'  => '',
    '| ' => '',
    '-'  => '',
    '$'  => '',
    '('  => '',
    ')'  => '',
    '`'  => '',
    '||' => '',
);
```

Notice the entry `'| ' => ''` — it blocks a **pipe followed by a space**, not a bare pipe character.

**Exploitation**

The filter blocks `| ` (pipe-space) but not a pipe with no trailing space, or a pipe followed immediately by a command with no space before it. Submitting:

```
127.0.0.1 |whoami
```

sends the pipe straight through because the literal substring `"| "` never appears — there's a space *before* the pipe, not after it.

**Result:** Command execution still achieved by exploiting the exact string the blacklist was written to match, rather than the character itself.

**Why High Was Still Exploitable**

A pattern-match blacklist is only as strong as its exact patterns. Filtering `"| "` instead of `"|"` blocks one specific formatting of the payload while leaving the underlying dangerous character completely usable. This is the same root cause as Medium — sanitisation is being done by matching strings the developer thought an attacker would type, not by controlling what the shell is allowed to interpret.

---

### How to Actually Fix This

Blacklisting shell metacharacters is fundamentally the wrong approach — there will always be an operator, encoding, or spacing variant that wasn't anticipated. Proper fixes avoid the shell entirely wherever possible:

```php
// Never build shell strings from user input.
// Use an allow-list + native functions instead of shell_exec/system.

if (filter_var($target, FILTER_VALIDATE_IP)) {
    $output = shell_exec('ping -c 4 ' . escapeshellarg($target));
} else {
    die('Invalid IP address');
}
```

A complete defence includes:

- **Input validation via allow-list, not blacklist** — validate that the input actually matches the expected format (a valid IPv4/IPv6 address) before it goes anywhere near a command
- **Avoid shell execution entirely** — where possible, use language-native functions or libraries instead of spawning a shell (e.g. a native ICMP library instead of shelling out to `ping`)
- **`escapeshellarg()` / `escapeshellcmd()`** — if shelling out is unavoidable, properly escape arguments so metacharacters are treated as literal text, not shell syntax
- **Least privilege** — run the web server process with minimal OS permissions so even successful injection has limited blast radius
- **WAF / IDS rules** — as a defence-in-depth layer, not a primary control

### Key Takeaway

Command injection defences fail in the same pattern seen across Medium and High: developers try to enumerate and block *bad* input instead of defining and enforcing what *good* input looks like. Every blacklist — whether a plain string match or a regex — has gaps, because the shell has dozens of ways to chain, substitute, and pipe commands. The only durable fix is to never let user input reach a shell interpreter unescaped, and to validate against a strict allow-list before it gets anywhere near `exec`-family functions.

---
*Part of the [DVWA Writeup Series](../README.md)*  
*Previous: [Brute Force](../brute-force.md)*
