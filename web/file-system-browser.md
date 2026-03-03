---
title: "Where is my file?"

difficulty: Medium
description: "You've just started your first job and your boss gives you a simple task: find a 'special' file hidden somewhere in the filesystem of an old server with unpredictable behavior. Because of its size, you've been given one day to explore it. Your objective is to traverse the filesystem, identify the 'special' file, and deliver it to your boss. However, be careful not to stray from the initial path, as it may lead to ghost files!"
flag: "CSC{S0 mANY d1R3CTOrIE2 1n dI58E11EF}"
---

> *You've just started your first job and your boss gives you a simple task: find a 'special' file hidden somewhere in the filesystem of an old server with unpredictable behavior. Because of its size, you've been given one day to explore it. Your objective is to traverse the filesystem, identify the 'special' file, and deliver it to your boss. However, be careful not to stray from the initial path, as it may lead to ghost files!*

web app that shows a file browser UI. page loads with 10 root directories. clicking one fires a POST to `/subdirectories` with `{"dir": "/5eky64c1"}`.

the page includes an obfuscated `main.js` with a string rotation table. the table has format strings and `'flag'`/`'filename'`. Ran the IIFE rotation in node to deobfuscate. the interesting part is `loadDirectory`:

```js
async function loadDirectory(dirPath) {
    const response = await fetch('/subdirectories', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ dir: dirPath })
    });
    const contentType = response.headers.get('content-type') || '';

    if (contentType.includes('application/json'))
        dirs = parseJSON(await response.text());
    else if (contentType.includes('application/xml'))
        dirs = parseXML(await response.text());
    else if (contentType.includes('application/csv'))
        dirs = parseCSV(await response.text());
    else if (contentType.includes('application/nviso'))
        dirs = parseNVISO(await response.text());
    else if (contentType.includes('text/plain')) {
        const params = new URLSearchParams(await response.text());
        displayFlag(params.get('flag'));
    }
}
```

so each response comes back as one of five content types, picked randomly:

| Content-Type | Format |
|---|---|
| `application/json` | `{"dir": ["item1", "item2", ...]}` |
| `application/xml` | `<directories><dir name="item1"/></directories>` |
| `application/csv` | `dir\nitem1\nitem2\n...` |
| `application/nviso` | `nvisOitem1nvisOitem2nviso...` |
| `text/plain` | `filename=X&flag=Y` (URL-encoded params) |

the first four give directory listings of 10 items each. the fifth is what shows up at leaf level with a `flag` parameter.

## crawling the tree

I spent a while looking for patterns in the directory names. maybe they encoded coordinates, maybe there was a hash scheme, maybe alphabetical ordering meant something. they're random 8-character strings like `4u33p8lo` and `xd52ml3d`. nope.

tried path traversal,  URL-encoded variants, null bytes, double slashes. The server doesn't validate paths against anything real. if you POST `{"dir": "/literally/anything"}`, it returns a plausible directory listing or a fake flag response. every fabricated path is "valid" in the sense that you get a response, but it always gives `flag=not the flag`. the only paths that lead to the real flag are the ones the API itself gives you, starting from the 10 roots in the initial HTML.

i thought the `application/nviso` format might have special behavior, or that the flag only appeared in a particular content type. tested each one individually. they all return the same data in different serialization. 

so it's 4 levels deep, 10 branches at each level, 10,000 leaf `.txt` files total. every leaf returns `flag=not the flag` except one. brute force it is.

## the crawler

```python
import requests, json, re

BASE = "..."
s = requests.Session()

def fetch_dir(path):
    r = s.post(f"{BASE}/subdirectories", json={"dir": path}, timeout=10)
    ct = r.headers.get("content-type", "")
    if "text/plain" in ct:
        return ("flag", r.text)
    dirs = []
    if "application/json" in ct:
        dirs = json.loads(r.text).get("dir", [])
    elif "application/xml" in ct:
        dirs = re.findall(r'name="([^"]+)"', r.text)
    elif "application/csv" in ct:
        dirs = [l.strip() for l in r.text.strip().split("\n")[1:] if l.strip()]
    elif "nviso" in ct:
        dirs = [s.strip() for s in r.text.split("nviso") if s.strip()]
    return ("dirs", dirs)

def crawl(path="/"):
    kind, data = fetch_dir(path)
    if kind == "flag":
        if "not the flag" not in data:
            print(f"FLAG at {path}: {data}")
        return
    for d in data:
        crawl(d)

crawl()
```

needed to handle all five content types per response since the server picks one at random. ran it, took a few minutes to chew through the tree. one hit:

`CSC{S0 mANY d1R3CTOrIE2 1n dI58E11EF}`
