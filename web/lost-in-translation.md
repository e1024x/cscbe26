---
title: "Lost in Translation"

difficulty: Medium
description: "Welcome to Lost in Translation, the hottest new language learning platform! We've built a blazing-fast system to deliver vocabulary packs in Dutch, English, and French. Our cutting-edge architecture ensures lightning-speed content delivery straight to your browser. Can you uncover the platform's hidden secrets?"
flag: "(flag obtained, text not recorded)"
---

> *Welcome to Lost in Translation, the hottest new language learning platform! We've built a blazing-fast system to deliver vocabulary packs in Dutch, English, and French. Our cutting-edge architecture ensures lightning-speed content delivery straight to your browser. Can you uncover the platform's hidden secrets?*

web app with a `/lang-packs/js` endpoint serving localization files. nginx is mentioned all over the place, in headers, in error pages. werkzeug shows up in the response headers too (Python WSGI backend behind nginx).

the nginx mentions were the hint. there's a well-known nginx misconfiguration with `alias` directives where a missing trailing slash causes an off-by-one path traversal. [Orange Tsai covered this at BlackHat US 2018](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf) (slide 18).

the idea: if the nginx config has something like:

```nginx
location /lang-packs {
    alias /app/static/lang-packs/;
}
```

then requesting `/lang-packs../main.py` makes nginx resolve it to `/app/static/main.py` because the alias substitution doesn't enforce the path boundary. the trailing `../` escapes the intended directory.

since werkzeug was in the headers, the backend is a Python Flask/WSGI app. tried fetching `main.py`:

got the application source. the source code contained the path to the flag file, read it with the same traversal technique.

