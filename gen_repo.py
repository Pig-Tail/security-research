#!/usr/bin/env python3
"""Scaffold write-up folders for every PUBLIC advisory and rebuild the index.

Gate: only advisories whose GitHub page is public (published_at set) are included.
Embargoed/draft findings are never emitted. Runnable-PoC folders (those already
containing a poc/ dir) keep their hand-written README; missing ones get a templated
write-up. Source of truth: ../profile-glowup/cves.json (regenerated from live gh data).
"""
import json, os, glob

HERE = os.path.dirname(os.path.abspath(__file__))
CVES = os.path.join(HERE, "..", "profile-glowup", "cves.json")
REPO = {"NetCoreToolService": "SteeltoeOSS/NetCoreToolService"}  # display override

def ident(x):
    return x["cve"] if x["cve"] else x["ghsa"]

def folder(x):
    return f"{ident(x)}-{x['proj']}"

def adv_url(x):
    # repo field is owner/name in cves.json
    return f"https://github.com/{x['repo']}/security/advisories/{x['ghsa']}"

def has_poc(fdir):
    p = os.path.join(fdir, "poc")
    return os.path.isdir(p) and any(os.scandir(p))

def writeup(x):
    cve_line = f" · [{x['cve']}](https://www.cve.org/CVERecord?id={x['cve']})" if x["cve"] else ""
    return f"""# {ident(x)} — {x['proj']}

- **Advisory:** [{x['ghsa']}]({adv_url(x)}){cve_line}
- **Severity:** {x['sev'].capitalize()} · {x['cwe']}
- **Status:** publicly disclosed and fixed. Reported by **Pig-Tail** through coordinated disclosure.

## Summary

{x['summary']}

> **Write-up only.** No standalone runnable PoC is published for this finding here — refer to the
> linked advisory for full technical detail, affected range, and the fixed version.
"""

def main():
    d = json.load(open(CVES))
    pub = [x for x in d if x["public"]]
    created = 0
    for x in pub:
        fdir = os.path.join(HERE, folder(x))
        os.makedirs(fdir, exist_ok=True)
        rp = os.path.join(fdir, "README.md")
        if not os.path.exists(rp):
            open(rp, "w").write(writeup(x))
            created += 1

    # rebuild index rows from every public advisory
    order = {"critical": 0, "high": 1, "medium": 2, "moderate": 2, "low": 3}
    pub.sort(key=lambda x: (order.get(x["sev"], 4), x["proj"]))
    rows = []
    for x in pub:
        fdir = os.path.join(HERE, folder(x))
        poc = "✅ runnable" if has_poc(fdir) else "📄 write-up"
        proj = REPO.get(x["proj"], x["proj"])
        rows.append(f"| [{ident(x)}]({folder(x)}/) | {proj} | {x['summary'][:60]} ({x['cwe']}) | {x['sev'].capitalize()} | {poc} |")
    runnable = sum(1 for x in pub if has_poc(os.path.join(HERE, folder(x))))
    print(f"[+] folders now: {len(pub)} public advisories, {runnable} with runnable PoC, {created} write-ups created")
    return rows

if __name__ == "__main__":
    rows = main()
    open(os.path.join(HERE, "_index_rows.md"), "w").write("\n".join(rows))
    print("[i] index rows written to _index_rows.md")
