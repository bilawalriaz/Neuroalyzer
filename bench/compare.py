#!/usr/bin/env python3
"""Diff the findings of two `scan --json` reports.

Usage: compare.py OLD.json NEW.json
Exits 1 if non-NER findings differ (they must be identical); NER differences are
counted per kind and printed so they can be judged. Timing fields are ignored.
"""
import json, sys, collections

def load(p):
    r = json.load(open(p))
    files = {}
    for tool in r.get("tools", []):
        for f in tool.get("files", []):
            files[f["path"]] = f
    return r, files

def split(findings):
    ner, other = collections.Counter(), collections.Counter()
    for x in findings or []:
        key = (x.get("type"), x.get("detector"))
        (ner if x.get("detector") == "ner" else other)[key] += x.get("count", 1)
    return ner, other

old_r, old = load(sys.argv[1])
new_r, new = load(sys.argv[2])
bad = 0
ner_old, ner_new = collections.Counter(), collections.Counter()
files_ner_diff = 0
for path in sorted(set(old) | set(new)):
    a, b = old.get(path, {}), new.get(path, {})
    (na, oa), (nb, ob) = split(a.get("findings")), split(b.get("findings"))
    if oa != ob or a.get("skipped") != b.get("skipped") or a.get("drift") != b.get("drift"):
        bad += 1
        if bad <= 20:
            print(f"NON-NER DIFF {path}\n  old={dict(oa)} skip={a.get('skipped')} drift={a.get('drift')}\n  new={dict(ob)} skip={b.get('skipped')} drift={b.get('drift')}")
    ner_old.update(na); ner_new.update(nb)
    files_ner_diff += na != nb
print(f"files: old={len(old)} new={len(new)}  non-NER mismatches: {bad}  files with NER differences: {files_ner_diff}")
for k in sorted(set(ner_old) | set(ner_new), key=str):
    o, n = ner_old[k], ner_new[k]
    print(f"  NER {k[0]:<10} old={o:>8} new={n:>8} delta={n-o:+d} ({(n-o)*100/max(o,1):+.2f}%)")
sys.exit(1 if bad else 0)
