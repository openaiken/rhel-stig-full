from __future__ import absolute_import, division, print_function

__metaclass__ = type

"""Semantic coverage check for the RHEL-09-654xxx audit rule requirements.

The STIG shows the expected rules as auditctl -l would print them. A host can
meet a requirement with rules written differently: other keys, the syscalls
in another order or merged into one rule, a -w watch instead of an
arch-specific -F path rule, auid!=unset for auid!=-1. Text comparison reports
all of those as findings (the formal role checks its own lines in
/etc/audit/rules.d/audit.rules, so it did exactly that on hosts hardened any
other way). This compares what events the rules record instead.

A loaded rule covers an expected rule when it records at least the same
events: same list and action; the same arch, or no arch restriction; a
superset of the syscalls (or all); the same path, with at least the expected
permissions; and no filter the expected rule lacks, since each extra filter
narrows what is recorded. Keys are labels and are ignored.
"""

import re

_ARCH = {"b64": "b64", "x86_64": "b64", "b32": "b32", "i386": "b32", "i686": "b32"}
_UNSET = {"-1", "unset", "4294967295"}


def _field(tok):
    m = re.match(r"^([A-Za-z_]+)(>=|<=|!=|=|>|<|&=|&)(.*)$", tok)
    if not m:
        return None
    name, op, val = m.groups()
    if name in ("auid", "loginuid") and val in _UNSET:
        val = "-1"
    return name, op, val


def parse(rule):
    toks = rule.split()
    r = {"kind": "syscall", "action": None, "arch": None, "syscalls": set(),
         "path": None, "perm": set(), "fields": set(), "text": rule.strip()}
    if not toks:
        return None
    if toks[0] == "-w":
        r["kind"] = "watch"
        r["path"] = toks[1].rstrip("/") if len(toks) > 1 else None
        r["perm"] = set("rwxa")
        r["syscalls"] = {"all"}
        i = 2
        while i < len(toks):
            if toks[i] == "-p" and i + 1 < len(toks):
                r["perm"] = set(toks[i + 1])
            i += 1
        return r
    i = 0
    while i < len(toks):
        t = toks[i]
        arg = toks[i + 1] if i + 1 < len(toks) else ""
        if t in ("-a", "-A"):
            r["action"] = ",".join(sorted(arg.split(",")))
            i += 2
        elif t == "-S":
            r["syscalls"] |= set(arg.split(","))
            i += 2
        elif t in ("-F", "-C"):
            f = _field(arg)
            i += 2
            if not f:
                continue
            name, op, val = f
            if name in ("key", "k"):
                continue
            if name == "arch":
                r["arch"] = _ARCH.get(val, val)
            elif name in ("path", "dir") and op == "=":
                r["path"] = val.rstrip("/")
            elif name == "perm" and op == "=":
                r["perm"] = set(val)
            else:
                r["fields"].add((name, op, val))
        elif t == "-k":
            i += 2
        else:
            i += 1
    if not r["syscalls"]:
        r["syscalls"] = {"all"}
    return r


def covers(loaded, expected):
    if loaded["kind"] == "watch":
        return (expected["path"] is not None and loaded["path"] == expected["path"]
                and expected["perm"] <= loaded["perm"])
    if loaded["action"] != expected["action"]:
        return False
    if loaded["arch"] not in (None, expected["arch"]):
        return False
    if "all" not in loaded["syscalls"] and not expected["syscalls"] <= loaded["syscalls"]:
        return False
    if loaded["path"] != expected["path"]:
        return False
    if expected["path"] is not None and not expected["perm"] <= loaded["perm"]:
        return False
    return loaded["fields"] <= expected["fields"]


def rhel9_audit_coverage(loaded_text, expected):
    """Return {loaded, missing, covered, report} for a list of expected rules."""
    loaded = [parse(l) for l in (loaded_text or "").splitlines()
              if l.strip().startswith(("-a", "-A", "-w"))]
    loaded = [l for l in loaded if l]
    missing, covered = [], []
    for e_text in expected:
        e = parse(e_text)
        hit = next((l for l in loaded if covers(l, e)), None)
        if hit:
            covered.append((e_text, hit["text"]))
        else:
            missing.append(e_text)
    lines = ["Rules loaded: {}".format(len(loaded))]
    for e_text, l_text in covered:
        lines.append("COVERED: {}\n  by: {}".format(e_text, l_text))
    for e_text in missing:
        lines.append("MISSING: {}".format(e_text))
    lines.append("Keys are not compared: they label records, they do not select them.")
    return {"loaded": len(loaded), "missing": missing,
            "covered": [c[0] for c in covered], "report": "\n".join(lines)}


class FilterModule(object):
    def filters(self):
        return {"rhel9_audit_coverage": rhel9_audit_coverage}
