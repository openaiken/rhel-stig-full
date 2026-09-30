#!/usr/bin/env python3
"""
Lint the supplement task files for shell-logic faults that silently produce
wrong compliance verdicts.

Encodes the bug classes actually found in this repo. A check that can only ever
report PASS is worse than no check, so these are worth catching mechanically
rather than by re-reading 187 files each revision.

Usage:
    python3 scripts/lint_supplement.py            # exits 1 if findings
    python3 scripts/lint_supplement.py --quiet    # counts only
"""

import argparse
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TASKS = os.path.join(REPO, "roles", "rhel9_stig_supplement", "tasks")
RULES_JSON = os.path.join(REPO, "files", "rules.json")


def multi_condition_rules():
    """STIG checks stating more than one finding condition.

    Reported as information, not as findings. A task can legitimately evaluate
    several conditions inside one shell block, so counting registers produces
    about 50% false positives -- but a partially implemented multi-condition
    check is a real and invisible false negative (it shipped in the four
    212xxx kernel-argument rules), so the list is worth re-reading each bump.
    """
    try:
        rules = json.load(open(RULES_JSON))
    except OSError:
        return {}
    out = {}
    for sid, r in rules.items():
        cc = " ".join(r.get("check_content", "").split())
        n = len(re.findall(r"this is a finding", cc, re.I))
        if n >= 2:
            out[sid] = n
    return out

CHECKS = {
    "NO-OPEN":      "status expression can never yield 'open' -- check cannot report a finding",
    "PREFIX-ANCHOR":"grep -n/-rn output is prefixed 'file:lineno:'; a '^\\s*' anchor can never match",
    "NO-GUARDS":    "shell/command task missing changed_when: false and/or failed_when: false",
    "DEAD-REGISTER":"registered variable is never referenced",
    "UNDEF-REF":    "variable referenced but never registered in this file",
    "SHELL-APOS":   "apostrophe in a shell comment (Ansible parse_kv sees unbalanced quotes)",
    "JINJA-COMMENT": "'{#' opens a Jinja comment (e.g. bash ${#arr[@]}); Ansible fails to parse the role",
    "FILE-NOT-EFFECTIVE":
                    "greps config files for a setting whose effective value can differ "
                    "(systemd drop-in without .conf, sysctl override, sshd Match block)",
}


def task_files():
    out = []
    for cat in sorted(os.listdir(TASKS)):
        d = os.path.join(TASKS, cat)
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if re.fullmatch(r"RHEL-09-\d{6}\.yml", fn):
                out.append((fn[:-4], os.path.join(d, fn)))
    return out


def lint(sid, path):
    src = open(path, encoding="utf-8").read()
    lines = src.splitlines()
    hits = []

    # C1: can the task ever report a finding?
    if "'open'" not in src and '"open"' not in src:
        hits.append(("NO-OPEN", 0, "no 'open' literal anywhere in the file"))

    # C2: grep -n family piped into a line-start comment/keyword anchor
    for i, l in enumerate(lines, 1):
        m = re.search(r"grep\s+(-[A-Za-z]*n[A-Za-z]*)\s", l)
        if m and "-" in m.group(1):
            window = "\n".join(lines[i - 1:i + 6])
            bad = re.search(r"grep\s+-[A-Za-z]*v[A-Za-z]*\s+'\^\\s\*|grep\s+-[A-Za-z]*v[A-Za-z]*\s+'\^\[\[:space:\]\]\*", window)
            anchored = re.search(r"\^\[\^:\]\+:\[0-9\]\+:|\^\[0-9\]\*:", window)
            if bad and not anchored:
                hits.append(("PREFIX-ANCHOR", i, l.strip()[:80]))

    # C3: every shell/command task needs changed_when: false and
    # failed_when: false. supplement.yml does not ignore errors, so one non-zero
    # exit aborts the play and every later rule drops out of supp_facts. This
    # used to be a heuristic over the final command, which missed a trailing
    # `[ -n "$x" ] && ...` (412035) -- exit status is too easy to get wrong by
    # inspection, so status comes from stdout markers only and rc is never used.
    for m in re.finditer(r"^- name: (.+)$", src, re.M):
        blk = src[m.start():]
        nxt = re.search(r"\n- name: ", blk)
        blk = blk[:nxt.start()] if nxt else blk
        if not re.search(r"^\s+(shell|command):", blk, re.M):
            continue
        ln = src[:m.start()].count("\n") + 1
        for guard in ("changed_when", "failed_when"):
            if not re.search(rf"^\s+{guard}:\s*false\s*$", blk, re.M):
                hits.append(("NO-GUARDS", ln, f"{m.group(1)[:52]} -- missing {guard}: false"))

    # C4/C5: register vs reference
    reg = set(re.findall(r"^\s*register:\s*(\w+)", src, re.M))
    refs = set(re.findall(r"(_\d{6}\w*)", src)) - reg
    for r in sorted(reg):
        if len(re.findall(re.escape(r), src)) <= 1:
            hits.append(("DEAD-REGISTER", 0, r))
    for r in sorted(refs):
        if r.startswith("_") and re.search(rf"{re.escape(r)}\s*\.", src):
            hits.append(("UNDEF-REF", 0, r))

    # C6: apostrophes inside shell comments
    in_shell = False
    for i, l in enumerate(lines, 1):
        if re.match(r"^\s+(shell|command):\s*[|>]", l):
            in_shell = True; continue
        if in_shell and re.match(r"^\s+\w+:", l) and not l.lstrip().startswith("#"):
            in_shell = False
        if in_shell:
            c = l.strip()
            # only an ODD count is dangerous; balanced quotes parse fine
            if c.startswith("#") and c.count("'") % 2 == 1:
                hits.append(("SHELL-APOS", i, c[:70]))

    # C6b: "{#" anywhere opens a Jinja comment. Bash ${#var} / ${#arr[@]} is the
    # usual culprit. Ansible then cannot split the task's arguments and the
    # include_role fails, aborting the entire supplement run, not one rule.
    for i, l in enumerate(lines, 1):
        if "{#" in l:
            hits.append(("JINJA-COMMENT", i, l.strip()[:70]))

    # C7: file-grep where the effective value can differ
    if re.search(r"/etc/systemd/[\w.]*\.conf\.d|/etc/sysctl\.d|sshd_config", src):
        if not re.search(r"systemctl show|sysctl -n|sshd -T", src):
            hits.append(("FILE-NOT-EFFECTIVE", 0,
                         "greps config files without querying the effective value"))
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    files = task_files()
    all_hits = {}
    for sid, path in files:
        h = lint(sid, path)
        if h:
            all_hits[sid] = h

    counts = {}
    for h in all_hits.values():
        for kind, _, _ in h:
            counts[kind] = counts.get(kind, 0) + 1

    print("=" * 72)
    print(f"SUPPLEMENT LINT -- {len(files)} task files")
    print("=" * 72)
    for k, desc in CHECKS.items():
        print(f"  {k:<20} {counts.get(k, 0):>4}   {desc[:60]}")

    if not args.quiet:
        for kind in CHECKS:
            rows = [(s, ln, d) for s, hs in sorted(all_hits.items())
                    for k, ln, d in hs if k == kind]
            if not rows:
                continue
            print(f"\n{'-' * 72}\n{kind}: {CHECKS[kind]}\n{'-' * 72}")
            for s, ln, d in rows:
                loc = f":{ln}" if ln else ""
                print(f"  {s}{loc}  {d}")

    multi = multi_condition_rules()
    ours = {s for s, _ in files}
    rel = sorted((s, n) for s, n in multi.items() if s in ours)
    if rel and not args.quiet:
        print(f"\n{'-' * 72}")
        print("INFO: supplement rules whose STIG check states multiple finding")
        print("conditions. Not findings -- verify each is fully implemented on a")
        print("revision bump; a partial implementation is a silent false negative.")
        print("-" * 72)
        for s_, n in rel:
            print(f"  {s_}  ({n} stated conditions)")

    total = sum(counts.values())
    print(f"\ntotal findings: {total}")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
