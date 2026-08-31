#!/usr/bin/env python3
"""
Audit supplement coverage consistency across the project.

Cross-checks four sources that must agree for a revision update to be complete:

  1. files/rules.json                  — the benchmark, with formal_role_covered
  2. roles/rhel9_stig_supplement/tasks/<cat>/RHEL-09-XXXXXX.yml   — task files
  3. roles/rhel9_stig_supplement/tasks/main.yml                   — import wiring
  4. group_vars/all/stig_supplement.yml                           — supp_rules toggles

Also reports which rules the formal role statically attempts (parsed from the
"# R-<vnum>" comments in roles/rhel9STIG/tasks/main.yml). That set is a superset
of formal_role_covered: the callback only records rules whose tasks actually ran,
so role tasks skipped by a conditional in your environment fall to the supplement.

Usage:
    python3 scripts/audit_coverage.py            # exits 1 if any gap found
    python3 scripts/audit_coverage.py --quiet    # summary only
"""

import argparse
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_JSON = os.path.join(REPO, "files", "rules.json")
SUPP_TASKS = os.path.join(REPO, "roles", "rhel9_stig_supplement", "tasks")
SUPP_MAIN = os.path.join(SUPP_TASKS, "main.yml")
SUPP_VARS = os.path.join(REPO, "group_vars", "all", "stig_supplement.yml")
FORMAL_MAIN = os.path.join(REPO, "roles", "rhel9STIG", "tasks", "main.yml")

STIG_ID_RE = re.compile(r"RHEL-09-\d{6}")


def load_rules():
    with open(RULES_JSON) as f:
        return json.load(f)


def task_files():
    """{stig_id: relative path} for every supplement task file on disk."""
    found = {}
    for category in sorted(os.listdir(SUPP_TASKS)):
        cat_dir = os.path.join(SUPP_TASKS, category)
        if not os.path.isdir(cat_dir):
            continue
        for fname in sorted(os.listdir(cat_dir)):
            if not fname.endswith(".yml"):
                continue
            m = STIG_ID_RE.fullmatch(fname[:-4])
            if m:
                found[m.group(0)] = os.path.join(category, fname)
    return found


def wired_imports():
    """{stig_id} imported by tasks/main.yml, plus any import path mismatches."""
    wired, mismatched = set(), []
    with open(SUPP_MAIN) as f:
        for line in f:
            m = re.match(r"\s*-\s*import_tasks:\s*(\S+)", line)
            if not m:
                continue
            path = m.group(1)
            sid = STIG_ID_RE.search(path)
            if not sid:
                continue
            wired.add(sid.group(0))
            if not os.path.exists(os.path.join(SUPP_TASKS, path)):
                mismatched.append(path)
    return wired, mismatched


def toggles():
    """{stig_id} present as a key under supp_rules in stig_supplement.yml."""
    keys = set()
    with open(SUPP_VARS) as f:
        for line in f:
            if line.lstrip().startswith("#"):
                continue
            m = re.match(r"\s+(RHEL-09-\d{6})\s*:", line)
            if m:
                keys.add(m.group(1))
    return keys


def formal_static(rules):
    """{stig_id} the formal role has a task for, via '# R-<vnum>' comments."""
    if not os.path.exists(FORMAL_MAIN):
        return set()
    with open(FORMAL_MAIN) as f:
        vnums = set(re.findall(r"^# R-(\d+)", f.read(), re.M))
    by_vnum = {v["group_id"].lstrip("V-"): sid for sid, v in rules.items()}
    return {by_vnum[v] for v in vnums if v in by_vnum}


def report(label, items, rules, note=""):
    print(f"\n  {label}: {len(items)}{note}")
    for sid in sorted(items):
        title = rules.get(sid, {}).get("title", "(not in rules.json)")
        print(f"    {sid}  {title[:78]}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true", help="summary only")
    args = ap.parse_args()

    rules = load_rules()
    files = task_files()
    wired, mismatched = wired_imports()
    toggled = toggles()
    static = formal_static(rules)

    all_ids = set(rules)
    covered = {s for s, r in rules.items() if r.get("formal_role_covered")}
    needs_supp = all_ids - covered

    print("=" * 72)
    print("COVERAGE AUDIT")
    print("=" * 72)
    print(f"  benchmark rules (rules.json):     {len(all_ids)}")
    print(f"  formal_role_covered (from scan):  {len(covered)}")
    print(f"  need supplement coverage:         {len(needs_supp)}")
    print(f"  supplement task files on disk:    {len(files)}")
    print(f"  wired into tasks/main.yml:        {len(wired)}")
    print(f"  supp_rules toggles declared:      {len(toggled)}")
    print(f"  formal role static tasks (# R-):  {len(static)}"
          "   (superset of scan coverage)")

    # Supplement tasks that overlap formal-role coverage are NOT a defect.
    # formal_role_covered is host-dependent: many role tasks are gated on
    # conditionals such as "packages['dconf'] is defined", so a rule covered on
    # one host is silently skipped on another, leaving it not_reviewed. The
    # overlapping supplement task is what makes coverage host-independent, and
    # cklb.py deliberately gives supplement facts precedence over XCCDF.
    overlap = set(files) & covered

    problems = {
        "MISSING task file (rule needs supplement, no file)":
            needs_supp - set(files),
        "ORPHAN task file (file exists, rule not in rules.json)":
            set(files) - all_ids,
        "NOT WIRED (task file exists, no import in main.yml)":
            set(files) - wired,
        "DANGLING import (main.yml imports a rule with no task file)":
            wired - set(files),
        "MISSING toggle (task file exists, no supp_rules entry)":
            set(files) - toggled,
        "ORPHAN toggle (supp_rules entry, no task file)":
            toggled - set(files),
    }

    total = sum(len(v) for v in problems.values()) + len(mismatched)

    if mismatched:
        print(f"\n  BROKEN import path (file not found at that path): "
              f"{len(mismatched)}")
        for p in mismatched:
            print(f"    {p}")

    if overlap:
        print(f"\n  note: {len(overlap)} supplement tasks overlap formal-role "
              f"coverage on this host.")
        print("        Expected — coverage is host-dependent; these keep the "
              "checklist complete")
        print("        on hosts where the role's conditionals skip the rule. "
              "Not a defect.")

    for label, items in problems.items():
        if not items:
            continue
        if args.quiet:
            print(f"\n  {label}: {len(items)}")
        else:
            report(label, items, rules)

    print()
    if total == 0:
        print("CLEAN — all four sources agree.")
        return 0
    print(f"{total} inconsistenc{'y' if total == 1 else 'ies'} found.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
