#!/usr/bin/env python3
"""
Audit supplement coverage consistency across the project.

The supplement assesses every rule (the DISA formal role takes no part in
assessment), so every rule must have exactly one supplement check, wired and
toggled. Cross-checks five sources that must agree:

  1. files/rules.json                  - the benchmark (parse_xccdf_benchmark.py)
  2. the CKLB template                 - the rules the checklist will contain
  3. roles/rhel9_stig_full/tasks/<cat>/RHEL-09-XXXXXX.yml   - task files
  4. roles/rhel9_stig_full/tasks/main.yml                   - import wiring
  5. group_vars/all/stig_rules.yml                           - stig_rules toggles

A rule present in the template but without a check renders not_reviewed,
which reviewers reject.

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
CKLB_DEFAULTS = os.path.join(REPO, "roles", "rhel9_stig_full", "defaults", "main.yml")
SUPP_TASKS = os.path.join(REPO, "roles", "rhel9_stig_full", "tasks")
SUPP_MAIN = os.path.join(SUPP_TASKS, "main.yml")
SUPP_VARS = os.path.join(REPO, "group_vars", "all", "stig_rules.yml")

STIG_ID_RE = re.compile(r"RHEL-09-\d{6}")


def load_rules():
    with open(RULES_JSON) as f:
        return json.load(f)


def template_rules():
    """{stig_id} in the CKLB template that cklb_template_path names."""
    with open(CKLB_DEFAULTS) as f:
        m = re.search(r'^cklb_template_path:\s*"\{\{\s*playbook_dir\s*\}\}/(\S+?)"',
                      f.read(), re.M)
    if not m:
        return None, "cklb_template_path not found in " + CKLB_DEFAULTS
    path = os.path.join(REPO, m.group(1))
    with open(path) as f:
        cklb = json.load(f)
    return {r["rule_version"] for s in cklb["stigs"] for r in s["rules"]}, path


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
    """{stig_id} present as a key under stig_rules in stig_rules.yml."""
    keys = set()
    with open(SUPP_VARS) as f:
        for line in f:
            if line.lstrip().startswith("#"):
                continue
            m = re.match(r"\s+(RHEL-09-\d{6})\s*:", line)
            if m:
                keys.add(m.group(1))
    return keys


def report(label, items, rules):
    print(f"\n  {label}: {len(items)}")
    for sid in sorted(items):
        title = rules.get(sid, {}).get("title", "(not in rules.json)")
        print(f"    {sid}  {title[:78]}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true", help="summary only")
    args = ap.parse_args()

    rules = load_rules()
    template, template_path = template_rules()
    files = task_files()
    wired, mismatched = wired_imports()
    toggled = toggles()
    all_ids = set(rules)

    print("=" * 72)
    print("COVERAGE AUDIT")
    print("=" * 72)
    print(f"  benchmark rules (rules.json):     {len(all_ids)}")
    if template is None:
        print(f"  CKLB template:                    ERROR - {template_path}")
        template = set()
    else:
        print(f"  CKLB template rules:              {len(template)}")
    print(f"  supplement task files on disk:    {len(files)}")
    print(f"  wired into tasks/main.yml:        {len(wired)}")
    print(f"  stig_rules toggles declared:      {len(toggled)}")

    problems = {
        "BENCHMARK/TEMPLATE mismatch (in rules.json, not in the template)":
            all_ids - template,
        "BENCHMARK/TEMPLATE mismatch (in the template, not in rules.json)":
            template - all_ids,
        "MISSING task file (rule has no supplement check: renders not_reviewed)":
            all_ids - set(files),
        "ORPHAN task file (file exists, rule not in rules.json)":
            set(files) - all_ids,
        "NOT WIRED (task file exists, no import in main.yml)":
            set(files) - wired,
        "DANGLING import (main.yml imports a rule with no task file)":
            wired - set(files),
        "MISSING toggle (task file exists, no stig_rules entry)":
            set(files) - toggled,
        "ORPHAN toggle (stig_rules entry, no task file)":
            toggled - set(files),
    }

    total = sum(len(v) for v in problems.values()) + len(mismatched)

    if mismatched:
        print(f"\n  BROKEN import path (file not found at that path): "
              f"{len(mismatched)}")
        for p in mismatched:
            print(f"    {p}")

    for label, items in problems.items():
        if not items:
            continue
        if args.quiet:
            print(f"\n  {label}: {len(items)}")
        else:
            report(label, items, rules)

    print()
    if total == 0:
        print("CLEAN - every rule has exactly one wired, toggled check.")
        return 0
    print(f"{total} inconsistenc{'y' if total == 1 else 'ies'} found.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
