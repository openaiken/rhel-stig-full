#!/usr/bin/env python3
"""
Diff two DISA XCCDF benchmark XMLs and report what changed between revisions.

Keyed on STIG ID (RHEL-09-XXXXXX). Reports rules added, removed, and — for
rules present in both — changes to the rule revision, V-number, severity,
title, check content, fix text, and CCIs.

Usage:
    python3 scripts/diff_benchmarks.py OLD_XCCDF NEW_XCCDF [--json OUT.json]

Example:
    python3 scripts/diff_benchmarks.py \
        files/U_RHEL_9_STIG_V2R8_Manual-xccdf.xml \
        files/U_RHEL_9_STIG_V2R9_Manual-xccdf.xml
"""

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET

XCCDF_NS = "http://checklists.nist.gov/xccdf/1.1"


def strip_xml_tags(text):
    """Remove embedded XML/HTML tags, collapse whitespace."""
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def extract_vuln_discussion(raw):
    m = re.search(r"<VulnDiscussion>(.*?)</VulnDiscussion>", raw, re.DOTALL)
    return strip_xml_tags(m.group(1) if m else raw)


def parse_benchmark(path):
    """Return (release_label, {stig_id: rule_dict})."""
    root = ET.parse(path).getroot()

    release = ""
    for plain in root.iter(f"{{{XCCDF_NS}}}plain-text"):
        if plain.get("id") == "release-info":
            release = (plain.text or "").strip()
    version = (root.findtext(f"{{{XCCDF_NS}}}version") or "").strip()
    label = f"version {version} / {release}".strip()

    rules = {}
    for group in root.iter(f"{{{XCCDF_NS}}}Group"):
        rule_el = group.find(f"{{{XCCDF_NS}}}Rule")
        if rule_el is None:
            continue
        stig_id = (rule_el.findtext(f"{{{XCCDF_NS}}}version") or "").strip()
        if not stig_id:
            continue

        check_el = rule_el.find(f"{{{XCCDF_NS}}}check")
        check_content = ""
        if check_el is not None:
            check_content = strip_xml_tags(
                check_el.findtext(f"{{{XCCDF_NS}}}check-content") or "")

        rules[stig_id] = {
            "stig_id": stig_id,
            "rule_id": rule_el.get("id", "").removesuffix("_rule"),
            "group_id": group.get("id", ""),
            "severity": rule_el.get("severity", ""),
            "title": (rule_el.findtext(f"{{{XCCDF_NS}}}title") or "").strip(),
            "discussion": extract_vuln_discussion(
                rule_el.findtext(f"{{{XCCDF_NS}}}description") or ""),
            "check_content": check_content,
            "fix_text": strip_xml_tags(
                rule_el.findtext(f"{{{XCCDF_NS}}}fixtext") or ""),
            "ccis": sorted(
                el.text.strip()
                for el in rule_el.findall(f"{{{XCCDF_NS}}}ident")
                if el.text and el.text.strip().startswith("CCI-")
            ),
        }
    return label, rules


# Fields compared for rules present in both revisions. rule_id changes on any
# content revision, so it is the cheap signal; the rest say what actually moved.
COMPARED = ["rule_id", "group_id", "severity", "title",
            "discussion", "check_content", "fix_text", "ccis"]

# Changes to these mean the supplement/formal task logic may need rework.
SUBSTANTIVE = {"severity", "check_content", "fix_text", "ccis"}


def diff(old, new):
    added = sorted(set(new) - set(old))
    removed = sorted(set(old) - set(new))
    changed = {}
    for sid in sorted(set(old) & set(new)):
        deltas = {f: (old[sid][f], new[sid][f])
                  for f in COMPARED if old[sid][f] != new[sid][f]}
        if deltas:
            changed[sid] = deltas
    return added, removed, changed


def truncate(val, n=160):
    s = ", ".join(val) if isinstance(val, list) else str(val)
    return s if len(s) <= n else s[:n] + " …"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("old_xccdf")
    ap.add_argument("new_xccdf")
    ap.add_argument("--json", metavar="OUT", help="also write full diff as JSON")
    ap.add_argument("--full", action="store_true",
                    help="print full field values instead of truncating")
    args = ap.parse_args()

    old_label, old = parse_benchmark(args.old_xccdf)
    new_label, new = parse_benchmark(args.new_xccdf)

    print(f"OLD: {args.old_xccdf}\n     {old_label} — {len(old)} rules")
    print(f"NEW: {args.new_xccdf}\n     {new_label} — {len(new)} rules\n")

    added, removed, changed = diff(old, new)
    substantive = {s: d for s, d in changed.items()
                   if SUBSTANTIVE & set(d)}

    print(f"{'=' * 72}\nSUMMARY\n{'=' * 72}")
    print(f"  added:                 {len(added)}")
    print(f"  removed:               {len(removed)}")
    print(f"  changed (any field):   {len(changed)}")
    print(f"  changed (substantive): {len(substantive)}"
          "   <- severity/check/fix/CCI; task logic may need rework")

    if added:
        print(f"\n{'=' * 72}\nADDED RULES — need coverage decisions\n{'=' * 72}")
        for sid in added:
            r = new[sid]
            print(f"\n  {sid}  {r['group_id']}  {r['severity']}")
            print(f"    {r['title']}")

    if removed:
        print(f"\n{'=' * 72}\nREMOVED RULES — retire tasks and vars\n{'=' * 72}")
        for sid in removed:
            r = old[sid]
            print(f"\n  {sid}  {r['group_id']}  {r['severity']}")
            print(f"    {r['title']}")

    if changed:
        print(f"\n{'=' * 72}\nCHANGED RULES\n{'=' * 72}")
        for sid, deltas in changed.items():
            marker = "**" if SUBSTANTIVE & set(deltas) else "  "
            print(f"\n{marker} {sid}  ({', '.join(sorted(deltas))})")
            for field in sorted(deltas):
                o, n = deltas[field]
                if field == "rule_id":
                    print(f"     rule_id: {o} -> {n}")
                    continue
                print(f"     {field}:")
                print(f"       - {o if args.full else truncate(o)}")
                print(f"       + {n if args.full else truncate(n)}")

    if args.json:
        with open(args.json, "w") as f:
            json.dump({
                "old": {"path": args.old_xccdf, "label": old_label,
                        "count": len(old)},
                "new": {"path": args.new_xccdf, "label": new_label,
                        "count": len(new)},
                "added": {s: new[s] for s in added},
                "removed": {s: old[s] for s in removed},
                "changed": changed,
                "substantive": sorted(substantive),
            }, f, indent=2)
        print(f"\nJSON diff written: {args.json}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
