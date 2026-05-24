#!/usr/bin/env python3
"""
Parse the DISA XCCDF benchmark XML and emit files/rules.json keyed by STIG ID.

Also cross-references roles/rhel9STIG/tasks/main.yml to mark which rules
are covered by the formal DISA Ansible role (formal_role_covered field).

Usage:
    python3 scripts/parse_xccdf_benchmark.py

Output:
    files/rules.json — one entry per rule, keyed by STIG ID (RHEL-09-XXXXXX)

Re-run this script if DISA releases a new benchmark version or the formal role changes.
"""

import json
import os
import re
import xml.etree.ElementTree as ET

XCCDF_NS = "http://checklists.nist.gov/xccdf/1.1"

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XCCDF_PATH = os.path.join(REPO_ROOT, "roles", "rhel9STIG", "files",
                           "U_RHEL_9_STIG_V2R8_Manual-xccdf.xml")
FORMAL_ROLE_TASKS = os.path.join(REPO_ROOT, "roles", "rhel9STIG", "tasks", "main.yml")
OUTPUT_PATH = os.path.join(REPO_ROOT, "files", "rules.json")


def strip_xml_tags(text):
    """Remove embedded XML/HTML tags, collapse whitespace."""
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def extract_vuln_discussion(raw):
    """Pull just the VulnDiscussion block from a Rule description."""
    m = re.search(r"<VulnDiscussion>(.*?)</VulnDiscussion>", raw, re.DOTALL)
    if m:
        return strip_xml_tags(m.group(1))
    return strip_xml_tags(raw)


def parse_rule_id(raw_id):
    """SV-257777r1155676_rule -> SV-257777r1155676"""
    return raw_id.removesuffix("_rule")


def get_formal_role_covered(tasks_path):
    """Return set of group ID numbers (e.g. '257779') covered by the formal role."""
    with open(tasks_path, "r") as f:
        content = f.read()
    return set(re.findall(r"stigrule_(\d+)", content))


def parse_benchmark(xccdf_path):
    tree = ET.parse(xccdf_path)
    root = tree.getroot()

    rules = {}

    for group in root.iter(f"{{{XCCDF_NS}}}Group"):
        group_id = group.get("id", "")

        rule_el = group.find(f"{{{XCCDF_NS}}}Rule")
        if rule_el is None:
            continue

        stig_id = (rule_el.findtext(f"{{{XCCDF_NS}}}version") or "").strip()
        if not stig_id:
            continue

        raw_rule_id = rule_el.get("id", "")
        rule_id = parse_rule_id(raw_rule_id)
        severity = rule_el.get("severity", "")

        title = (rule_el.findtext(f"{{{XCCDF_NS}}}title") or "").strip()

        raw_desc = rule_el.findtext(f"{{{XCCDF_NS}}}description") or ""
        discussion = extract_vuln_discussion(raw_desc)

        fix_text = strip_xml_tags(
            rule_el.findtext(f"{{{XCCDF_NS}}}fixtext") or ""
        )

        check_el = rule_el.find(f"{{{XCCDF_NS}}}check")
        check_content = ""
        if check_el is not None:
            check_content = strip_xml_tags(
                check_el.findtext(f"{{{XCCDF_NS}}}check-content") or ""
            )

        ccis = [
            el.text.strip()
            for el in rule_el.findall(f"{{{XCCDF_NS}}}ident")
            if el.text and el.text.strip().startswith("CCI-")
        ]

        rules[stig_id] = {
            "stig_id":      stig_id,
            "rule_id":      rule_id,
            "group_id":     group_id,
            "severity":     severity,
            "title":        title,
            "discussion":   discussion,
            "check_content": check_content,
            "fix_text":     fix_text,
            "ccis":         ccis,
            "formal_role_covered": None,  # populated after parsing
        }

    return rules


def main():
    print(f"Parsing:  {XCCDF_PATH}")
    rules = parse_benchmark(XCCDF_PATH)
    print(f"Extracted {len(rules)} rules")

    print(f"Checking: {FORMAL_ROLE_TASKS}")
    covered_numbers = get_formal_role_covered(FORMAL_ROLE_TASKS)
    for rule in rules.values():
        # group_id is V-257777; the number is what stigrule_NNNNNN uses
        num = rule["group_id"].lstrip("V-")
        rule["formal_role_covered"] = num in covered_numbers

    covered = sum(1 for r in rules.values() if r["formal_role_covered"])
    print(f"Formal role covers {covered}/{len(rules)} rules "
          f"({len(rules) - covered} need supplement coverage)")

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(rules, f, indent=2)
    print(f"Written:  {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
