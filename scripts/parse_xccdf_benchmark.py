#!/usr/bin/env python3
"""
Parse the DISA XCCDF benchmark XML and emit files/rules.json keyed by STIG ID.

The benchmark lives in files/ (moved out of roles/rhel9STIG, which is now used
for remediation only and does not take part in assessment).

Usage:
    python3 scripts/parse_xccdf_benchmark.py

Output:
    files/rules.json — one entry per rule, keyed by STIG ID (RHEL-09-XXXXXX)

Re-run when DISA releases a new benchmark version.
"""

import json
import os
import re
import xml.etree.ElementTree as ET

XCCDF_NS = "http://checklists.nist.gov/xccdf/1.1"

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XCCDF_PATH = os.path.join(REPO_ROOT, "files", "U_RHEL_9_STIG_V2R9_Manual-xccdf.xml")
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
        }

    return rules


def main():
    print(f"Parsing:  {XCCDF_PATH}")
    rules = parse_benchmark(XCCDF_PATH)
    print(f"Extracted {len(rules)} rules")

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(rules, f, indent=2)
    print(f"Written:  {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
