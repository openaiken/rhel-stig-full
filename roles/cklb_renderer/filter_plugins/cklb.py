from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime

XCCDF_NS = "http://checklists.nist.gov/xccdf/1.2"

_MONTHS = {
    'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4,
    'may': 5, 'jun': 6, 'jul': 7, 'aug': 8,
    'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12,
}

_XCCDF_TO_CKLB = {'pass': 'not_a_finding', 'fail': 'open'}


def _filename_datetime(path):
    """Parse the YYMonDD-HH:MM[:SS] filename prefix for chronological sorting."""
    name = os.path.basename(path)
    m = re.match(r'(\d{2})([A-Za-z]{3})(\d{2})-(\d{2}):(\d{2})(?::(\d{2}))?', name)
    if not m:
        return datetime.min
    yy, mon, dd, hh, mm, ss = m.groups()
    month = _MONTHS.get(mon.lower(), 0)
    return datetime(2000 + int(yy), month, int(dd), int(hh), int(mm), int(ss or 0))


_BENCH_PREFIX = 'xccdf_mil.disa.stig_testresult_scap_mil.disa_comp_'

_XCCDF_COMMENTS = (
    "Result extracted from the official DISA Ansible role and inserted "
    "into this checklist automatically."
)


def _parse_xccdf(path):
    """Returns {rule_id: {status, finding_details, comments}} from an XCCDF results file."""
    root = ET.parse(path).getroot()

    bench_el = root.find(f'{{{XCCDF_NS}}}benchmark')
    bench_href = bench_el.get('href', '') if bench_el is not None else ''
    benchmark = bench_href.removeprefix(_BENCH_PREFIX) or bench_href
    end_time = root.get('end-time', '')

    # Provenance for the comments: the formal-role results may come from an
    # earlier run than the supplement results, deliberately, so each rendered
    # rule says when its source was produced.
    stamp = (
        f"Formal role scan: {end_time or 'unknown'} UTC "
        f"(results file {os.path.basename(path)})"
    )

    rules = {}
    for rr in root.findall(f'{{{XCCDF_NS}}}rule-result'):
        idref = rr.get('idref', '')
        m = re.search(r'SV-\d+r\d+', idref)
        if not m:
            continue
        result_el = rr.find(f'{{{XCCDF_NS}}}result')
        if result_el is None:
            continue
        raw = result_el.text or ''
        rule_id = m.group(0)
        rules[rule_id] = {
            'status': _XCCDF_TO_CKLB.get(raw, 'not_reviewed'),
            'finding_details': (
                f"Benchmark: {benchmark}\n"
                f"Scan completed: {end_time}\n"
                f"Result: {raw}"
            ),
            'comments': f"{_XCCDF_COMMENTS}\n{stamp}",
        }

    return rules


def _truthy(v):
    if isinstance(v, str):
        return v.strip().lower() in ('1', 'true', 'yes', 'on')
    return bool(v)


def cklb_render(template_json, hostname, xccdf_paths, supp_paths, fqdn='', ip_address='',
                supp_rules=None, formal_manage=None):
    """
    Merge XCCDF results and supplement facts into the CKLB template for a single host.

    Precedence (highest to lowest):
      1. supplement facts — manually assessed rules not covered by the formal role
      2. XCCDF            — rules the formal role remediated and the callback recorded
      3. template         — not_reviewed (untouched)

    Within each source, results are merged per rule across all of the host's
    result files, the newest file winning; each rule's comments name the run
    it came from.
    """
    cklb = json.loads(template_json)
    cklb['title'] = f"RHEL 9 STIG - {hostname}"
    cklb['target_data']['host_name'] = hostname
    cklb['target_data']['fqdn'] = fqdn
    cklb['target_data']['ip_address'] = ip_address

    # Merge per rule, newest file wins, oldest to newest. Taking only the
    # newest file whole meant a run limited by tags (the single-rule
    # verification loop) replaced every other rule with not_reviewed. Each
    # rule keeps the provenance line of the file it came from, so a result
    # carried over from an earlier run is visibly dated.
    # The find patterns are globs (*-<host>.json), which also match another
    # host whose name ends in -<host>: bindtest would absorb delta-bindtest.
    # Keep only files whose host part is exactly this host.
    stamp_re = r'\d{2}[A-Za-z]{3}\d{2}-\d{2}:\d{2}(?::\d{2})?-'
    own = lambda paths, tail: [
        p for p in (paths or [])
        if re.fullmatch(stamp_re + re.escape(hostname) + re.escape(tail), os.path.basename(p))
    ]
    xccdf_paths = own(xccdf_paths, '-xccdf-results.xml')
    supp_paths = own(supp_paths, '.json')

    xccdf_accum = {}
    for path in sorted(xccdf_paths or [], key=lambda p: (_filename_datetime(p), p)):
        xccdf_accum.update(_parse_xccdf(path))
    # Likewise a formal rule switched off with rhel9STIG_stigrule_<V>_Manage
    # must not keep an old result. formal_manage maps the V number to the flag.
    if formal_manage:
        for rid in list(xccdf_accum):
            m = re.match(r'SV-(\d+)r', rid)
            if m and not _truthy(formal_manage.get(m.group(1), True)):
                del xccdf_accum[rid]

    supp_accum = {}
    for path in sorted(supp_paths or [], key=lambda p: (_filename_datetime(p), p)):
        with open(path, 'r') as f:
            facts = json.load(f)
        run = _filename_datetime(path)
        stamp = (
            "Supplement check run: "
            + (run.strftime('%Y-%m-%d %H:%M:%S') if run != datetime.min else 'unknown')
            + f" controller local time (results file {os.path.basename(path)})"
        )
        for stig_id, entry in facts.items():
            # A rule switched off in supp_rules must not keep winning over the
            # formal role through a result left in an older file.
            if supp_rules and not _truthy(supp_rules.get(stig_id, True)):
                continue
            entry = dict(entry)
            entry['comments'] = '\n'.join(c for c in (entry.get('comments', ''), stamp) if c)
            supp_accum[stig_id] = entry

    for stig in cklb['stigs']:
        for rule in stig['rules']:
            stig_id = rule['rule_version']  # RHEL-09-211010 — primary identifier
            rule_id = rule['rule_id']       # SV-257777r1155676 — used by XCCDF results
            if stig_id in supp_accum:
                entry = supp_accum[stig_id]
                rule['status'] = entry.get('status', 'not_reviewed')
                rule['finding_details'] = entry.get('finding_details', '')
                rule['comments'] = entry.get('comments', '')
            elif rule_id in xccdf_accum:
                entry = xccdf_accum[rule_id]
                rule['status'] = entry['status']
                rule['finding_details'] = entry['finding_details']
                rule['comments'] = entry['comments']

    return cklb


class FilterModule:
    def filters(self):
        return {'cklb_render': cklb_render}
