from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import os
import re
from datetime import datetime, timedelta

_MONTHS = {
    'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4,
    'may': 5, 'jun': 6, 'jul': 7, 'aug': 8,
    'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12,
}


_STAMP_RE = r'(\d{4}|\d{2})([A-Za-z]{3})(\d{2})-(\d{2}):(\d{2})(?::(\d{2}))?-'


def _filename_datetime(path):
    """Parse the YYYYMonDD-HH:MM:SS filename prefix for chronological sorting.

    Also accepts the older YYMonDD-HH:MM[:SS] form, so existing files keep
    their place in the ordering.
    """
    name = os.path.basename(path)
    m = re.match(_STAMP_RE, name)
    if not m:
        return datetime.min
    yy, mon, dd, hh, mm, ss = m.groups()
    year = int(yy) if len(yy) == 4 else 2000 + int(yy)
    month = _MONTHS.get(mon.lower(), 0)
    return datetime(year, month, int(dd), int(hh), int(mm), int(ss or 0))


def _truthy(v):
    if isinstance(v, str):
        return v.strip().lower() in ('1', 'true', 'yes', 'on')
    return bool(v)


def cklb_render(template_json, hostname, supp_paths, fqdn='', ip_address='',
                supp_rules=None, max_age_days=30):
    """
    Fill the CKLB template for a single host from its supplement results.

    The supplement assesses every rule; the DISA formal role takes no part in
    assessment. A rule with no result inside the age window stays as the
    template has it: not_reviewed.

    Results are merged per rule across all of the host's result files, the
    newest file winning; each rule's comments name the run it came from.
    """
    cklb = json.loads(template_json)
    cklb['title'] = f"RHEL 9 STIG - {hostname}"
    cklb['target_data']['host_name'] = hostname
    cklb['target_data']['fqdn'] = fqdn
    cklb['target_data']['ip_address'] = ip_address

    # The find pattern is a glob (*-<host>.json), which also matches another
    # host whose name ends in -<host>: bindtest would absorb delta-bindtest.
    # Keep only files whose host part is exactly this host.
    supp_paths = [
        p for p in (supp_paths or [])
        if re.fullmatch(_STAMP_RE + re.escape(hostname) + r'\.json', os.path.basename(p))
    ]

    # Only files inside the age window take part in the merge (0: no limit).
    max_age_days = int(max_age_days or 0)
    if max_age_days > 0:
        cutoff = datetime.now() - timedelta(days=max_age_days)
        supp_paths = [p for p in supp_paths if _filename_datetime(p) >= cutoff]

    # Merge per rule, newest file wins, oldest to newest. Taking only the
    # newest file whole meant a run limited by tags (the single-rule
    # verification loop) replaced every other rule with not_reviewed. Each
    # rule keeps the provenance line of the file it came from, so a result
    # carried over from an earlier run is visibly dated.
    accum = {}
    for path in sorted(supp_paths, key=lambda p: (_filename_datetime(p), p)):
        with open(path, 'r') as f:
            facts = json.load(f)
        run = _filename_datetime(path)
        stamp = (
            "Supplement check run: "
            + (run.strftime('%Y-%m-%d %H:%M:%S') if run != datetime.min else 'unknown')
            + f" controller local time (results file {os.path.basename(path)})"
        )
        for stig_id, entry in facts.items():
            # A rule switched off in supp_rules must not keep a result left
            # in an older file.
            if supp_rules and not _truthy(supp_rules.get(stig_id, True)):
                continue
            entry = dict(entry)
            entry['comments'] = '\n'.join(c for c in (entry.get('comments', ''), stamp) if c)
            accum[stig_id] = entry

    for stig in cklb['stigs']:
        for rule in stig['rules']:
            entry = accum.get(rule['rule_version'])  # STIG ID, e.g. RHEL-09-211010
            if entry:
                rule['status'] = entry.get('status', 'not_reviewed')
                rule['finding_details'] = entry.get('finding_details', '')
                rule['comments'] = entry.get('comments', '')

    return cklb


class FilterModule:
    def filters(self):
        return {'cklb_render': cklb_render}
