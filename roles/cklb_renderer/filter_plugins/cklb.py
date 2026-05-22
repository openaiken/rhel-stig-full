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
    """Parse YYMonDD-HH:MM prefix from filename for chronological sorting."""
    name = os.path.basename(path)
    m = re.match(r'(\d{2})([A-Za-z]{3})(\d{2})-(\d{2}):(\d{2})', name)
    if not m:
        return datetime.min
    yy, mon, dd, hh, mm = m.groups()
    month = _MONTHS.get(mon.lower(), 0)
    return datetime(2000 + int(yy), month, int(dd), int(hh), int(mm))


def _latest(paths):
    if not paths:
        return None
    return max(paths, key=_filename_datetime)


def _parse_xccdf(path):
    """Returns {rule_id: cklb_status} from an XCCDF results file."""
    accumulator = {}
    root = ET.parse(path).getroot()
    for rr in root.findall(f'{{{XCCDF_NS}}}rule-result'):
        idref = rr.get('idref', '')
        m = re.search(r'SV-\d+r\d+', idref)
        if not m:
            continue
        result_el = rr.find(f'{{{XCCDF_NS}}}result')
        if result_el is not None:
            accumulator[m.group(0)] = _XCCDF_TO_CKLB.get(result_el.text, 'not_reviewed')
    return accumulator


def cklb_render(template_json, hostname, xccdf_paths, supp_paths, fqdn='', ip_address=''):
    """
    Merge XCCDF results and supplement facts into the CKLB template for a single host.

    Precedence (highest to lowest):
      1. supplement facts — manually assessed rules not covered by the formal role
      2. XCCDF            — rules the formal role remediated and the callback recorded
      3. template         — not_reviewed (untouched)
    """
    cklb = json.loads(template_json)
    cklb['title'] = f"RHEL 9 STIG - {hostname}"
    cklb['target_data']['host_name'] = hostname
    cklb['target_data']['fqdn'] = fqdn
    cklb['target_data']['ip_address'] = ip_address

    xccdf_accum = {}
    xccdf_file = _latest(xccdf_paths)
    if xccdf_file:
        xccdf_accum = _parse_xccdf(xccdf_file)

    supp_accum = {}
    supp_file = _latest(supp_paths)
    if supp_file:
        with open(supp_file, 'r') as f:
            supp_accum = json.load(f)

    for stig in cklb['stigs']:
        for rule in stig['rules']:
            rule_id = rule['rule_id']
            if rule_id in supp_accum:
                entry = supp_accum[rule_id]
                rule['status'] = entry.get('status', 'not_reviewed')
                rule['finding_details'] = entry.get('finding_details', '')
                rule['comments'] = entry.get('comments', '')
            elif rule_id in xccdf_accum:
                rule['status'] = xccdf_accum[rule_id]

    return cklb


class FilterModule:
    def filters(self):
        return {'cklb_render': cklb_render}
