from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
    name: rhel9_xccdf_results
    type: notification
    short_description: Write XCCDF test-result XML for DISA STIG formal role runs
    description:
      - Collects pass/fail results from tasks named with the stigrule_<id> convention
        and writes a per-host XCCDF TestResult XML file at the end of each play.
      - Output directory is controlled by the XML_PATH environment variable.
    requirements:
      - Set XML_PATH environment variable to the desired output directory.
      - Enable via callbacks_enabled = rhel9_xccdf_results in ansible.cfg.
"""

import os
import re
import tempfile
import xml.dom.minidom
import xml.etree.ElementTree as ET
from time import gmtime, localtime, strftime

from ansible import context
from ansible.plugins.callback import CallbackBase


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "notification"
    CALLBACK_NAME = "rhel9_xccdf_results"

    CALLBACK_NEEDS_ENABLED = True

    def _get_stig_path(self):
        search_dir = os.path.join(os.path.abspath("."), "roles", "rhel9STIG", "files")
        if not os.path.isdir(search_dir):
            return None
        for name in sorted(os.listdir(search_dir)):
            if "xccdf" in name.lower() and name.lower().endswith(".xml"):
                return os.path.join(search_dir, name)
        return None

    def __init__(self):
        super(CallbackModule, self).__init__()
        # {hostname: {rule_key: bool}} — bool is is_changed() result
        self.rules = {}
        # cache for _get_rev to avoid re-reading the STIG XML per task
        self._rev_cache = {}

        self.stig_path = os.environ.get("STIG_PATH") or self._get_stig_path()
        self._display.display("Using STIG_PATH: {}".format(self.stig_path))

        xml_dir = os.environ.get("XML_PATH")
        if xml_dir is None:
            xml_dir = tempfile.mkdtemp()
        self.xml_dir = xml_dir
        os.makedirs(self.xml_dir, exist_ok=True)
        self._display.display("Writing XCCDF results to: {}".format(self.xml_dir))

        self.stig_name = os.path.basename(self.stig_path) if self.stig_path else "unknown"
        # seconds included so two runs in the same minute do not overwrite
        self.run_ts = strftime("%y%b%d-%H:%M:%S", localtime())
        # formal-role.yml runs in check mode for the validate tag or --check,
        # where changed means would-change, i.e. a finding. In a remediate run
        # changed means was-fixed, which is not an assessment; those results
        # get a different suffix so the checklist renderer (which merges
        # every *-xccdf-results.xml per rule) never picks them up.
        args = context.CLIARGS
        tags = args.get("tags") or ()
        self.assessing = "validate" in tags or bool(args.get("check"))
        ET.register_namespace("", "http://checklists.nist.gov/xccdf/1.2")

    def _get_rev(self, nid):
        if nid in self._rev_cache:
            return self._rev_cache[nid]
        rev = "0"
        if self.stig_path:
            with open(self.stig_path, "r") as f:
                m = re.search(r"SV-{}r(?P<rev>\d+)_rule".format(nid), f.read())
            if m:
                rev = m.group("rev")
        self._rev_cache[nid] = rev
        return rev

    def v2_runner_on_ok(self, result):
        name = result._task.get_name()
        m = re.search(r"stigrule_(?P<id>\d+)", name)
        if not m:
            return
        nid = m.group("id")
        rev = self._get_rev(nid)
        key = "{}r{}".format(nid, rev)
        host = result._host.get_name()
        host_rules = self.rules.setdefault(host, {})
        # True means changed or failed (fail), False means unchanged (pass).
        # A rule fails if any of its tasks fails, so True must stick. This used
        # to keep the first False instead: once one task passed, a later task
        # that would change the host was ignored, and a later ok task
        # overwrote an earlier failure. 33 formal rules have several tasks.
        host_rules[key] = host_rules.get(key, False) or result.is_changed()

    def v2_runner_on_failed(self, result, ignore_errors=False):  # noqa: ARG002
        name = result._task.get_name()
        m = re.search(r"stigrule_(?P<id>\d+)", name)
        if not m:
            return
        nid = m.group("id")
        rev = self._get_rev(nid)
        key = "{}r{}".format(nid, rev)
        host = result._host.get_name()
        # failed task always marks the rule as not passing
        self.rules.setdefault(host, {})[key] = True

    def v2_playbook_on_stats(self, stats):
        endtime = strftime("%Y-%m-%dT%H:%M:%S", gmtime())
        for host in stats.processed:
            host_rules = self.rules.get(host, {})
            if not host_rules:
                continue
            tr = ET.Element("{http://checklists.nist.gov/xccdf/1.2}TestResult")
            tr.set(
                "id",
                "xccdf_mil.disa.stig_testresult_scap_mil.disa_comp_{}".format(self.stig_name),
            )
            tr.set("end-time", endtime)

            bm = ET.SubElement(tr, "{http://checklists.nist.gov/xccdf/1.2}benchmark")
            bm.set(
                "href",
                "xccdf_mil.disa.stig_testresult_scap_mil.disa_comp_{}".format(self.stig_name),
            )

            tg = ET.SubElement(tr, "{http://checklists.nist.gov/xccdf/1.2}target")
            tg.text = host

            for rule, changed in host_rules.items():
                state = "fail" if changed else "pass"
                rr = ET.SubElement(tr, "{http://checklists.nist.gov/xccdf/1.2}rule-result")
                rr.set("idref", "xccdf_mil.disa.stig_rule_SV-{}_rule".format(rule))
                rs = ET.SubElement(rr, "{http://checklists.nist.gov/xccdf/1.2}result")
                rs.text = state

            passing = sum(1 for v in host_rules.values() if not v)
            sc = ET.SubElement(tr, "{http://checklists.nist.gov/xccdf/1.2}score")
            sc.set("maximum", str(len(host_rules)))
            sc.set("system", "urn:xccdf:scoring:flat-unweighted")
            sc.text = str(passing)

            suffix = "xccdf-results.xml" if self.assessing else "xccdf-remediate-run.xml"
            out_path = os.path.join(self.xml_dir, "{}-{}-{}".format(self.run_ts, host, suffix))
            with open(out_path, "wb") as f:
                out = ET.tostring(tr)
                pretty = xml.dom.minidom.parseString(out).toprettyxml(encoding="utf-8")
                f.write(pretty)
            self._display.display("Wrote XCCDF results for {}: {}".format(host, out_path))
