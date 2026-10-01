#!/usr/bin/env python3
"""Unit tests for roles/rhel9_stig_full/filter_plugins/audit_rules.py.

Run: python3 scripts/test_audit_rules.py   (exits non-zero on any failure)
"""
import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location(
    "audit_rules", os.path.join(HERE, "..", "roles", "rhel9_stig_full",
                                "filter_plugins", "audit_rules.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

E = "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod"
P = "-a always,exit -F arch=b64 -F path=/etc/passwd -F perm=wa -k identity"
X = "-a always,exit -S all -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged-chage"
CASES = [
    ("exact, other key", E, "-a always,exit -F arch=b64 -S fchmodat,chmod,fchmod -F auid>=1000 -F auid!=unset -k mykey", True),
    ("superset syscalls", E, "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,chown -F auid>=1000 -F auid!=-1", True),
    ("missing one syscall", E, "-a always,exit -F arch=b64 -S chmod,fchmod -F auid>=1000 -F auid!=-1", False),
    ("wrong arch", E, "-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1", False),
    ("extra narrowing filter", E, "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F uid=0", False),
    ("fewer filters (broader)", E, "-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat", True),
    ("never action", E, "-a never,exit -F arch=b64 -S chmod,fchmod,fchmodat", False),
    ("watch covers path rule", P, "-w /etc/passwd -p wa -k x", True),
    ("watch missing perm a", P, "-w /etc/passwd -p w -k x", False),
    ("watch on other path", P, "-w /etc/passwd- -p wa -k x", False),
    ("exe rule exact", X, "-a always,exit -S all -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=-1 -F key=k", True),
    ("exe rule other binary", X, "-a always,exit -S all -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=-1", False),
    ("exe rule wrong perm", X, "-a always,exit -S all -F path=/usr/bin/chage -F perm=w -F auid>=1000 -F auid!=-1", False),
    ("syscall rule cannot cover exe", X, "-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1", False),
    ("empty rule set", E, "No rules", False),
]

failures = 0
for name, expected, loaded, want in CASES:
    got = not m.rhel9_audit_coverage(loaded, [expected])["missing"]
    ok = got == want
    failures += not ok
    print("{}  {:32} covered={}".format("ok  " if ok else "FAIL", name, got))
print("failures:", failures)
sys.exit(1 if failures else 0)
