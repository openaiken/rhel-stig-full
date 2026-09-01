# CLAUDE.md

Agent notes for this repo. `README.md` documents *what the project does and how to
run it* — read it for usage. This file covers what will bite you, and is loaded
every session, so keep it short and high-signal.

Current revision: **RHEL 9 STIG V2R9** (445 rules, Release: 9, 01 Jul 2026).

## The one thing to understand first

`formal_role_covered` in `files/rules.json` is **host-dependent, not a property of
the role**. 21 formal-role tasks are gated on conditionals like
`packages['dconf'] is defined`. On a host with dconf those tasks run and the
callback records a result; on a headless host they are skipped *silently* and the
rule lands in the checklist as `not_reviewed`. Measured: 278 covered on one host
vs 259 on another — same role.

Consequences:

- The supplement deliberately carries more tasks (187) than any one host strictly
  needs (167 here). **Never delete a supplement task because a scan shows the
  formal role covering that rule.** The overlap is what makes coverage
  host-independent.
- `cklb.py` gives supplement facts precedence over XCCDF for this reason.
- In `audit_coverage.py` output, a big gap between `formal role static tasks (# R-)`
  and `formal_role_covered` means many role tasks are being skipped on that host.

## Identifiers

**STIG ID (`RHEL-09-XXXXXX`) is the key everywhere** — `rules.json` keys, task
filenames, tags, `supp_rules`, `supp_facts`, and the CKLB join on `rule_version`.

V-numbers churn between revisions and must not be used as identity. They appear
functionally in exactly two places, both same-revision joins against the
callback's XCCDF *results*, which identify rules only by `SV-`/`V-` number:
`scripts/parse_xccdf_benchmark.py` and `roles/cklb_renderer/filter_plugins/cklb.py`.

One V-number dependency exists by DISA's design: `rhel9STIG_stigrule_<Vnum>_Manage`
toggles. R8→R9 renamed none of them, but a future revision could, which would
silently invalidate `group_vars/all/stig_formal_role.yml`. Check on every bump.

## Status contract

The supplement writes only `not_a_finding`, `open`, `not_applicable`. It **never**
writes `not_reviewed`: a rule awaiting an operator decision is `open` until its
attestation var is set, and a check that cannot determine state is also `open`
(an unverifiable control is conservatively a finding). Therefore `not_reviewed`
in a rendered checklist means a real coverage gap, never an assessment outcome.
Reviewers reject submitted checklists containing it.

Do not confuse `not_applicable` (rule doesn't apply here) with `not_a_finding`
(rule applies, system complies).

## Writing supplement tasks

- One file per STIG ID: `roles/rhel9_stig_supplement/tasks/<cat>/RHEL-09-XXXXXX.yml`
- Shell emits `STATUS: PASS` / `STATUS: FAIL` / `NA:`; exit code is never used
- `changed_when: false` and `failed_when: false` on every shell task
- No apostrophes in shell comments (Ansible `parse_kv` sees unbalanced quotes)
- No literal double quotes in `set_fact` strings (they sit inside double-quoted YAML)
- Wire into `tasks/main.yml` with `import_tasks`, a STIG ID tag, and a
  `supp_rules` conditional; add the toggle to `group_vars/all/stig_supplement.yml`
- Attestation vars: bool + optional `_method` string; the bool clears the finding,
  the method string lands in `finding_details`

### Shell traps that have actually shipped bugs here

- **`grep -n`/`-rn` prefix every line with `file:lineno:`** (just `lineno:` under
  `-h`). A downstream `grep -v '^\s*#'` then never matches. This shipped in 5
  tasks: one cried wolf on every host, one was a **silent always-PASS**. Anchor
  past the prefix: `grep -vE '^[^:]+:[0-9]+:[[:space:]]*#'`, or `^[0-9]*:` under `-h`.
- A check that can only ever return PASS is worse than no check. When the
  detection pattern and the exclusion filters share a broken anchor, both die
  together and the task reports compliant forever.
- `process substitution` (`done < <(...)`) is fine — the shell module gets bash.

## Verification loop

```bash
python3 scripts/audit_coverage.py     # must print CLEAN
ansible-playbook supplement.yml -t RHEL-09-XXXXXX -e my_host=stigging-sandbox2 \
    --vault-password-file vault_pass.txt        # single rule, fast
./run.sh validate --host stigging-sandbox2 --vault-pass-file vault_pass.txt
```

`audit_coverage.py` cross-checks `rules.json`, task files, `main.yml` wiring, and
`supp_rules` toggles. It must print CLEAN before any revision work is done.
Then confirm the rendered CKLB has **0 `not_reviewed`** and 0 empty
`finding_details`.

Test host: `stigging-sandbox2` (192.168.1.65, user `claude`, key
`~/.ansible/stig-sandbox2`). **`ansible_pipelining=true` is mandatory there** —
fapolicyd plus `noexec` on `/home`, `/tmp`, `/var/tmp` means Ansible cannot drop
and execute a module file, and every module fails without it. It is set per-host
in `hosts`. Validate mode is genuinely non-destructive (play-level `check_mode`
is honored; `changed: true` there is a prediction, not an applied change).

## Revision bump procedure

1. Replace `roles/rhel9STIG/`. **Delete `roles/rhel9STIG/callback_plugins/`** —
   the role ships a stale `stig_xml` callback that reads the same `XML_PATH` env
   var as ours and breaks XCCDF output. It has shipped in the tarball before.
2. Confirm the new XCCDF's release label and rule count match the new CKLB
   template's `release_info` and `size`.
3. `python3 scripts/diff_benchmarks.py OLD.xml NEW.xml --json out.json`, then
   reconcile against DISA's changelog. The XCCDF is authoritative; the changelog
   omits pure `rule_id` revision bumps.
4. Update `XCCDF_PATH` in `parse_xccdf_benchmark.py` and `cklb_template_path` in
   `roles/cklb_renderer/defaults/main.yml`.
5. Scan a host, regenerate `rules.json`, regenerate the comment blocks in
   `stig_formal_role.yml` (from the role's own defaults, not from a scan) and
   `stig_supplement.yml`.
6. Rework tasks for substantive check/fix changes; retire tasks, toggles, and
   attestation vars for removed rules.

**Budget time to sweep for latent shell-logic bugs, not just to diff rule text.**
In the V2R9 bump, three of four commits fixed pre-existing R8 defects that the
changelog could never have revealed. Check whether a supplement task is already
correct before changing it — in V2R9, four of seven "changed" rules needed no
code at all.

## Commit style

One logical change per commit, subject prefixed `[Claude-Code] `. Say plainly
when a fix is a pre-existing defect rather than part of the revision bump.
Secrets (`vault_pass.txt`, `group_vars/all/vault.yml`) are gitignored — never
read or commit them; pass paths to `--vault-pass-file` instead.
