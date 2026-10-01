# CLAUDE.md

Agent notes for this repo. `README.md` documents *what the project does and how to
run it* — read it for usage. This file covers what will bite you, and is loaded
every session, so keep it short and high-signal.

Current revision: **RHEL 9 STIG V2R9** (445 rules, Release: 9, 01 Jul 2026).

## The one thing to understand first

**`roles/rhel9_stig_full` assesses every rule; the DISA formal role
(`roles/rhel9STIG`) only remediates.** One playbook, `stig.yml`, selected by
tag: `disa_remediate` runs the DISA role; `remediate` runs every check, then
our own fixes (`tasks/fix/`) for rules that came back `open` only; `validate`
assesses and renders (with `remediate`: re-checks what a fix changed first);
`render` re-renders from earlier results. `remediate` alone writes no results
file: its pre-fix verdicts would be newest and a render would show fixed
rules open. Every rule in
`rules.json` and the CKLB template has exactly one task (`audit_coverage.py`
enforces it).

Why the formal role cannot assess: in check mode a rule "fails" when a task
*would change something*, and its tasks write one exact line into one exact
file or set one exact value. A host configured correctly any other way was
reported open: drop-ins (`sysctl.d`, `sshd_config.d`, `rules.d`,
`pwquality.conf.d`, `modprobe.d/<other>.conf`), other spellings (`HALT`,
`key = v`, tabs), **stricter** values than its fixed one (minlen 16 for "15 or
more"; mode 0600 for "0640 or less"), and N/A clauses it ignores. On
delta-bindtest (ComplianceAsCode) that was 124 of 156 open findings. So checks
here test what the STIG check text tests, on the effective value where one
exists (`sysctl -n`, `sshd -T`, `auditctl -l` via the `rhel9_audit_coverage`
filter, `gsettings`, `systemctl show`), files read as their consumer reads
them, thresholds compared as thresholds.

Results and rendering:

- `cklb.py` merges a host's result files per rule, newest winning, and stamps
  each rule's comments with its run. A tag-limited run (`-t RHEL-09-...`) must
  not blank the other rules. Rules switched off in `stig_rules` are dropped;
  files are matched to the exact host name (glob suffix collisions).
- Result files are `reports/results/YYYYMonDD-HH:MM:SS-<host>.json` (the
  older `YYMonDD-HH:MM` form still parses). Only the last
  `cklb_max_result_age_days` (default 30, `run.sh --max-result-age`, 0 = none)
  are merged; older results are dropped, not reported.
- `run.sh` exits 2 when some hosts failed or were unreachable but others
  completed, 1 when a stage fails outright. ansible-core exits 4 for both
  "unreachable" and "parse/vault error", so run.sh decides from the PLAY RECAP.
- Every stage needs the vault password: `group_vars/all/vault.yml` is loaded
  for every play.

`rhel9_attest_documented_exceptions` (STIG ID -> documentation reference) is
honoured only by rules whose check text allows an ISSO/ISSM-documented
exception; each such task says so, and the var's comment lists them.

## Identifiers

**STIG ID (`RHEL-09-XXXXXX`) is the key everywhere** — `rules.json` keys, task
filenames, tags, `stig_rules`, `stig_facts`, and the CKLB join on `rule_version`.

V-numbers churn between revisions and must not be used as identity. Assessment
uses none. The one V-number dependency is DISA's, and remediation only:
`rhel9STIG_stigrule_<Vnum>_Manage` toggles in `group_vars/all/stig_formal_role.yml`.
R8→R9 renamed none, but a future revision could. Check on every bump.

## Status contract

Assessment writes only `not_a_finding`, `open`, `not_applicable`. It **never**
writes `not_reviewed`: a rule awaiting an operator decision is `open` until its
attestation var is set, and a check that cannot determine state is also `open`
(an unverifiable control is conservatively a finding). Therefore `not_reviewed`
in a rendered checklist means a real coverage gap, never an assessment outcome.
Reviewers reject submitted checklists containing it.

Do not confuse `not_applicable` (rule doesn't apply here) with `not_a_finding`
(rule applies, system complies).

## Writing check tasks

- One file per STIG ID: `roles/rhel9_stig_full/tasks/<cat>/RHEL-09-XXXXXX.yml`
- Shell emits `STATUS: PASS` / `STATUS: FAIL` / `NA:`; exit code is never used
- `changed_when: false`, `failed_when: false`, `check_mode: false` on every
  shell task (checks gate fixes, so they must run under `--check` too)
- No apostrophes in shell comments (Ansible `parse_kv` sees unbalanced quotes)
- No literal double quotes in `set_fact` strings (they sit inside double-quoted YAML)
- Wire into `tasks/main.yml` with `import_tasks`, a STIG ID tag, and a
  `stig_rules` conditional; add the toggle to `group_vars/all/stig_rules.yml`
- Attestation vars: bool + optional `_method` string; the bool clears the finding,
  the method string lands in `finding_details`

### Shell traps that have actually shipped bugs here

Run `python3 scripts/lint_checks.py` — it encodes every class below and must
report 0. Re-run it after touching any task.

- **`grep -n`/`-rn` prefix every line with `file:lineno:`** (just `lineno:` under
  `-h`). A downstream `grep -v '^\s*#'` then never matches. This shipped in 5
  tasks: one cried wolf on every host, one was a **silent always-PASS**. Anchor
  past the prefix: `grep -vE '^[^:]+:[0-9]+:[[:space:]]*#'`, or `^[0-9]*:` under `-h`.
- A check that can only ever return PASS is worse than no check. When the
  detection pattern and the exclusion filters share a broken anchor, both die
  together and the task reports compliant forever.
- **Never compare an octal mode as a decimal string.** `stat -c '%a'` gives
  `"640"`; testing `$1+0 > 600` misses every mode whose owner digit is 0, so a
  world-readable private key at `0004` scores 4 and passes. Use a bitmask of the
  disallowed bits: `[ $(( 8#$mode & 8#177 )) -ne 0 ]` for "0600 or less
  permissive", `8#133` for 0644. (`8#` is bash base-8.) Converting correctly
  to decimal and comparing by size (`printf '%d' "0$mode"` then `-le 384`) is
  the same bug: 0006 is numerically tiny. Lint rule OCTAL-MAGNITUDE.
- **Grepping a config file does not prove the setting is in effect.** systemd
  ignores drop-ins whose name does not end in `.conf`, so a grep hit can reflect
  dead configuration — this is exactly what V2R9 renamed 211045's drop-in to fix.
  Prefer the effective value: `systemctl show -p X --value`, `sysctl -n`, `sshd -T`.
- **Every shell/command task needs `failed_when: false` — no exceptions.**
  `stig.yml` does not ignore errors, so one non-zero exit aborts the play
  and every later rule silently drops out of `stig_facts`. Deciding "this one
  can't fail" by inspection does not work: 412035 ended in
  `[ -n "$x" ] && echo ...`, which exits 1 when `$x` is empty, and aborted the
  run on a less-hardened host. The linter used to guess and missed it; it now
  requires the guard on every task. Status must come from stdout markers, and
  empty stdout must land on `open`.
- **Read configuration the way its consumer reads it** (all shipped as false
  negatives, fixed 2026-10-01): modprobe reads only `*.conf` (use
  `modprobe --showconfig`, which prints `-` as `_`); sudo skips sudoers.d
  names with a dot (use the files `visudo -c` reports); libpwquality reads
  `pwquality.conf.d/*.conf` first and `pwquality.conf` last, and
  `pam_pwquality.so`/`pam_faillock.so` arguments override both files;
  rsyslog loads rsyslog.d only via include (`rsyslogd -N1 -o FILE` gives the
  merged config); `/etc/default/grub` is sourced, last assignment wins.
- `xargs -I{}` rewrites every `{}` in its command, including `find -exec`'s
  (lint XARGS-BRACES).
- **An undeterminable result is `open`, never a pass.** If a lookup returns
  empty, do not let the status expression fall through to `not_a_finding`.
- If an attestation var follows the bool+`_method` pattern, the `_method` string
  must actually reach `finding_details`, or the operator's justification is
  silently discarded.
- **A STIG check often states more than one finding condition, and all must
  hold.** The four 212xxx kernel-argument rules each require both that every
  running kernel carries the arg *and* that `/etc/default/grub` carries it so
  it survives the next kernel install; only the first was implemented, so a
  host passed while the setting was one `dnf update` from vanishing. The
  linter lists multi-condition rules as INFO — re-read that list each bump.
- `process substitution` (`done < <(...)`) is fine — the shell module gets bash.
- **`{#` opens a Jinja comment.** Bash `${#arr[@]}` / `${#var}` in a task makes
  Ansible fail to parse the role, aborting the *whole* assessment run. Use
  `set -- ...; $#` or `wc -l`. Lint rule JINJA-COMMENT catches it.
- **Testing a shell body with plain `bash` does not prove the task works.**
  Fixture tests bypass Ansible templating; that is how the `{#` bug shipped.
  After any change, also run the task (or the whole assessment) through
  `ansible-playbook` on a real host.
- For GNOME/dconf rules, query `gsettings get|writable` (with
  `DCONF_PROFILE=user XDG_CONFIG_HOME=/nonexistent`), as the STIG does. Keyfile
  greps miss defaults, override order, uncompiled databases, and commented locks.

## Writing fix tasks (phase 4: own remediation, replacing the DISA role)

- `tasks/fix/<cat>/RHEL-09-XXXXXX.yml`, same `<cat>` as the check; wired in
  `tasks/fix_imports.yml` gated on toggle **and** `status == 'open'`
- Modules, not shell. One `block:`; a changed task appends the ID to
  `stig_fixed`; `rescue:` records `stig_fix_errors[id]` **and** appends to
  `stig_fixed` (a failed fix may still have changed state, so re-check it)
- Only fixes with one reasonable implementation. Never: 213105 (userns,
  breaks podman), 253075/254025 (forwarding), removals with exception
  clauses (nfs-utils, postfix, tuned, ...)
- A check that reads only runtime state passes as soon as the fix applies it,
  so the fix must prove persistence itself (sysctl fixes verify the last value
  in `systemd-sysctl --cat-config`, writing `zz-rhel9-stig-full.conf`)
- `lint_checks.py` FIX-STRUCTURE / FIX-NOT-WIRED / FIX-AUDIT-DRIFT enforce
  the above (audit fixes carry a copy of the check's expected rules)
- Traps hit writing the first 300 fixes:
  - `systemd_service masked: true` reported `changed` while `systemctl mask`
    refused (an admin symlink in /etc/systemd/system): verify `LoadState`
  - `{{3,4}}` in a regex is Jinja (lint JINJA-QUANTIFIER); `awk '{{print}}'`
    too; `: ` in a plain-scalar command breaks YAML (use `shell: |`)
  - a lookahead like `(?![^#]*x)` crosses lines under MULTILINE: add `\n`
  - rootfiles' tmpfiles.d resets /root dotfiles to 0644 on every rpm
    transaction and boot; override in /etc/tmpfiles.d
  - `-e 2` makes audit rules immutable until reboot; check `auditctl -s`
  - `augenrules` always leaves `/etc/audit/audit.rules` 0640 (STIG: 0600);
    653110 adds an auditd.service ExecStartPost chmod
  - a fix can settle another rule as a side effect; remediate.yml re-checks
    every rule that was open and has a fix, not only those that changed
  - a fix that only needs a value nobody else sets still must win against a
    later file: name drop-ins `zz-` (last wins) or `00-` (sshd: first wins)

## Verification loop

```bash
python3 scripts/audit_coverage.py     # must print CLEAN
python3 scripts/lint_checks.py    # must report 0
python3 scripts/test_audit_rules.py   # audit-rule filter unit tests
ansible-playbook stig.yml -t RHEL-09-XXXXXX -e my_host=demoserver \
    -l stigging-sandbox3,delta-bindtest --vault-password-file vault_pass.txt
./run.sh validate --host demoserver --vault-pass-file vault_pass.txt
```

`audit_coverage.py` cross-checks `rules.json`, the CKLB template, task files,
`main.yml` wiring and `stig_rules` toggles. It must print CLEAN before any
revision work is done.
Then confirm the rendered CKLB has **0 `not_reviewed`** and 0 empty
`finding_details`.

Test hosts (`demoserver` group): `stigging-sandbox3` is deliberately unhardened with GNOME (use it to find false negatives: any pass there is suspect); `delta-bindtest` is hardened. Primary: `stigging-sandbox2` (192.168.1.65, user `claude`, key
`~/.ansible/stig-sandbox2`). **`ansible_pipelining=true` is mandatory there** —
fapolicyd plus `noexec` on `/home`, `/tmp`, `/var/tmp` means Ansible cannot drop
and execute a module file, and every module fails without it. It is set per-host
in `hosts`. Validate is read-only: it runs only the assessment shells. Test
`remediate` with `-- --check` first, then for real, then again (must be
changed=0). Both demoserver hosts are dedicated test VMs, safe to break
(rebuilds just cost the owner time; delta-bindtest runs test containers).

## Revision bump procedure

1. Put the new benchmark XML in `files/`; update `XCCDF_PATH` in
   `parse_xccdf_benchmark.py` and regenerate `rules.json`.
2. Replace the CKLB template; update `cklb_template_path`. Its `release_info` and
   rule count must match the benchmark (`audit_coverage.py` cross-checks rules).
3. `python3 scripts/diff_benchmarks.py OLD.xml NEW.xml --json out.json`, then
   reconcile against DISA's changelog. The XCCDF is authoritative; the changelog
   omits pure `rule_id` revision bumps.
4. Rework tasks whose check text changed; add tasks for new rules (every rule
   needs one); retire tasks, toggles and attestation vars for removed rules.
5. Remediation: replace `roles/rhel9STIG/` (delete any `callback_plugins/` it
   ships) and regenerate the comment block in `stig_formal_role.yml` from the
   role's own defaults.

**Budget time to sweep for latent shell-logic bugs, not just to diff rule text.**
In the V2R9 bump, three of four commits fixed pre-existing R8 defects that the
changelog could never have revealed. Check whether a task is already
correct before changing it — in V2R9, four of seven "changed" rules needed no
code at all.

## Commit style

One logical change per commit, subject prefixed `[Claude-Code] `. Say plainly
when a fix is a pre-existing defect rather than part of the revision bump.
Secrets (`vault_pass.txt`, `group_vars/all/vault.yml`) are gitignored — never
read or commit them; pass paths to `--vault-pass-file` instead.
