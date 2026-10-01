# rhel-stig-full
Automated assessment of every RHEL 9 STIG control, producing a ready-to-report Checklist for STIG Viewer 3.x, plus remediation through the DISA RHEL 9 STIG Ansible role.

## WIP
This project is a Work-In-Progress. Furthermore, *this document was largely written by Claude Code, and manually edited for clarity and finer details.*

## Overview

- **Assessment** (`./run.sh validate`): the **`rhel9_stig_full` role** checks all 445 rules of RHEL 9 STIG V2R9, read-only, one task file per STIG ID, then renders the results into a populated `.cklb` checklist.
- **Remediation** (`./run.sh remediate`): the unmodified **DISA formal role** (`rhel9STIG`) enforces settings. It takes no part in assessment.

Why the formal role does not assess: in check mode it reports whether a task *would change something*, and its tasks write one exact line into one exact file. A host configured correctly any other way (a drop-in file, different spelling, a stricter value) was reported open. The assessment role checks what each STIG check text checks, on the effective state wherever there is one.

## Usage

```bash
./run.sh validate                      # assess every rule, write a checklist to reports/
./run.sh remediate                     # DISA role enforces settings; run validate after
./run.sh --help                        # all options, including exit codes
```

**Examples:**
```bash
./run.sh validate --host myserver.example.com --vault-pass-file ~/.vault_pass
./run.sh remediate --host prod-servers --vault-pass-file ~/.vault_pass
./run.sh validate --skip-supplement            # re-render from earlier results only
./run.sh validate --max-result-age 7           # merge only the last 7 days of results
./run.sh validate --host myserver -- -e "stig_rules={'RHEL-09-671010': false}"
```

`run.sh` exits 0 when every stage completed on every host, 2 when some hosts failed or were unreachable but the others were processed, and 1 when a stage failed outright.

### Running playbooks directly

```bash
ansible-playbook stig.yml -t validate -e my_host=myserver              # assess + checklist
ansible-playbook stig.yml -t RHEL-09-653030 -e my_host=myserver        # one rule, no render
ansible-playbook stig.yml -t RHEL-09-653030,render -e my_host=myserver # one rule + checklist
ansible-playbook stig.yml -t render -e my_host=myserver                # re-render only
ansible-playbook stig.yml -t remediate -e my_host=myserver             # remediate only
ansible-playbook stig.yml -t remediate,validate -e my_host=myserver    # remediate, then assess
```

`stig.yml` is the single playbook. Remediation runs only under the `remediate` tag, and a checklist is rendered only under `validate` or `render`. Every check is tagged `validate` and its STIG ID; a tag-limited run updates only those rules, since the renderer merges results per rule across runs. Without `--tags` every play runs, remediation included.

## Configuration

All configuration lives in `group_vars/all/`. Per-host overrides go in `host_vars/<hostname>/`.

### `stig_attestation.yml` — operator attestation

These variables record human judgment or organizational context that cannot be determined programmatically. Each is documented inline. All default to "not attested"; an unattested rule that needs one is an open finding.

Many follow a **bool + method** pattern: the bool clears the finding, the method string is recorded in `finding_details` for the reviewer.

**Status semantics** — two distinct values must not be confused:
- `not_applicable` — the rule does not apply to this system (no GDM, no postfix, a documented N/A clause)
- `not_a_finding` — the rule applies and the system is compliant

#### Attestation variable reference

| Variable(s) | Rule(s) | Purpose |
|---|---|---|
| `rhel9_attest_documented_exceptions` | ~25 rules (listed in the file) | Map of STIG ID to an ISSO/ISSM documentation reference, honoured only by rules whose check text allows a documented exception |
| `rhel9_attest_patching_current` | 211015 | Patches are current per org policy |
| `rhel9_gui_approved` | 211030, 215070 | Graphical interface is ISSO-approved |
| `rhel9_grub_superuser` | 212020 | Non-default grub2 superuser account name |
| `rhel9_attest_disk_encryption_na[_method]` | 231190 | Encryption provided at hypervisor/storage layer |
| `rhel9_attest_ppsm_compliant` | 251035 | Firewall ports/protocols comply with PPSM CAL |
| `rhel9_attest_ntp_source_approved` | 252020 | NTP sources are organizationally approved |
| `rhel9_attest_ipsec_tunnels_approved` | 252045 | IPsec tunnels are documented and ISSO-approved |
| `rhel9_attest_no_sshd[_method]` | 255010, 255015 | Documented exception: this host must not run SSH (the sshd rules are N/A without the package) |
| `rhel9_attest_ssh_x11_forwarding_approved[_method]` | 255155 | X11 forwarding is an ISSO-documented requirement |
| `rhel9_attest_usbguard_na` | 291015, 291020, 291025, 291030 | VM with no USB peripherals |
| `rhel9_attest_usbguard_compliant[_method]` | 291015, 291020, 291030 | Alternate USB blocking mechanism in use |
| `rhel9_attest_wifi_approved[_comment]` | 291040 | Wireless adapter is an ISSO-approved requirement |
| `rhel9_attest_audit_notification_compliant[_method]` | 215101, 252060, 653125 | Alternate audit failure notification mechanism |
| `rhel9_authorized_users` | 411095 | Complete list of authorized accounts in /etc/passwd |
| `rhel9_temporary_accounts` | 411040 | Temporary accounts (empty list = not_a_finding) |
| `rhel9_sudo_designated_admins` | 431016 | Designated sudo admin group(s)/account(s), as written in sudoers |
| `rhel9_attest_sel_sudo_context_compliant[_method]` | 431016 | IdM-managed sudo rules include sysadm_t/sysadm_r |
| `rhel9_attest_nopasswd_isso_approved` | 611085 | NOPASSWD sudoers entries have documented ISSO approval |
| `rhel9_attest_alt_mfa_cert_verification[_method]` | 611170 | Non-SSSD MFA implements certificate revocation checking |
| `rhel9_attest_no_ssh_key_auth[_method]` | 611190 | Alternate MFA makes the SSH key passphrase check moot |
| `rhel9_attest_alt_mfa_no_pki[_method]` | 215075, 255035, 611165, 611175, 631010, 631015 | Approved non-PKI MFA in use; these rules become N/A |
| `rhel9_attest_ipa_certmap[_method]` | 631015 | IPA manages certmap centrally |
| `rhel9_attest_alt_fim_tool[_name]` | 651010–651035 | Alternate file integrity tool |
| `rhel9_aide_timer_unit` | 651015 | Systemd timer unit name for AIDE scheduling |
| `rhel9_attest_alt_log_offload[_method]` | 652025, 652040, 652055 | Alternate log offload tool |
| `rhel9_attest_log_aggregation_server` | 652025 | **Set in `host_vars/` only** — host is an authorized syslog collector |
| `rhel9_audit_min_storage_gb` | 653030 | Minimum *size* of the audit log partition, as provisioned (default 2) |
| `rhel9_attest_audit_immediate_offload[_method]` | 653030 | Audit records forwarded immediately to a remote facility (N/A) |
| `rhel9_attest_crypto_subpolicy_approved[_method]` | 672020 | AO-approved crypto subpolicy exception |

> **`rhel9_attest_log_aggregation_server`** must be set in `host_vars/<hostname>/`, never in `group_vars/all/`. Setting it globally would silently clear a real finding on every non-collector host.

### `stig_rules.yml` — rule toggles

Set a rule to `false` to stop assessing it. Results from earlier runs are dropped too, so it renders `not_reviewed`:

```yaml
stig_rules:
  RHEL-09-231190: false
```

### `stig_formal_role.yml` — remediation toggles

Remediation only. Uncomment and set to `false` to stop the DISA role remediating a rule:

```yaml
rhel9STIG_stigrule_257779_Manage: false   # RHEL-09-211020
```

### Checklist age window

`cklb_max_result_age_days` (default 30, in `roles/rhel9_stig_full/defaults/main.yml`, or `run.sh --max-result-age`) limits which results are merged into the checklist. A rule with no result in the window renders `not_reviewed` rather than a stale status. 0 disables the limit.

## How Assessment Works

Each task file follows a two-task structure:

1. A `shell: |` block that inspects the system and prints `STATUS: PASS`, `STATUS: FAIL`, or `NA:` at the start of a line. The shell always exits 0 (`failed_when: false`); the exit code is never used.
2. A `set_fact` task that turns that output into the rule's `status`, `finding_details` and `comments` in the `stig_facts` accumulator.

At the end of the play, `stig_facts` is written to `reports/results/<YYYYMonDD-HH:MM:SS>-<host>.json`. The renderer merges a host's result files per rule, newest winning, and ends each rule's comments with the run it came from.

**Status values:**
- `not_a_finding` — compliant, or a clearing attestation is set
- `open` — non-compliant, or the state could not be determined (an unverifiable control is conservatively a finding)
- `not_applicable` — the rule does not apply, per its STIG text

Assessment never writes `not_reviewed`. In a rendered checklist it means the rule was not assessed inside the age window — a gap to fix, not an outcome. Reviewers reject a checklist containing it.

Checks prefer the effective value to configuration text (`sysctl -n`, `sshd -T`, `auditctl -l`, `gsettings`, `systemctl show`, `systemd-analyze cat-config`), read files the way their consumer does (drop-ins, last value wins), and compare thresholds as thresholds. Audit-rule coverage is checked semantically by the `rhel9_audit_coverage` filter plugin (unit tests: `python3 scripts/test_audit_rules.py`).

## Project Structure

### Playbooks
- **`stig.yml`** — the single playbook: play 1 is the DISA role (`remediate` tag), play 2 the assessment and checklist (`validate` / `render` tags).
- **`run.sh`** — orchestration: credentials, skip flags, per-host failure handling, argument passthrough.

### Roles
- **`roles/rhel9_stig_full/`** — 445 assessment tasks, one per STIG ID, under `tasks/<category>/`; `tasks/render.yml` and `filter_plugins/cklb.py` render the checklist; `filter_plugins/audit_rules.py` checks audit-rule coverage.
- **`roles/rhel9STIG/`** — unmodified DISA formal role (V2R9), remediation only. Do not edit.

### Supporting Files
- **`files/U_RHEL_9_STIG_V2R9_Manual-xccdf.xml`** — the DISA benchmark, source of `rules.json`.
- **`files/rules.json`** — all 445 rules keyed by STIG ID (check and fix text, severity, CCIs). Regenerate with `python3 scripts/parse_xccdf_benchmark.py`.
- **`files/empty-checklist-rhel9v2r9.cklb`** — CKLB template used by the renderer.
- **`scripts/audit_coverage.py`** — every rule in `rules.json` and the template must have exactly one wired, toggled task. Must print `CLEAN`.
- **`scripts/lint_checks.py`** — static checks for the bug classes found in this codebase. Must report 0.
- **`scripts/diff_benchmarks.py`** — diffs two benchmarks by STIG ID; run first on a revision bump.
- **`scripts/test_audit_rules.py`** — unit tests for the audit-rule filter.

### Reports
`reports/` is gitignored: `results/*-<host>.json` (results) and `*-<host>.cklb` (checklists).

## Maintenance

### Updating to a new STIG revision
1. Put the new benchmark XML in `files/`, update `XCCDF_PATH` in `scripts/parse_xccdf_benchmark.py`, and regenerate `files/rules.json`.
2. Replace the CKLB template in `files/` and `cklb_template_path` in `roles/rhel9_stig_full/defaults/main.yml`. Confirm its `release_info` and rule count match the benchmark.
3. Run `python3 scripts/diff_benchmarks.py OLD.xml NEW.xml` and reconcile against DISA's changelog (the XCCDF is authoritative; the changelog omits pure `rule_id` bumps).
4. Rework tasks for rules whose check text changed; add tasks for new rules; retire tasks, toggles and attestation vars for removed rules.
5. For remediation, replace `roles/rhel9STIG/` with the new DISA role (delete any `callback_plugins/` it ships) and regenerate the comment block in `group_vars/all/stig_formal_role.yml`.
6. `python3 scripts/audit_coverage.py` must print `CLEAN` and `python3 scripts/lint_checks.py` must report 0.

### Task conventions
- One file per STIG ID: `roles/rhel9_stig_full/tasks/<category>/RHEL-09-XXXXXX.yml`
- Status markers at the start of a line, matched with `is search('^...', multiline=True)`
- `changed_when: false` and `failed_when: false` on every shell/command task
- No apostrophes in shell comments; no double quotes inside the `set_fact` string; no `{#` anywhere
- Attestation vars: bool + optional `_method` string, and the method must reach `finding_details`
- Wire into `tasks/main.yml` with `import_tasks`, a STIG ID tag, and a `stig_rules` conditional
