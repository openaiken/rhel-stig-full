# rhel-stig-full
Modification and Extension of the formal RHEL 9 STIG Ansible code, to fully implement every control and produce a ready-to-report Checklist for STIG Viewer 3.x.

## WIP
This project is a Work-In-Progress. Furthermore, *this document was largely written by Claude Code, and manually edited for clarity and finer details.*

## Overview

The DISA Ansible role (`rhel9STIG`) remediates most RHEL 9 STIG controls but emits XCCDF results for only 259 of the 446 rules. This project wraps that role with:

- A **supplement role** (`rhel9_stig_supplement`) containing shell-based validation tasks for all 187 rules the formal role does not cover.
- A **CKLB renderer** (`cklb_renderer`) that merges XCCDF results and supplement facts into a populated `.cklb` checklist for STIG Viewer 3.x.
- A **`run.sh`** orchestration script that drives all three playbooks with a single command.

The result is a fully automated pipeline that produces a deliverable checklist covering all 446 rules.

## Usage

### Quickstart

```bash
# Full validate pass — runs formal role in check mode, runs all supplement
# checks, writes a populated CKLB to reports/
./run.sh validate

# Full remediate pass — enforces STIG settings, runs supplement checks
# (no CKLB output; run validate afterward for the deliverable)
./run.sh remediate
```

### `run.sh` reference

```
Usage: run.sh <validate|remediate> [OPTIONS] [-- ANSIBLE_ARGS]

Modes (required):
  validate    Dry-run: formal role in check mode, supplement validation,
              CKLB checklist generated.
  remediate   Apply: formal role enforces settings, supplement runs.
              CKLB is NOT generated (run validate after for deliverable).

Target:
  -H HOST, --host HOST      Inventory host or group (default: default_host_group)

Auth (mutually exclusive):
  (default)                 Prompt for become (sudo) password once
  --vault-file FILE         Read become credentials from an ansible-vault file
  --vault                   Prompt for vault password; reads become credentials
                            from the vault for the duration of the run

Skip plays:
  --skip-formal             Skip the rhel9STIG formal role play
  --skip-supplement         Skip supplement checks/remediation
  --skip-cklb               Skip the CKLB renderer (validate mode only)

Other:
  -v, -vv, -vvv, -vvvv     Ansible verbosity (default: -v)
  --                        Pass remaining arguments verbatim to every
                            ansible-playbook call
```

**Examples:**
```bash
./run.sh validate --host myserver.example.com
./run.sh remediate --host prod-servers --vault-file ~/.vault_pass
./run.sh validate --skip-formal -vvv
./run.sh validate --host myserver -- -e "supp_rules={'RHEL-09-671010': false}"
```

### Running playbooks directly

Each playbook can also be run standalone:

```bash
# Formal role only, check mode
ansible-playbook formal-role.yml -t validate -e my_host=myserver

# Supplement only, single rule by STIG ID tag
ansible-playbook supplement.yml -t RHEL-09-653030 -e my_host=myserver

# CKLB renderer only (against existing reports/ output)
ansible-playbook cklb.yml -t validate -e my_host=myserver
```

### Tags

| Tag | Formal role | Supplement role | CKLB renderer |
|---|---|---|---|
| `validate` | Runs in check mode (no changes) | Runs all check tasks | Renders checklist |
| `remediate` | Remediates findings | Runs all remediation tasks | Not applicable |
| `RHEL-09-XXXXXX` | — | Runs that single rule only | — |
| *(no tag)* | Remediates | Runs all tasks | Renders checklist |

Tags can be combined: `-t validate,RHEL-09-231190` runs the supplement in validate mode for one rule only.

## Configuration

All configuration lives in `group_vars/all/`. Per-host overrides go in `host_vars/<hostname>/`.

### `stig_attestation.yml` — operator attestation

These variables require human judgment or organizational context that cannot be determined programmatically. Each is documented inline with verification steps and expected values. All default to `false`; a `false` value produces an open finding in the generated checklist.

Many attestations follow a **bool + method** pattern: the bool clears the finding, the method string is recorded in `finding_details` for the checklist reviewer.

```yaml
rhel9_attest_disk_encryption_na: false
rhel9_attest_disk_encryption_method: ""   # e.g. "VMware datastore encryption"
```

**Status semantics** — two distinct values are used and must not be confused:
- `not_applicable` — the rule does not apply to this system (no GDM, no postfix, no ipsec, etc.)
- `not_a_finding` — the rule applies and the system is compliant

#### Attestation variable reference

| Variable(s) | Rule(s) | Purpose |
|---|---|---|
| `rhel9_attest_patching_current` | 211015 | Patches are current per org policy |
| `rhel9_gui_approved` | 211030 | Graphical display manager is ISSO-approved |
| `rhel9_attest_disk_encryption_na[_method]` | 231190 | Encryption provided at hypervisor/storage layer |
| `rhel9_grub_superuser` | 212020 | Non-default grub2 superuser account name |
| `rhel9_attest_ppsm_compliant` | 251035 | Firewall ports/protocols comply with PPSM CAL |
| `rhel9_attest_ntp_source_approved` | 252020 | NTP sources are organizationally approved |
| `rhel9_attest_ipsec_tunnels_approved` | 252045 | IPsec tunnels are documented and ISSO-approved |
| `rhel9_attest_usbguard_na` | 291030 | VM with no USB peripherals (rule not applicable) |
| `rhel9_attest_usbguard_compliant[_method]` | 291030 | Alternate USB blocking mechanism in use |
| `rhel9_attest_wifi_approved[_comment]` | 291040 | Wireless adapter is ISSO-approved operational requirement |
| `rhel9_attest_audit_notification_compliant[_method]` | 252060, 653125 | Alternate audit failure notification mechanism |
| `rhel9_authorized_users` | 411095 | Complete list of authorized accounts in /etc/passwd |
| `rhel9_temporary_accounts` | 411040 | List of temporary accounts (empty list = not_a_finding) |
| `rhel9_attest_sel_sudo_context_compliant[_method]` | 431016 | IdM-managed sudo rules include sysadm_t/sysadm_r |
| `rhel9_attest_nopasswd_isso_approved` | 611085 | NOPASSWD sudoers entries have documented ISSO approval |
| `rhel9_attest_alt_mfa_cert_verification[_method]` | 611170 | Non-SSSD MFA implements certificate revocation checking |
| `rhel9_attest_no_ssh_key_auth[_method]` | 611190 | Alternate MFA (PIV/CAC, FIDO2) makes SSH key passphrase check NA |
| `rhel9_attest_alt_mfa_no_pki[_method]` | 631010, 631015 | Non-PKI MFA in use (FIDO2/OTP); both 631 rules become NA |
| `rhel9_attest_ipa_certmap[_method]` | 631015 | IPA/FreeIPA manages certmap centrally (no local sssd.conf section) |
| `rhel9_attest_alt_fim_tool[_name]` | 651010–651035 | Alternate FIM tool (Tripwire, Wazuh, etc.); all 651 rules become NA |
| `rhel9_aide_timer_unit` | 651015 | Systemd timer unit name for AIDE scheduling (preferred over cron) |
| `rhel9_attest_alt_log_offload[_method]` | 652025, 652055 | Alternate log offload tool (SPLUNK, Filebeat, etc.) |
| `rhel9_attest_log_aggregation_server` | 652025 | **Set in `host_vars/` only** — host is an authorized syslog collector |
| `rhel9_audit_min_storage_gb` | 653030 | Minimum available audit partition space in GB (default: 2) |
| `rhel9_attest_audit_immediate_offload[_method]` | 653030 | Audit records forwarded immediately to remote facility (rule NA) |
| `rhel9_attest_crypto_subpolicy_approved[_method]` | 672020 | AO-approved crypto subpolicy exception with ISSO documentation |

> **`rhel9_attest_log_aggregation_server`** must be set in `host_vars/<hostname>/`, never in `group_vars/all/`. Setting it globally would silently clear a real finding on every non-collector host.

### `stig_formal_role.yml` — formal role remediation toggles

Uncomment and set to `false` to prevent the formal role from remediating a specific rule:

```yaml
rhel9STIG_stigrule_257779_Manage: false   # RHEL-09-211020
```

### `stig_supplement.yml` — supplement rule toggles

Set any rule to `false` to skip it entirely from supplement checks:

```yaml
supp_rules:
  RHEL-09-231190: false
  RHEL-09-671010: false
```

## How the Supplement Works

Each supplement task file follows a two-task structure:

1. A `shell: |` block that inspects the system and writes `STATUS: PASS`, `STATUS: FAIL`, or `NA:` to stdout. The shell always exits 0 (`failed_when: false`); the exit code is never used for pass/fail determination.
2. A `set_fact` task that reads `_XXXXXX_result.stdout` and writes the rule's `status`, `finding_details`, and `comments` into the `supp_facts` accumulator dict.

At the end of the play, `supp_facts` is written to `reports/supp-facts/` as a JSON file keyed by STIG ID. The CKLB renderer reads this alongside the XCCDF results.

**Status values written to `supp_facts`:**
- `not_a_finding` — check passed or compliant condition attested
- `open` — check failed and no clearing attestation is set
- `not_applicable` — rule does not apply to this system

**Coverage:**

| Category range | Domain |
|---|---|
| 171 | Consent banner (graphical) |
| 211–215 | OS/kernel configuration |
| 231–232 | File permissions and ownership |
| 251–252, 255 | Networking (firewall, NTP, SSH) |
| 271 | GNOME/dconf settings |
| 291 | Hardware (USB, wifi) |
| 411–412 | Account and session management |
| 431–433 | sudo / SELinux |
| 611–631 | Authentication and PKI |
| 651–654 | File integrity (AIDE) and audit logging |
| 671–672 | FIPS and crypto policy |

All 187 rules not covered by the formal role have supplement tasks. Coverage is verified by cross-referencing `files/rules.json`.

## Project Structure

### Playbooks
- **`formal-role.yml`** — runs the DISA `rhel9STIG` role. `validate` tag automatically enables check mode. A callback plugin records per-host XCCDF results to `reports/`.
- **`supplement.yml`** — runs `rhel9_stig_supplement`. Results are written to `reports/supp-facts/` as JSON.
- **`cklb.yml`** — runs `cklb_renderer`, merging XCCDF results and supplement facts into a populated CKLB file in `reports/`. Can be run independently against existing report files.
- **`run.sh`** — orchestrates all three playbooks. Handles become/vault credential prompts, skip flags, and argument passthrough.

### Roles
- **`roles/rhel9STIG/`** — unmodified DISA formal role (RHEL 9 V2R8). Do not edit. When updating to a new version, delete `roles/rhel9STIG/callback_plugins/` if present — the role ships a stale `stig_xml` callback that conflicts with the project callback and will silently break XCCDF output.
- **`roles/rhel9_stig_supplement/`** — 187 shell-based validation tasks, one file per STIG ID, organized under `tasks/<category>/`. Attestation-aware: each task reads from `group_vars/all/stig_attestation.yml` and folds attestation values into `finding_details`.
- **`roles/cklb_renderer/`** — Ansible role with a Python filter plugin (`filter_plugins/cklb.py`) that parses XCCDF results and supplement JSON, maps them onto the CKLB template, and writes the rendered checklist. Handles multi-scan history by picking the latest result file per host.

### Supporting Files
- **`files/rules.json`** — all 446 RHEL 9 V2R8 rules keyed by STIG ID. Includes `formal_role_covered` flag derived from actual XCCDF callback output. Regenerate with `python3 scripts/parse_xccdf_benchmark.py` after a new scan or a new benchmark release.
- **`files/empty-checklist-rhel9v2r8.cklb`** — CKLB template used by the renderer. Replace with the new template when DISA releases a new revision.
- **`callbacks/rhel9_xccdf_results.py`** — callback plugin that writes per-host XCCDF results to `reports/`. A refactor of the DISA-bundled `stig_xml` callback, renamed to avoid collisions on role updates.
- **`scripts/parse_xccdf_benchmark.py`** — parses the XCCDF benchmark XML and cross-references XCCDF results to produce `files/rules.json`.

### Reports
The `reports/` directory is gitignored. It contains:
- `*-<hostname>-xccdf-results.xml` — per-run XCCDF output from the formal role callback
- `supp-facts/*-<hostname>.json` — per-run supplement facts from the supplement role
- `*-<hostname>-*.cklb` — rendered CKLB checklists

## Maintenance

### Updating to a new STIG revision
1. Replace `roles/rhel9STIG/` with the new DISA role. Remove `roles/rhel9STIG/callback_plugins/` if present.
2. Replace `files/empty-checklist-rhel9v2r8.cklb` with the new CKLB template.
3. Run a scan against a representative host to generate a fresh XCCDF results file.
4. Run `python3 scripts/parse_xccdf_benchmark.py` to regenerate `files/rules.json` with updated `formal_role_covered` flags and rule metadata.
5. Review the diff — new rules added by DISA will appear as uncovered and will need supplement tasks.

### `files/rules.json` and `formal_role_covered`
This flag is set by cross-referencing the XCCDF callback output, not by inspecting the role source. It is the ground truth for which rules the formal role actually produces results for in your environment. On a fresh clone with no scan results, all rules show as uncovered; run at least one scan first.

### Supplement task conventions
- One file per STIG ID: `roles/rhel9_stig_supplement/tasks/<category>/RHEL-09-XXXXXX.yml`
- Shell blocks use `STATUS: PASS` / `STATUS: FAIL` / `NA:` sentinel output
- `changed_when: false` and `failed_when: false` on every shell task
- No apostrophes in shell block comments (Ansible's `parse_kv` sees unbalanced quotes)
- No literal double quotes in `set_fact` string values (embedded in outer double-quoted YAML)
- Attestation vars: bool + optional `_method` string; bool clears the finding, method appears in `finding_details`
- Wire new tasks into `roles/rhel9_stig_supplement/tasks/main.yml` with `import_tasks`, a STIG ID tag, and a `supp_rules` conditional
