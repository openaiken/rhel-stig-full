# rhel-stig-full
Modification and Extension of the formal RHEL 9 STIG Ansible code, to fully implement every control and produce a ready-to-report Checklist for STIG Viewer 3.x.

## WIP
This project is a Work-In-Progress. Furthermore, *this document was largely written by Claude Code, and manually edited for clarity and finer details.*

## Usage

### Typical workflow

**1. Remediate** — apply STIG hardening and run supplement checks:
```bash
ansible-playbook formal-role.yml supplement.yml -t remediate
```

**2. Validate** — run checks in check mode (no changes) and render the CKLB checklist:
```bash
ansible-playbook formal-role.yml supplement.yml cklb.yml -t validate
```

Or run all three playbooks in order with `run.sh`:
```bash
./run.sh -t validate
```

The `formal-role.yml` playbook detects the `validate` tag and automatically enables check mode for the formal role. The supplement role always runs its `validate`-tagged tasks in check mode by design (it only inspects, never modifies).

### Tags

| Tag | Formal role | Supplement role | CKLB renderer |
|---|---|---|---|
| `validate` | Runs in check mode (no changes) | Runs all check tasks | Renders checklist |
| `remediate` | Remediates findings | Runs all remediation tasks | Not applicable |
| `RHEL-09-XXXXXX` | — | Runs that single supplement rule | — |
| *(no tag)* | Remediates | Runs all tasks | Renders checklist |

You can also combine tags, e.g. `-t validate,RHEL-09-231190` to validate a single supplement rule.

### Targeting a host

All playbooks default to the `stigging-sandbox` host. Override with:
```bash
ansible-playbook formal-role.yml -e my_host=myserver.example.com -t validate
```

### Vars to configure

All levers are in `group_vars/all/`. Per-host overrides belong in `host_vars/<hostname>/`.

#### `group_vars/all/stig_attestation.yml` — operator attestation

These cannot be determined programmatically. Set each to `true` only after manually verifying the described condition.

| Variable | Rule | Description |
|---|---|---|
| `rhel9_attest_patching_current` | RHEL-09-211015 | Confirm patches are current per org patching policy |
| `rhel9_gui_approved` | RHEL-09-211030 | Set `true` if a graphical display manager is ISSO-approved |
| `rhel9_attest_disk_encryption_na` | RHEL-09-231190 | Set `true` if encryption is provided at hypervisor/storage layer |
| `rhel9_grub_superuser` | RHEL-09-212020 | Non-default grub2 superuser account name (leave blank = open finding) |

#### `group_vars/all/stig_formal_role.yml` — formal role Manage overrides

Uncomment and set to `false` to prevent the formal role from remediating a specific rule:
```yaml
rhel9STIG_stigrule_257779_Manage: false   # RHEL-09-211020
```

#### `group_vars/all/stig_supplement.yml` — supplement rule toggles

Set any rule to `false` to skip it entirely from supplement checks:
```yaml
supp_rules:
  RHEL-09-231190: false
```

## Project Structure


### Playbooks
- **`formal-role.yml`** — runs the unmodified DISA Ansible role (`rhel9STIG`). A custom callback plugin records results as a per-host XCCDF results file in `reports/`.
- **`supplement.yml`** — runs `rhel9_stig_supplement`, a custom role containing checks for rules not covered by the formal role. Results are written to `reports/supp-facts/` as JSON.
- **`cklb.yml`** — runs `cklb_renderer`, which merges the XCCDF results and supplement facts into a populated CKLB checklist for STIG Viewer 3.x. Output goes to `reports/`.
- **`run.sh`** — runs all three playbooks in order. Adds a `-vv` argument by default but passes all CLI arguments to all 3 playbooks.

### Roles
- **`roles/rhel9STIG/`** — unmodified DISA formal role. Do not edit.
- **`roles/rhel9_stig_supplement/`** — custom checks for the 187 rules the formal role does not cover. One task file per STIG ID (e.g. `tasks/RHEL-09-211010.yml`).
- **`roles/cklb_renderer/`** — reads `reports/` and `reports/supp-facts/` for the target host and renders a CKLB file. Can be run independently against existing results without re-running remediation.

### Supporting Files
- **`files/rules.json`** — all 446 RHEL 9 STIG V2R8 rules extracted from the XCCDF benchmark, keyed by STIG ID. Includes `formal_role_covered` flag derived from the latest XCCDF results file in `reports/`. Regenerate with `python3 scripts/parse_xccdf_benchmark.py` after a new scan or a new benchmark version.
- **`callbacks/stig_xml.py`** — Ansible callback plugin that writes per-host XCCDF results to `reports/`. It is a refactor of the stig_xml callback plugin included with the official DISA role.
- **`files/empty-checklist-rhel9v2r8.cklb`** — CKLB template used by the renderer. This should be replaced when new revisions are dropped.

### Notes
- Generating a new `files/rules.json` requires a recent XCCDF results file in `reports/` for accurate `formal_role_covered` values. On a fresh clone with no scan results, all rules will show as uncovered. This is relevant to maintaining the codebase for new STIG releases.
- Supplement facts are keyed by STIG ID (`RHEL-09-XXXXXX`). XCCDF results are keyed by rule ID (`SV-XXXXXX`) internally; the renderer handles the mapping.
- Report files in `reports/` are gitignored.
