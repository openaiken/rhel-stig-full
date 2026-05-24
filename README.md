# rhel-stig-full
Modification and Extension of the formal RHEL 9 STIG Ansible code, to fully implement every control and produce a ready-to-report Checklist for STIG Viewer 3.x.

## WIP
This project is a Work-In-Progress.

## Project Structure
*This section written by Claude Code.*

### Playbooks
- **`formal-role.yml`** — runs the unmodified DISA Ansible role (`rhel9STIG`). A custom callback plugin records results as a per-host XCCDF results file in `reports/`.
- **`supplement.yml`** — runs `rhel9_stig_supplement`, a custom role containing checks for rules not covered by the formal role. Results are written to `reports/supp-facts/` as JSON.
- **`cklb.yml`** — runs `cklb_renderer`, which merges the XCCDF results and supplement facts into a populated CKLB checklist for STIG Viewer 3.x. Output goes to `reports/`.
- **`run.sh`** — runs all three playbooks in order.

### Roles
- **`roles/rhel9STIG/`** — unmodified DISA formal role. Do not edit.
- **`roles/rhel9_stig_supplement/`** — custom checks for the 187 rules the formal role does not cover. One task file per STIG ID (e.g. `tasks/RHEL-09-211010.yml`).
- **`roles/cklb_renderer/`** — reads `reports/` and `reports/supp-facts/` for the target host and renders a CKLB file. Can be run independently against existing results without re-running remediation.

### Supporting Files
- **`files/rules.json`** — all 446 RHEL 9 STIG V2R8 rules extracted from the XCCDF benchmark, keyed by STIG ID. Includes `formal_role_covered` flag derived from the latest XCCDF results file in `reports/`. Regenerate with `python3 scripts/parse_xccdf_benchmark.py` after a new scan or a new benchmark version.
- **`callbacks/stig_xml.py`** — Ansible callback plugin that writes per-host XCCDF results to `reports/`.
- **`files/empty-checklist-rhel9v2r8.cklb`** — CKLB template used by the renderer.

### Notes
- `files/rules.json` requires a recent XCCDF results file in `reports/` for accurate `formal_role_covered` values. On a fresh clone with no scan results, all rules will show as uncovered.
- Supplement facts are keyed by STIG ID (`RHEL-09-XXXXXX`). XCCDF results are keyed by rule ID (`SV-XXXXXX`) internally; the renderer handles the mapping.
- Report files in `reports/` are gitignored.
