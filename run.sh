#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export XML_PATH="$HOME/oss/rhel-stig-full/reports"

# ── defaults ──────────────────────────────────────────────────────────────────
TAG=""
HOST="default_host_group"
SKIP_FORMAL=false
SKIP_SUPPLEMENT=false
SKIP_CKLB=false
MAX_RESULT_AGE=
VERBOSITY="-v"
VAULT_MODE=""        # "file" or "prompt"
VAULT_FILE=""        # path supplied with --vault-pass-file
VAULT_TMPFILE=""     # temp file created when using --vault
BECOME_TMPFILE=""    # temp file for become password
PASSTHROUGH=()

# ── helpers ───────────────────────────────────────────────────────────────────
die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo; echo "==> $*"; }
warn() { echo "WARNING: $*" >&2; }

usage() {
  cat <<'EOF'
Usage: run.sh <validate|remediate> [OPTIONS] [-- ANSIBLE_ARGS]

Modes (required):
  validate    Assess: every rule is checked (read-only) by the rhel9_stig_full
              role and the CKLB checklist is generated.
  remediate   Apply: the DISA formal role (roles/rhel9STIG) enforces STIG
              settings. Nothing is assessed; run validate afterwards to
              produce a checklist.

Target:
  -H HOST_OR_GROUP, --host HOST_OR_GROUP
              Ansible inventory host name or group name to target
              (default: default_host_group)

Auth (mutually exclusive — choose one):
  (default)                 Prompt for become (sudo) password once
  --vault-pass-file FILE    Use FILE as the ansible-vault password file;
                            become credentials are read from the vault
  --vault                   Prompt for vault password (stored in a temp
                            file for the duration of the run); become
                            credentials are read from the vault

Skip plays:
  --skip-supplement         validate: skip the checks (re-render from earlier
                            results only)
  --skip-cklb               validate: assess without rendering a checklist
  --skip-formal             remediate: do nothing (kept for compatibility)

Checklist:
  --max-result-age DAYS     Merge only result files from the last DAYS days
                            into the checklist (default 30; 0 = no limit).
                            Older results are left out rather than reported.

Other:
  -v, -vv, -vvv, -vvvv     Ansible verbosity level (default: -v)
  -h, --help                Show this message

Exit status:
  0  every stage completed on every host
  1  a stage failed outright (bad arguments, parse or vault error, or no host
     completed); later stages were not run
  2  some hosts failed or were unreachable; the others were processed and a
     WARNING lists the hosts that were not

Arguments after -- are forwarded verbatim to every ansible-playbook call.

Examples:
  ./run.sh validate
  ./run.sh validate --host stigging-sandbox2
  ./run.sh remediate --host prod-servers --vault-pass-file ~/.vault_pass
  ./run.sh validate --skip-supplement     # re-render from earlier results
  ./run.sh validate --vault -- -e "extra_var=foo"
EOF
  exit 0
}

# ── argument parsing ──────────────────────────────────────────────────────────
[[ $# -eq 0 ]] && usage

while [[ $# -gt 0 ]]; do
  case "$1" in
    validate|remediate)
      TAG="$1"; shift ;;
    -H|--host)
      [[ $# -lt 2 ]] && die "--host requires an argument"
      HOST="$2"; shift 2 ;;
    --host=*)
      HOST="${1#*=}"; shift ;;
    --skip-formal)
      SKIP_FORMAL=true; shift ;;
    --skip-supplement)
      SKIP_SUPPLEMENT=true; shift ;;
    --skip-cklb)
      SKIP_CKLB=true; shift ;;
    --max-result-age)
      [[ $# -lt 2 ]] && die "--max-result-age requires a number of days"
      [[ "$2" =~ ^[0-9]+$ ]] || die "--max-result-age takes a whole number of days, got: $2"
      MAX_RESULT_AGE="$2"; shift 2 ;;
    --vault-pass-file)
      [[ $# -lt 2 ]] && die "--vault-pass-file requires a path argument"
      [[ -f "$2" ]] || die "Vault password file not found: $2"
      VAULT_MODE="file"; VAULT_FILE="$2"; shift 2 ;;
    --vault-pass-file=*)
      VAULT_FILE="${1#*=}"
      [[ -f "$VAULT_FILE" ]] || die "Vault password file not found: $VAULT_FILE"
      VAULT_MODE="file"; shift ;;
    --vault)
      VAULT_MODE="prompt"; shift ;;
    -v|-vv|-vvv|-vvvv)
      VERBOSITY="$1"; shift ;;
    -h|--help)
      usage ;;
    --)
      shift; PASSTHROUGH=("$@"); break ;;
    *)
      die "Unknown argument: '$1'  (use -- to pass args directly to ansible-playbook)" ;;
  esac
done

[[ -z "$TAG" ]] && die "Mode is required: validate or remediate"
[[ -n "$VAULT_MODE" && -n "${ANSIBLE_BECOME_PASSWORD:-}" ]] && \
  die "Cannot combine --vault/--vault-pass-file with ANSIBLE_BECOME_PASSWORD env var"

# ── credential setup ──────────────────────────────────────────────────────────
_cleanup() {
  [[ -n "$BECOME_TMPFILE" ]] && rm -f "$BECOME_TMPFILE"
  [[ -n "$VAULT_TMPFILE" ]]  && rm -f "$VAULT_TMPFILE"
  # Both tests are false when --vault-pass-file supplied the credentials, which
  # would make this function return 1. Under an EXIT trap that becomes the
  # scripts exit code, so a fully successful run would report failure.
  return 0
}
trap _cleanup EXIT

if [[ "$VAULT_MODE" == "prompt" ]]; then
  read -rsp "Vault password: " _vp; echo
  VAULT_TMPFILE=$(mktemp)
  chmod 600 "$VAULT_TMPFILE"
  printf '%s' "$_vp" > "$VAULT_TMPFILE"
  unset _vp
  VAULT_FILE="$VAULT_TMPFILE"
elif [[ -z "$VAULT_MODE" ]]; then
  # no vault — prompt for become password and write to a temp file
  # only the stage that touches hosts needs privilege
  if [[ ( "$TAG" == "remediate" && "$SKIP_FORMAL" == false ) ||
        ( "$TAG" == "validate" && "$SKIP_SUPPLEMENT" == false ) ]]; then
    read -rsp "BECOME password for $HOST: " _bp; echo
    BECOME_TMPFILE=$(mktemp)
    chmod 600 "$BECOME_TMPFILE"
    printf '%s' "$_bp" > "$BECOME_TMPFILE"
    unset _bp
  fi
fi

# ── build common args ─────────────────────────────────────────────────────────
COMMON=("$VERBOSITY" -e "my_host=$HOST")
[[ -n "$BECOME_TMPFILE" ]] && COMMON+=(--become-password-file "$BECOME_TMPFILE")
[[ -n "$VAULT_MODE" ]]     && COMMON+=(--vault-password-file "$VAULT_FILE")
[[ ${#PASSTHROUGH[@]} -gt 0 ]] && COMMON+=("${PASSTHROUGH[@]}")

# ── run plays ─────────────────────────────────────────────────────────────────
# One unreachable or failed host must not stop the other hosts from being
# assessed. ansible-playbook exits 2 (failed hosts) or 4 (unreachable hosts),
# but 4 is also what a parse or vault error returns, before anything has run.
# So a stage continues only if it printed a PLAY RECAP and at least one host
# came through clean; otherwise it is fatal, as before. Hosts that did not come
# through are listed at the end, and the script then exits non-zero.
SKIPPED_HOSTS=()
run_play() {
  local stage="$1"; shift
  local log rc
  log=$(mktemp)
  set +e
  ansible-playbook "$@" 2>&1 | tee "$log"
  rc=${PIPESTATUS[0]}
  set -e
  if [[ $rc -ne 0 ]]; then
    local clean bad
    clean=$(awk '/^PLAY RECAP/ {r=1; next} r && / : ok=/ && /unreachable=0 / && /failed=0 / {print $1}' "$log")
    bad=$(awk '/^PLAY RECAP/ {r=1; next} r && / : ok=/ && !(/unreachable=0 / && /failed=0 /) {print $1}' "$log")
    rm -f "$log"
    if [[ ($rc -eq 2 || $rc -eq 4) && -n "$clean" ]]; then
      warn "$stage: failed or unreachable on: $(echo $bad); continuing with: $(echo $clean)"
      SKIPPED_HOSTS+=($bad)
      return 0
    fi
    die "$stage failed (ansible-playbook exit $rc) with no host completing cleanly"
  fi
  rm -f "$log"
}

# One playbook, selected by tag: remediate runs the DISA role only (never a
# checklist); validate assesses every rule, then renders the checklist.
PLAY_ARGS=()
if [[ "$TAG" == "remediate" ]]; then
  if [[ "$SKIP_FORMAL" == true ]]; then
    info "Nothing to do: remediate with --skip-formal"
    exit 0
  fi
  PLAY_ARGS=(--tags remediate)
  info "Remediate (DISA role) → $HOST"
else
  if [[ "$SKIP_SUPPLEMENT" == true && "$SKIP_CKLB" == true ]]; then
    info "Nothing to do: validate with --skip-supplement and --skip-cklb"
    exit 0
  elif [[ "$SKIP_SUPPLEMENT" == true ]]; then
    PLAY_ARGS=(--tags render)                       # re-render from earlier results
    info "Render checklist from earlier results → $HOST"
  else
    PLAY_ARGS=(--tags validate)
    [[ "$SKIP_CKLB" == true ]] && PLAY_ARGS+=(--skip-tags render)
    info "Assess every rule$([[ "$SKIP_CKLB" == true ]] || echo ' and render the checklist') → $HOST"
  fi
  [[ -n "$MAX_RESULT_AGE" ]] && PLAY_ARGS+=(-e "cklb_max_result_age_days=$MAX_RESULT_AGE")
fi
run_play "$TAG" ./stig.yml "${PLAY_ARGS[@]}" "${COMMON[@]}"

if [[ ${#SKIPPED_HOSTS[@]} -gt 0 ]]; then
  warn "not fully processed: $(printf '%s\n' "${SKIPPED_HOSTS[@]}" | sort -u | tr '\n' ' ')"
  warn "their checklists (if rendered) carry results from earlier runs, dated in the comments"
  exit 2
fi

info "Done."
