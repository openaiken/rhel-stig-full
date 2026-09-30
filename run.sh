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
  validate    Dry-run: formal role runs in check mode, supplement runs
              validation checks, CKLB checklist is generated.
  remediate   Apply: formal role enforces STIG settings, supplement runs
              remediation then validation. CKLB is NOT generated
              (use validate after to produce a deliverable).

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
  --skip-formal             Skip the rhel9STIG formal role play
  --skip-supplement         Skip the supplement checks/remediation play
  --skip-cklb               Skip the CKLB renderer (validate mode only)

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
  ./run.sh validate --skip-formal -vvv
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
  if [[ "$SKIP_FORMAL" == false || "$SKIP_SUPPLEMENT" == false ]]; then
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

if [[ "$SKIP_FORMAL" == false ]]; then
  info "Formal role ($TAG) → $HOST"
  run_play "Formal role" ./formal-role.yml --tags "$TAG" "${COMMON[@]}"
fi

if [[ "$SKIP_SUPPLEMENT" == false ]]; then
  info "Supplement ($TAG) → $HOST"
  run_play "Supplement" ./supplement.yml --tags "$TAG" "${COMMON[@]}"
fi

if [[ "$SKIP_CKLB" == false && "$TAG" == "validate" ]]; then
  info "CKLB renderer → $HOST"
  run_play "CKLB renderer" ./cklb.yml --tags validate "${COMMON[@]}"
fi

if [[ ${#SKIPPED_HOSTS[@]} -gt 0 ]]; then
  warn "not fully processed: $(printf '%s\n' "${SKIPPED_HOSTS[@]}" | sort -u | tr '\n' ' ')"
  warn "their checklists (if rendered) carry results from earlier runs, dated in the comments"
  exit 2
fi

info "Done."
