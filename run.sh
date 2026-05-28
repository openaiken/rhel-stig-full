#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export XML_PATH="$HOME/oss/rhel-stig-full/reports"

# ── defaults ──────────────────────────────────────────────────────────────────
TAG=""
HOST="default-host-group"
SKIP_FORMAL=false
SKIP_SUPPLEMENT=false
SKIP_CKLB=false
VERBOSITY="-v"
VAULT_MODE=""      # "file" or "prompt"
VAULT_FILE=""      # path supplied with --vault-file
VAULT_TMPFILE=""   # temp file created when using --vault
PASSTHROUGH=()

# ── helpers ───────────────────────────────────────────────────────────────────
die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo; echo "==> $*"; }

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
              (default: default-host-group)

Auth (mutually exclusive — choose one):
  (default)                 Prompt for become (sudo) password once
  --vault-file FILE         Use FILE as the ansible-vault password file;
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

Arguments after -- are forwarded verbatim to every ansible-playbook call.

Examples:
  ./run.sh validate
  ./run.sh validate --host stigging-sandbox2
  ./run.sh remediate --host prod-servers --vault-file ~/.vault_pass
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
    --vault-file)
      [[ $# -lt 2 ]] && die "--vault-file requires a path argument"
      [[ -f "$2" ]] || die "Vault password file not found: $2"
      VAULT_MODE="file"; VAULT_FILE="$2"; shift 2 ;;
    --vault-file=*)
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
[[ -n "$VAULT_MODE" && -n "$ANSIBLE_BECOME_PASSWORD" ]] && \
  die "Cannot combine --vault/--vault-file with ANSIBLE_BECOME_PASSWORD env var"

# ── credential setup ──────────────────────────────────────────────────────────
_cleanup() {
  unset ANSIBLE_BECOME_PASSWORD 2>/dev/null || true
  [[ -n "$VAULT_TMPFILE" ]] && rm -f "$VAULT_TMPFILE"
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
  # no vault — prompt for become password directly
  if [[ "$SKIP_FORMAL" == false || "$SKIP_SUPPLEMENT" == false ]]; then
    read -rsp "BECOME password for $HOST: " _bp; echo
    export ANSIBLE_BECOME_PASSWORD="$_bp"
    unset _bp
  fi
fi

# ── build common args ─────────────────────────────────────────────────────────
COMMON=("$VERBOSITY" -e "my_host=$HOST")
[[ -n "$VAULT_MODE" ]] && COMMON+=(--vault-password-file "$VAULT_FILE")
[[ ${#PASSTHROUGH[@]} -gt 0 ]] && COMMON+=("${PASSTHROUGH[@]}")

# ── run plays ─────────────────────────────────────────────────────────────────
if [[ "$SKIP_FORMAL" == false ]]; then
  info "Formal role ($TAG) → $HOST"
  ansible-playbook ./formal-role.yml --tags "$TAG" "${COMMON[@]}"
fi

if [[ "$SKIP_SUPPLEMENT" == false ]]; then
  info "Supplement ($TAG) → $HOST"
  ansible-playbook ./supplement.yml --tags "$TAG" "${COMMON[@]}"
fi

if [[ "$SKIP_CKLB" == false && "$TAG" == "validate" ]]; then
  info "CKLB renderer → $HOST"
  ANSIBLE_BECOME_ASK_PASS=false ansible-playbook ./cklb.yml --tags validate "${COMMON[@]}"
fi

info "Done."
