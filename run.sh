#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export XML_PATH="$HOME/oss/rhel-stig-full/reports"

# ── defaults ──────────────────────────────────────────────────────────────────
TAG=""
HOST="stigging-sandbox"
SKIP_FORMAL=false
SKIP_SUPPLEMENT=false
SKIP_CKLB=false
VERBOSITY="-v"
PASSTHROUGH=()

# ── helpers ───────────────────────────────────────────────────────────────────
die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo; echo "==> $*"; }

usage() {
  cat <<'EOF'
Usage: run.sh <validate|remediate> [OPTIONS] [-- ANSIBLE_ARGS]

Modes (required):
  validate    Dry-run: formal role runs in check mode, supplement collects
              facts, CKLB checklist is generated. No changes applied.
  remediate   Apply: formal role enforces STIG settings, supplement collects
              facts, CKLB checklist is generated.

Options:
  -H HOST, --host HOST    Ansible inventory host or group
                          (default: stigging-sandbox)
  --skip-formal           Skip the rhel9STIG formal role play
  --skip-supplement       Skip the supplement checks play
  --skip-cklb             Skip the CKLB renderer play
  -v, -vv, -vvv, -vvvv   Ansible verbosity level (default: -v)
  -h, --help              Show this message

Arguments after -- are forwarded verbatim to every ansible-playbook call.

Examples:
  ./run.sh validate
  ./run.sh remediate --host myserver
  ./run.sh validate --skip-formal -vvv
  ./run.sh validate -- -e "my_extra_var=foo"
  ./run.sh validate --host stigging-sandbox2 --skip-cklb
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

# ── become password ───────────────────────────────────────────────────────────
# Prompt once if any play that needs become will run. The password is supplied
# via ANSIBLE_BECOME_PASSWORD so Ansible doesn't re-prompt on each play.
# The cklb play runs with become: false — ANSIBLE_BECOME_ASK_PASS=false
# suppresses the prompt there even though become_ask_pass=true in ansible.cfg.
if [[ "$SKIP_FORMAL" == false || "$SKIP_SUPPLEMENT" == false ]]; then
  read -rsp "BECOME password for $HOST: " _bp; echo
  export ANSIBLE_BECOME_PASSWORD="$_bp"
  unset _bp
fi
trap 'unset ANSIBLE_BECOME_PASSWORD 2>/dev/null || true' EXIT

# ── build common args array ───────────────────────────────────────────────────
COMMON=("$VERBOSITY" -e "my_host=$HOST")
[[ ${#PASSTHROUGH[@]} -gt 0 ]] && COMMON+=("${PASSTHROUGH[@]}")

# ── run plays ─────────────────────────────────────────────────────────────────
if [[ "$SKIP_FORMAL" == false ]]; then
  info "Formal role ($TAG) → $HOST"
  ansible-playbook ./formal-role.yml --tags "$TAG" "${COMMON[@]}"
fi

if [[ "$SKIP_SUPPLEMENT" == false ]]; then
  info "Supplement checks → $HOST"
  ansible-playbook ./supplement.yml --tags validate "${COMMON[@]}"
fi

if [[ "$SKIP_CKLB" == false ]]; then
  info "CKLB renderer → $HOST"
  ANSIBLE_BECOME_ASK_PASS=false ansible-playbook ./cklb.yml --tags validate "${COMMON[@]}"
fi

info "Done."
