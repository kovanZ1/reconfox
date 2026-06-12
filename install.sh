#!/usr/bin/env bash
# reconfox installer for Linux (Kali / Debian / Ubuntu).
# Creates a virtualenv, installs the package and symlinks `reconfox` into PATH.
#
# Usage:
#   ./install.sh                      # default: ~/.local/share/reconfox, link to /usr/local/bin
#   ./install.sh --prefix /opt        # custom install prefix
#   ./install.sh --no-link            # do not symlink, just install in venv
#   ./install.sh --uninstall          # remove symlink + venv

set -euo pipefail

# --- colors --------------------------------------------------------------
if [[ -t 1 ]]; then
    GREEN=$'\033[1;32m'
    AMBER=$'\033[1;33m'
    RED=$'\033[1;31m'
    CYAN=$'\033[1;36m'
    GREY=$'\033[0;90m'
    BOLD=$'\033[1m'
    RESET=$'\033[0m'
else
    GREEN=""; AMBER=""; RED=""; CYAN=""; GREY=""; BOLD=""; RESET=""
fi

log()  { printf "${GREEN}[+]${RESET} %s\n" "$*"; }
info() { printf "${CYAN}[*]${RESET} %s\n" "$*"; }
warn() { printf "${AMBER}[!]${RESET} %s\n" "$*"; }
err()  { printf "${RED}[-]${RESET} %s\n" "$*" >&2; }

banner() {
    printf "${GREEN}"
    cat <<'EOF'

   ┳┓┏┓┏┓┏┓┳┓┏┓┏┓┓┏
   ┣┫┣ ┃ ┃┃┃┃┣ ┃┃┏┛
   ┛┗┗┛┗┛┗┛┛┗┻ ┗┛┛┗
              installer

EOF
    printf "${RESET}"
}

# --- defaults ------------------------------------------------------------
PREFIX="${HOME}/.local/share/reconfox"
LINK_DIR="/usr/local/bin"
DO_LINK=1
UNINSTALL=0

# --- args ----------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)    PREFIX="$2"; shift 2 ;;
        --link-dir)  LINK_DIR="$2"; shift 2 ;;
        --no-link)   DO_LINK=0; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        -h|--help)
            cat <<EOF
Usage: $0 [OPTIONS]

  --prefix DIR     Install venv here (default: ~/.local/share/reconfox)
  --link-dir DIR   Symlink `reconfox` here   (default: /usr/local/bin)
  --no-link        Do not symlink, leave the binary in the venv
  --uninstall      Remove the symlink and the install prefix
  -h, --help       Show this help

EOF
            exit 0
            ;;
        *) err "Unknown argument: $1"; exit 1 ;;
    esac
done

banner

# --- uninstall path ------------------------------------------------------
if [[ $UNINSTALL -eq 1 ]]; then
    info "Uninstalling reconfox..."
    if [[ -L "${LINK_DIR}/reconfox" ]]; then
        if [[ -w "${LINK_DIR}" ]]; then
            rm -f "${LINK_DIR}/reconfox"
        else
            sudo rm -f "${LINK_DIR}/reconfox"
        fi
        log "Removed symlink ${LINK_DIR}/reconfox"
    fi
    if [[ -d "${PREFIX}" ]]; then
        rm -rf "${PREFIX}"
        log "Removed ${PREFIX}"
    fi
    log "Uninstalled."
    exit 0
fi

# --- preflight checks ----------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "${SCRIPT_DIR}/pyproject.toml" ]]; then
    err "pyproject.toml not found in ${SCRIPT_DIR}. Run install.sh from the repo root."
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    err "python3 is required but not found. Install with: sudo apt install python3 python3-venv"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYTHON_MAJOR=$(python3 -c 'import sys; print(sys.version_info.major)')
PYTHON_MINOR=$(python3 -c 'import sys; print(sys.version_info.minor)')

if (( PYTHON_MAJOR < 3 || (PYTHON_MAJOR == 3 && PYTHON_MINOR < 11) )); then
    err "Python 3.11+ required (you have ${PYTHON_VERSION})."
    exit 1
fi
info "Python ${PYTHON_VERSION} detected."

# --- optional tools check ------------------------------------------------
missing_tools=()
for tool in nmap ffuf; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        missing_tools+=("$tool")
    fi
done

if [[ ${#missing_tools[@]} -gt 0 ]]; then
    warn "Missing optional tools: ${missing_tools[*]}"
    warn "Install with: sudo apt install nmap ffuf"
else
    log "Required tools found: nmap, ffuf"
fi

if ! command -v searchsploit >/dev/null 2>&1; then
    warn "searchsploit not found — exploit search disabled."
    warn "Install with: sudo apt install exploitdb"
fi

# --- install -------------------------------------------------------------
info "Install prefix: ${PREFIX}"
mkdir -p "$(dirname "${PREFIX}")"

if [[ -d "${PREFIX}/.venv" ]]; then
    warn "Existing venv at ${PREFIX}/.venv — recreating."
    rm -rf "${PREFIX}/.venv"
fi

info "Creating virtualenv..."
python3 -m venv "${PREFIX}/.venv"

info "Upgrading pip..."
"${PREFIX}/.venv/bin/pip" install --quiet --upgrade pip

info "Installing reconfox from ${SCRIPT_DIR}..."
"${PREFIX}/.venv/bin/pip" install --quiet "${SCRIPT_DIR}"

# Verify
if ! "${PREFIX}/.venv/bin/reconfox" --version >/dev/null 2>&1; then
    err "Installation failed: reconfox binary not working after install."
    exit 1
fi
log "Package installed in ${PREFIX}/.venv"

# --- symlink -------------------------------------------------------------
if [[ $DO_LINK -eq 1 ]]; then
    BIN_PATH="${LINK_DIR}/reconfox"
    SRC="${PREFIX}/.venv/bin/reconfox"

    if [[ -w "${LINK_DIR}" ]]; then
        ln -sf "${SRC}" "${BIN_PATH}"
    else
        info "${LINK_DIR} requires sudo for symlink..."
        sudo ln -sf "${SRC}" "${BIN_PATH}"
    fi
    log "Symlinked: ${BIN_PATH} → ${SRC}"
fi

# --- done ----------------------------------------------------------------
printf "\n${GREEN}${BOLD}Installation complete.${RESET}\n\n"
printf "Try:\n"
printf "  ${CYAN}reconfox --help${RESET}\n"
printf "  ${CYAN}reconfox scan https://example.com -o ./reports --no-tui${RESET}\n"
printf "  ${CYAN}reconfox${RESET}  ${GREY}# TUI mode${RESET}\n\n"
printf "Uninstall: ${GREY}./install.sh --uninstall${RESET}\n\n"
