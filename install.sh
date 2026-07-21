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
    for m in "/usr/local/share/man/man1/reconfox.1" "${HOME}/.local/share/man/man1/reconfox.1"; do
        if [[ -f "$m" ]]; then
            rm -f "$m" 2>/dev/null || sudo rm -f "$m" 2>/dev/null || true
            log "Removed man page $m"
        fi
    done
    rm -f "${HOME}/.bash_completion.d/reconfox" 2>/dev/null || true
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

for opt in "searchsploit:exploitdb:exploit search" "nuclei:nuclei:template vuln scan"; do
    bin="${opt%%:*}"; rest="${opt#*:}"; pkg="${rest%%:*}"; what="${rest#*:}"
    if ! command -v "$bin" >/dev/null 2>&1; then
        warn "${bin} not found — ${what} disabled. Install: sudo apt install ${pkg}"
    fi
done

DEFAULT_WORDLIST="/usr/share/wordlists/dirb/common.txt"
if [[ ! -f "${DEFAULT_WORDLIST}" ]]; then
    warn "Default wordlist ${DEFAULT_WORDLIST} not found (ffuf needs one)."
    warn "Install with: sudo apt install seclists  (or dirb)"
fi

# --- install -------------------------------------------------------------
info "Install prefix: ${PREFIX}"
mkdir -p "$(dirname "${PREFIX}")"

if [[ -d "${PREFIX}/.venv" ]] && "${PREFIX}/.venv/bin/python" -c "" >/dev/null 2>&1; then
    info "Reusing existing venv at ${PREFIX}/.venv (upgrading in place)."
else
    if [[ -d "${PREFIX}/.venv" ]]; then
        warn "Existing venv is broken — recreating."
        rm -rf "${PREFIX}/.venv"
    fi
    info "Creating virtualenv..."
    python3 -m venv "${PREFIX}/.venv"
fi

info "Upgrading pip..."
"${PREFIX}/.venv/bin/pip" install --quiet --upgrade pip

info "Installing reconfox from ${SCRIPT_DIR}..."
"${PREFIX}/.venv/bin/pip" install --quiet --upgrade "${SCRIPT_DIR}"

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

# --- man page ------------------------------------------------------------
MAN_SRC="${SCRIPT_DIR}/man/reconfox.1"
if [[ -f "${MAN_SRC}" ]]; then
    if [[ $DO_LINK -eq 1 && "${LINK_DIR}" == "/usr/local/bin" ]]; then
        MAN_DIR="/usr/local/share/man/man1"
    else
        MAN_DIR="${HOME}/.local/share/man/man1"
    fi
    if { mkdir -p "${MAN_DIR}" && cp "${MAN_SRC}" "${MAN_DIR}/reconfox.1"; } 2>/dev/null; then
        log "Man page: ${MAN_DIR}/reconfox.1  (man reconfox)"
    elif command -v sudo >/dev/null 2>&1 \
         && sudo mkdir -p "${MAN_DIR}" 2>/dev/null \
         && sudo cp "${MAN_SRC}" "${MAN_DIR}/reconfox.1" 2>/dev/null; then
        log "Man page: ${MAN_DIR}/reconfox.1  (man reconfox)"
    else
        warn "Could not install man page to ${MAN_DIR} (skipped)."
    fi
fi

# --- shell completion ----------------------------------------------------
RECONFOX_BIN="${PREFIX}/.venv/bin/reconfox"
COMP_DIR="${PREFIX}/completions"
mkdir -p "${COMP_DIR}"
if _RECONFOX_COMPLETE=bash_source "${RECONFOX_BIN}" > "${COMP_DIR}/reconfox.bash" 2>/dev/null \
   && [[ -s "${COMP_DIR}/reconfox.bash" ]]; then
    if mkdir -p "${HOME}/.bash_completion.d" 2>/dev/null; then
        cp "${COMP_DIR}/reconfox.bash" "${HOME}/.bash_completion.d/reconfox" 2>/dev/null || true
    fi
    log "bash completion generated: source ${COMP_DIR}/reconfox.bash"
fi
if _RECONFOX_COMPLETE=zsh_source "${RECONFOX_BIN}" > "${COMP_DIR}/reconfox.zsh" 2>/dev/null \
   && [[ -s "${COMP_DIR}/reconfox.zsh" ]]; then
    log "zsh completion generated:  source ${COMP_DIR}/reconfox.zsh"
fi

# --- done ----------------------------------------------------------------
printf "\n${GREEN}${BOLD}Installation complete.${RESET}\n\n"
printf "Try:\n"
printf "  ${CYAN}reconfox doctor${RESET}  ${GREY}# check nmap/ffuf/searchsploit/nuclei + wordlist${RESET}\n"
printf "  ${CYAN}reconfox --help${RESET}\n"
printf "  ${CYAN}reconfox scan https://example.com -o ./reports --no-tui${RESET}\n"
printf "  ${CYAN}reconfox${RESET}  ${GREY}# TUI mode${RESET}\n\n"
printf "Uninstall: ${GREY}./install.sh --uninstall${RESET}\n\n"
