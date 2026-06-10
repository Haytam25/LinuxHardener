#!/usr/bin/env bash

# ==============================================================================
# Linux Security Hardening & Audit Script
# Target OS: Ubuntu / Debian / RHEL Core Ecosystems
# Features: Non-disruptive compliance checks for SSH, Firewalls, and Permissions
# ==============================================================================

# ANSI color codes for clean terminal reporting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}"
echo "  _      _                    _    _               _     "
echo " | |    (_)                  | |  | |             | |    "
echo " | |     _ _ __  _   ___  __ | |__| | __ _ _ __ __| | ___"
echo " | |    | | '_ \| | | \ \/ / |  __  |/ _' | '__/ _' |/ _ \\"
echo " | |____| | | | | |_| |>  <  | |  | | (_| | | | (_| |  __/"
echo " |______|_|_| |_|\__,_/_/\_\ |_|  |_|\__,_|_|  \__,_|\___|"
echo " ======================= Security Audit Engine ======================="
echo -e "${NC}\n"

# Ensure the script is running with root privileges (required to read secure config files)
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Error: This audit tool requires root privileges. Please run with sudo.${NC}"
    exit 1
fi

echo -e "[*] Audit initiated at: $(date)"
echo -e "------------------------------------------------------------"

# ------------------------------------------------------------------------------
# PHASE 1: SSH Daemon Hardening Audit
# ------------------------------------------------------------------------------
echo -e "${YELLOW}[*] Phase 1: Auditing SSH Configurations...${NC}"
SSH_CONFIG="/etc/ssh/sshd_config"

if [ -f "$SSH_CONFIG" ]; then
    # 1. Check for Root Login Permitted over SSH
    ROOT_LOGIN=$(grep -Ei '^PermitRootLogin' "$SSH_CONFIG" | awk '{print $2}')
    if [ "$ROOT_LOGIN" == "no" ]; then
        echo -e "  [${GREEN}PASSED${NC}] PermitRootLogin is safely set to 'no'."
    else
        echo -e "  [${RED}FAILED${NC}] Remote root login is enabled or unconfigured. (Risk: Brute-Force Target)"
    fi

    # 2. Check for Password Authentication Policy
    PWD_AUTH=$(grep -Ei '^PasswordAuthentication' "$SSH_CONFIG" | awk '{print $2}')
    if [ "$PWD_AUTH" == "no" ]; then
        echo -e "  [${GREEN}PASSED${NC}] PasswordAuthentication is disabled (Enforcing SSH Keys)."
    else
        echo -e "  [${YELLOW}WARNING${NC}] PasswordAuthentication is enabled. Consider enforcing SSH public keys."
    fi
else
    echo -e "  [${YELLOW}!${NC}] SSH daemon configuration file not found. Skipping phase."
fi

# ------------------------------------------------------------------------------
# PHASE 2: Network Perimeter Control (Firewall Check)
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[*] Phase 2: Auditing Network Firewall State...${NC}"

# Check for UFW (Ubuntu/Debian standard)
if command -v ufw &> /dev/null; then
    UFW_STATUS=$(ufw status | grep -i "Status" | awk '{print $2}')
    if [ "$UFW_STATUS" == "active" ]; then
        echo -e "  [${GREEN}PASSED${NC}] Uncomplicated Firewall (UFW) is active and running."
    else
        echo -e "  [${RED}FAILED${NC}] UFW is installed but INACTIVE."
    fi
# Check for firewalld (RHEL/CentOS standard)
elif command -v firewall-cmd &> /dev/null; then
    FW_CMD_STATUS=$(firewall-cmd --state 2>&1)
    if [ "$FW_CMD_STATUS" == "running" ]; then
        echo -e "  [${GREEN}PASSED${NC}] Firewalld is active and running."
    else
        echo -e "  [${RED}FAILED${NC}] Firewalld is installed but INACTIVE."
    fi
else
    echo -e "  [${RED}FAILED${NC}] No standard firewall management tool (ufw/firewalld) detected active."
fi

# ------------------------------------------------------------------------------
# PHASE 3: File System Integrity & Critical Permissions
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}[*] Phase 3: Auditing Critical System File Permissions...${NC}"

check_perms() {
    local file=$1
    local expected=$2
    if [ -f "$file" ]; then
        # Grab octal permission representation
        local current=$(stat -c "%a" "$file")
        if [ "$current" -eq "$expected" ]; then
            echo -e "  [${GREEN}PASSED${NC}] $file permissions are secure ($current)."
        else
            echo -e "  [${RED}FAILED${NC}] $file permissions are $current! Expected $expected. (Risk: Credential Leaks)"
        fi
    else
        echo -e "  [${YELLOW}!${NC}] $file does not exist on this machine."
    fi
}

# /etc/shadow contains user password hashes, must be highly restricted (typically 600 or 000)
check_perms "/etc/shadow" "600"
# /etc/passwd contains basic account structures, should be readable but non-writable (644)
check_perms "/etc/passwd" "644"

echo -e "------------------------------------------------------------"
echo -e "[✓] Security Audit Complete."