#!/usr/bin/env bash

# --- UI / UX ---

if [[ -t 1 ]]; then
    BOLD='\033[1m'; RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
    YELLOW='\033[1;33m'; MAGENTA='\033[0;35m'; BLUE='\033[0;34m'; WHITE='\033[1;37m'; NC='\033[0m'
else
    BOLD=""; RED=""; GREEN=""; CYAN=""; YELLOW=""; MAGENTA=""; BLUE=""; WHITE=""; NC=""
fi

header() {
    if [[ ! -t 1 ]]; then return; fi
    clear
    get_interface
    echo -e "${CYAN}${BOLD}"
    echo "   ██╗ ██████╗ ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗"
    echo "   ██║██╔═══██╗████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║"
    echo "   ██║██║   ██║██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║"
    echo "   ██║██║   ██║██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║"
    echo "   ██║╚██████╔╝██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║"
    echo "   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝"
    echo -e "${NC}"
    echo -e "${BLUE}${BOLD}   Network Intelligence Suite v22.0 (Git Edition)${NC}"
    echo -e "${CYAN}   ========================================================${NC}"
    echo -e "   ${WHITE}Interface:${NC} $DEFAULT_IFACE  |  ${WHITE}IP:${NC} $MY_IP"
    echo -e "${CYAN}   ========================================================${NC}"
    echo ""
}
pause() { echo ""; read -p "Press [Enter] to return..." ; }
