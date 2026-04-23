#!/bin/bash

# ==========================================
# Terminal Colors
# ==========================================
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# ==========================================
# Variables & Arguments
# ==========================================
VERBOSE=0
DOMAIN=""
DOMAIN_LIST=""
BYPASS_ARGS=()

function usage() {
    echo -e "${CYAN}Usage:${NC} ./find_crit.sh [OPTIONS] [BYPASS_OPTIONS]"
    echo -e "  -d, --domain DOMAIN    Target a single domain (runs Subfinder first)."
    echo -e "  -l, --list FILE        Target a list of known domains (skips Subfinder)."
    echo -e "  -v, --verbose          Show all output, including 403/401 failures."
    echo -e "  -h, --help             Show this help menu."
    echo -e "\n${CYAN}Bypass Options (passed directly to 403-bypass.sh):${NC}"
    echo -e "  --header, --encode, --protocol, -H \"Header: val\", -c \"cookie=val\", etc."
    echo -e "  (Defaults to --exploit if no specific mode is provided)"
    echo -e "\n${CYAN}Examples:${NC}"
    echo -e "  ./find_crit.sh -d target.com"
    echo -e "  ./find_crit.sh -l internal.txt -v --header -H \"Authorization: Bearer xyz\""
}

# Parse flags
while [[ "$#" -gt 0 ]]; do
    case $1 in
        -d|--domain) DOMAIN="$2"; shift 2 ;;
        -l|--list) DOMAIN_LIST="$2"; shift 2 ;;
        -v|--verbose) VERBOSE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) BYPASS_ARGS+=("$1"); shift ;; # Capture all unknown arguments for the bypass script
    esac
done

if [[ -z "$DOMAIN" ]] && [[ -z "$DOMAIN_LIST" ]]; then
    echo -e "${RED}[!] Error: You must specify either a domain (-d) or a list (-l).${NC}"
    usage
    exit 1
fi

if [[ -n "$DOMAIN" ]] && [[ -n "$DOMAIN_LIST" ]]; then
    echo -e "${RED}[!] Error: Please provide either -d OR -l, not both.${NC}"
    exit 1
fi

# Check if a specific bypass mode was provided in the extra arguments
MODE_PROVIDED=0
for arg in "${BYPASS_ARGS[@]}"; do
    case $arg in
        --header|--protocol|--port|--HTTPmethod|--encode|--SQLi|--exploit)
            MODE_PROVIDED=1
            break
            ;;
    esac
done

# If no mode was provided, default to --exploit
if [ $MODE_PROVIDED -eq 0 ]; then
    BYPASS_ARGS+=("--exploit")
fi

# ==========================================
# Phase 1: Asset Assembly
# ==========================================
SESSION_ID=$$
TARGET_FILE="targets_${SESSION_ID}.txt"
RESTRICTED_FILE="restricted_${SESSION_ID}.txt"

if [[ -n "$DOMAIN" ]]; then
    echo -e "${YELLOW}[1/3] Running Subfinder on ${DOMAIN}...${NC}"
    
    if [ $VERBOSE -eq 1 ]; then
        subfinder -d "$DOMAIN" -o "$TARGET_FILE"
    else
        subfinder -d "$DOMAIN" -o "$TARGET_FILE" > /dev/null 2>&1
    fi

    if [ ! -f "$TARGET_FILE" ] || [ ! -s "$TARGET_FILE" ]; then
        echo -e "${RED}[!] No subdomains found for ${DOMAIN}. Exiting.${NC}"
        exit 1
    fi
    COUNT=$(wc -l < "$TARGET_FILE")
    echo -e "${GREEN}[+] Found ${COUNT} subdomains.${NC}\n"

elif [[ -n "$DOMAIN_LIST" ]]; then
    if [ ! -f "$DOMAIN_LIST" ]; then
        echo -e "${RED}[!] Error: File '$DOMAIN_LIST' not found.${NC}"
        exit 1
    fi
    
    echo -e "${YELLOW}[1/3] Using provided inventory list: ${DOMAIN_LIST}${NC}"
    cp "$DOMAIN_LIST" "$TARGET_FILE"
    
    COUNT=$(wc -l < "$TARGET_FILE")
    echo -e "${GREEN}[+] Loaded ${COUNT} target domains.${NC}\n"
fi

# ==========================================
# Phase 2: Probing for Restricted Endpoints
# ==========================================
echo -e "${YELLOW}[2/3] Probing with httpx for 403/401 endpoints...${NC}"

if [ $VERBOSE -eq 1 ]; then
    httpx -l "$TARGET_FILE" -mc 403,401 -o "$RESTRICTED_FILE"
else
    httpx -l "$TARGET_FILE" -mc 403,401 -o "$RESTRICTED_FILE" > /dev/null 2>&1
fi

if [ ! -f "$RESTRICTED_FILE" ] || [ ! -s "$RESTRICTED_FILE" ]; then
    echo -e "${GREEN}[+] No 403/401 restricted endpoints found. The perimeter is clear! Exiting.${NC}"
    rm -f "$TARGET_FILE" "$RESTRICTED_FILE"
    exit 0
fi

RESTRICTED_COUNT=$(wc -l < "$RESTRICTED_FILE")
echo -e "${GREEN}[+] Isolated ${RESTRICTED_COUNT} restricted endpoints for bypass testing.${NC}\n"

# ==========================================
# Phase 3: Exploitation / Bypass Testing
# ==========================================
echo -e "${YELLOW}[3/3] Initiating 403-bypass suite...${NC}"

if ! command -v 4zero3 &> /dev/null; then
    echo -e "${RED}[!] Error: '4zero3' command not found. Please install it first.${NC}"
    echo -e "${YELLOW}[*] Cleaning up temporary files...${NC}"
    rm -f "$TARGET_FILE" "$RESTRICTED_FILE"
    exit 1
fi

# Pass the collected bypass arguments down to the script
if [ $VERBOSE -eq 1 ]; then
    4zero3 -l "$RESTRICTED_FILE" "${BYPASS_ARGS[@]}"
else
    echo -e "${CYAN}[*] Filtering output for anomalies (2xx, 3xx, 5xx)... Run with -v for full output.${NC}"
    4zero3 -l "$RESTRICTED_FILE" "${BYPASS_ARGS[@]}" | grep -vE "Status: 4[0-9]{2}"
fi

# ==========================================
# Cleanup
# ==========================================
echo -e "\n${YELLOW}[*] Cleaning up temporary files...${NC}"
rm -f "$TARGET_FILE" "$RESTRICTED_FILE"
echo -e "${GREEN}[+] Sequence complete. Happy Hunting! 🍻${NC}"
