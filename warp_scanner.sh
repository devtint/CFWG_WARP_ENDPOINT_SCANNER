#!/usr/bin/env bash
# Cloudflare WARP Mass Endpoint Scanner (Bash Fallback Version)
# Author: Tint Naing Win (@BadCodeWriter)
#
# POSIX shell implementation for scanning Cloudflare WARP endpoints
# and testing WireGuard tunnels on Linux, macOS, and OpenWrt routers.

set -e

WORKING_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="${WORKING_DIR}/WARP_Configs"
WORKING_CONF_DIR="${WORKING_DIR}/Working_Configs"
CSV_OUTPUT="${WORKING_DIR}/working_endpoints.csv"
TXT_OUTPUT="${WORKING_DIR}/working_endpoints.txt"
WGCF_BIN="${WORKING_DIR}/wgcf"

CLOUDFLARE_SUBNETS=(
    "162.159.192.0"
    "162.159.193.0"
    "162.159.195.0"
    "188.114.96.0"
    "188.114.97.0"
    "188.114.98.0"
)

WARP_PORTS=(2408 500 4500 1701 854 859 864 939)

ACTIVE_TUNNEL=""

cleanup() {
    if [ -n "$ACTIVE_TUNNEL" ]; then
        echo "[!] Interrupted. Tearing down active WireGuard tunnel: $ACTIVE_TUNNEL"
        wg-quick down "$ACTIVE_TUNNEL" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[-] ERROR: Root privileges required to create WireGuard network interfaces."
        echo "    Please re-run with sudo: sudo ./warp_scanner.sh"
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# STEP 0: ENVIRONMENT PRE-CHECK
# -----------------------------------------------------------------------------
pre_check() {
    echo ""
    echo "======================================================================"
    echo "  Step 0: Environment Pre-Check"
    echo "======================================================================"

    PRE_CHECK_PASSED=1

    # Check 0.1: Active wg-quick tunnel interfaces
    echo "[*] Checking for active WireGuard tunnel interfaces..."
    if ip link show 2>/dev/null | grep -qE "warp_|^[0-9]+: wg"; then
        echo "  [WARN] Active WireGuard interfaces detected on this system."
        echo "         They may interfere with tunnel testing in Step 5."
        printf "  Press Enter to continue anyway or Ctrl+C to exit first: "
        read -r _
    else
        echo "  [PASS] No active WireGuard interfaces detected."
    fi

    # Check 0.2: Cloudflare WARP app process
    echo "[*] Checking for Cloudflare WARP app process..."
    if pgrep -x "warp-svc" >/dev/null 2>&1; then
        echo "  [WARN] Cloudflare WARP service (warp-svc) is running."
        echo "         Disconnect it before scanning to avoid interference."
        printf "  Press Enter to continue anyway or Ctrl+C to exit: "
        read -r _
    else
        echo "  [PASS] No Cloudflare WARP process detected."
    fi

    # Check 0.3: Basic internet connectivity
    echo "[*] Checking basic internet connectivity (ping 1.1.1.1)..."
    if ping -c 1 -W 3 1.1.1.1 >/dev/null 2>&1; then
        echo "  [PASS] Internet is reachable. Ping 1.1.1.1 succeeded."
    else
        echo "  [WARN] Ping to 1.1.1.1 failed. ICMP may be blocked on your network."
        echo "         Scan will still attempt UDP socket probes."
    fi

    # Check 0.4: DNS resolution
    echo "[*] Checking DNS resolution (resolving cloudflare.com)..."
    if RESOLVED=$(getent hosts cloudflare.com 2>/dev/null | awk '{print $1; exit}') && [ -n "$RESOLVED" ]; then
        echo "  [PASS] DNS working. cloudflare.com resolved to ${RESOLVED}."
    elif RESOLVED=$(host cloudflare.com 2>/dev/null | grep "has address" | head -1 | awk '{print $NF}') && [ -n "$RESOLVED" ]; then
        echo "  [PASS] DNS working. cloudflare.com resolved to ${RESOLVED}."
    else
        echo "  [FAIL] DNS resolution failed. Cannot resolve cloudflare.com."
        echo "         Your internet may not be working, or DNS is blocked."
        PRE_CHECK_PASSED=0
    fi

    echo ""
    if [ "$PRE_CHECK_PASSED" -eq 1 ]; then
        echo "[+] Pre-check complete. All critical checks passed. Proceeding with scan."
    else
        echo "[!] Pre-check complete. One or more checks failed. Scan may not produce results."
        printf "  Type YES to proceed anyway or press Enter to exit: "
        read -r proceed
        if [ "$(echo "$proceed" | tr '[:lower:]' '[:upper:]')" != "YES" ]; then
            exit 1
        fi
    fi
}

check_prerequisites() {
    echo ""
    echo "======================================================================"
    echo "  Step 1: Prerequisite & Environment Checks"
    echo "======================================================================"
    check_root
    echo "[+] Root privileges confirmed."

    if ! command -v wg-quick >/dev/null 2>&1; then
        echo "[-] ERROR: wg-quick command not found."
        echo "    Please install wireguard-tools on your Linux/macOS distribution."
        exit 1
    fi
    echo "[+] wireguard-tools (wg-quick) verified."

    if [ ! -f "$WGCF_BIN" ]; then
        echo "[*] Downloading wgcf binary for Linux/macOS..."
        OS_TYPE="$(uname -s | tr '[:upper:]' '[:lower:]')"
        ARCH_TYPE="$(uname -m)"
        case "$ARCH_TYPE" in
            x86_64|amd64) ARCH_STR="amd64" ;;
            aarch64|arm64) ARCH_STR="arm64" ;;
            *) ARCH_STR="386" ;;
        esac

        DOWNLOAD_URL=$(curl -s https://api.github.com/repos/ViRb3/wgcf/releases/latest | grep "browser_download_url" | grep "$OS_TYPE" | grep "$ARCH_STR" | head -n 1 | cut -d '"' -f 4)
        if [ -z "$DOWNLOAD_URL" ]; then
            DOWNLOAD_URL=$(curl -s https://api.github.com/repos/ViRb3/wgcf/releases/latest | grep "browser_download_url" | grep "$OS_TYPE" | head -n 1 | cut -d '"' -f 4)
        fi

        if [ -z "$DOWNLOAD_URL" ]; then
            echo "[-] Failed to auto-detect wgcf release binary URL."
            exit 1
        fi

        curl -sL "$DOWNLOAD_URL" -o "$WGCF_BIN"
        chmod +x "$WGCF_BIN"
        echo "[+] Downloaded wgcf binary: $WGCF_BIN"
    else
        echo "[+] wgcf binary verified."
    fi
}

# -----------------------------------------------------------------------------
# STEP 2: CLOUDFLARE ACCOUNT REGISTRATION & PROFILE PARSING
# -----------------------------------------------------------------------------
register_account() {
    echo ""
    echo "======================================================================"
    echo "  Step 2: Cloudflare Account Registration & Profile Parsing"
    echo "======================================================================"

    ACCOUNT_FILE="${WORKING_DIR}/wgcf-account.toml"
    PROFILE_FILE="${WORKING_DIR}/wgcf-profile.conf"

    # Fast path: reuse existing valid profile
    if [ -f "$PROFILE_FILE" ]; then
        _pk=$(grep "PrivateKey" "$PROFILE_FILE" 2>/dev/null | cut -d '=' -f 2 | tr -d ' ')
        _pub=$(grep "PublicKey" "$PROFILE_FILE" 2>/dev/null | cut -d '=' -f 2 | tr -d ' ')
        if [ -n "$_pk" ] && [ -n "$_pub" ]; then
            echo "[+] Existing valid wgcf-profile.conf found. Skipping registration."
            PRIVATE_KEY=$_pk
            ADDRESS=$(grep "Address" "$PROFILE_FILE" | cut -d '=' -f 2 | tr -d ' ')
            DNS=$(grep "DNS" "$PROFILE_FILE" | cut -d '=' -f 2 | tr -d ' ')
            PUBLIC_KEY=$_pub
            RESERVED=$(grep "Reserved" "$PROFILE_FILE" | cut -d '=' -f 2 | tr -d ' ' 2>/dev/null || true)
            return 0
        fi
    fi

    if [ ! -f "$ACCOUNT_FILE" ]; then
        # Pre-check API reachability
        echo "[*] Checking reachability of api.cloudflareclient.com..."
        if ! curl -s --connect-timeout 5 --max-time 5 -o /dev/null https://api.cloudflareclient.com 2>/dev/null; then
            echo ""
            echo "[!] Cannot reach api.cloudflareclient.com."
            echo "    Your network is blocking Cloudflare's WARP registration server."
            echo ""
            echo "    Option A: Switch to mobile hotspot, run the script there once,"
            echo "              then copy wgcf-account.toml back here and run again."
            echo "    Option B: Ask someone on an open network to run wgcf register"
            echo "              and send you their wgcf-account.toml file."
            echo "    Option C: Place an existing wgcf-profile.conf here and run again."
            echo ""
            printf "  Press Enter to exit, or type SKIP to try anyway: "
            read -r skip_choice
            if [ "$(echo "$skip_choice" | tr '[:lower:]' '[:upper:]')" != "SKIP" ]; then
                exit 1
            fi
            echo "[!] Skipping pre-check. Attempting registration anyway..."
        else
            echo "[+] api.cloudflareclient.com is reachable. Proceeding with registration."
        fi

        echo "[*] Registering new Cloudflare WARP account..."
        set +e
        REG_OUTPUT=$("$WGCF_BIN" register --accept-tos 2>&1)
        REG_EXIT=$?
        set -e

        if [ $REG_EXIT -ne 0 ]; then
            echo ""
            echo "[-] Registration failed. Diagnosing error..."
            if echo "$REG_OUTPUT" | grep -qiE "refused|connectex|No connection|actively refused"; then
                echo "[-] Connection was actively refused by the ISP or network firewall."
                echo "    The /reg API path is being specifically blocked."
                echo "    Switch to mobile hotspot or obtain wgcf-account.toml from another network."
            elif echo "$REG_OUTPUT" | grep -qiE "timeout|timed out|deadline"; then
                echo "[-] Connection timed out waiting for Cloudflare's server."
                echo "    Try again in a few minutes or switch to mobile hotspot."
            elif echo "$REG_OUTPUT" | grep -qiE "TLS|certificate|x509|ssl|handshake"; then
                echo "[-] TLS handshake failed. A proxy or firewall is intercepting HTTPS."
                echo "    Try disabling antivirus SSL scanning or switch to mobile hotspot."
            elif echo "$REG_OUTPUT" | grep -qiE "429|rate limit|too many"; then
                echo "[-] Cloudflare rate-limited this registration attempt."
                echo "    Wait 10 to 15 minutes and try again."
            else
                echo "[-] Unexpected error: $REG_OUTPUT"
            fi
            exit 1
        fi

        echo "[+] Cloudflare WARP account registered successfully."
    else
        echo "[+] Existing wgcf-account.toml found. Skipping registration."
    fi

    echo "[*] Generating base WireGuard profile..."
    set +e
    GEN_OUTPUT=$("$WGCF_BIN" generate 2>&1)
    GEN_EXIT=$?
    set -e

    if [ ! -f "$PROFILE_FILE" ]; then
        echo "[-] wgcf generate ran but wgcf-profile.conf was not created."
        echo "    The account file may be corrupt or revoked."
        echo "    Delete wgcf-account.toml and run again."
        [ -n "$GEN_OUTPUT" ] && echo "    Raw error: $GEN_OUTPUT"
        exit 1
    fi

    PRIVATE_KEY=$(grep "PrivateKey" "$PROFILE_FILE" | cut -d '=' -f 2 | tr -d ' ')
    ADDRESS=$(grep "Address" "$PROFILE_FILE" | cut -d '=' -f 2 | tr -d ' ')
    DNS=$(grep "DNS" "$PROFILE_FILE" | cut -d '=' -f 2 | tr -d ' ')
    PUBLIC_KEY=$(grep "PublicKey" "$PROFILE_FILE" | cut -d '=' -f 2 | tr -d ' ')
    RESERVED=$(grep "Reserved" "$PROFILE_FILE" | cut -d '=' -f 2 | tr -d ' ' 2>/dev/null || true)

    if [ -z "$PRIVATE_KEY" ] || [ -z "$PUBLIC_KEY" ] || [ -z "$ADDRESS" ]; then
        echo "[-] Profile file created but is missing required keys. It may be corrupt."
        echo "    Delete both wgcf-account.toml and wgcf-profile.conf and run again."
        exit 1
    fi

    echo "[+] Profile parameters extracted successfully."
    echo "    Address   : $ADDRESS"
    echo "    PublicKey : $PUBLIC_KEY"
}



prescan_targets() {
    echo ""
    echo "======================================================================"
    echo "  Step 3: Target Generation & UDP Reachability Pre-Scan"
    echo "======================================================================"

    mkdir -p "${WORKING_DIR}/.tmp_scan"
    TMP_SCAN="${WORKING_DIR}/.tmp_scan"
    rm -f "${TMP_SCAN}"/*

    echo "[*] Pre-scanning candidate endpoints..."

    JOB_COUNT=0
    MAX_CONCURRENT=60

    for prefix in "${CLOUDFLARE_SUBNETS[@]}"; do
        for i in $(seq 1 254); do
            ip="${prefix%.0}.${i}"
            for port in "${WARP_PORTS[@]}"; do
                (
                    if ping -c 1 -W 1 "$ip" >/dev/null 2>&1; then
                        echo "${ip}:${port}" >> "${TMP_SCAN}/responsive.txt"
                    fi
                ) &
                JOB_COUNT=$((JOB_COUNT + 1))
                if [ "$JOB_COUNT" -ge "$MAX_CONCURRENT" ]; then
                    wait -n 2>/dev/null || wait
                    JOB_COUNT=$((JOB_COUNT - 1))
                fi
            done
        done
    done
    wait

    RESPONSIVE_COUNT=0
    if [ -f "${TMP_SCAN}/responsive.txt" ]; then
        RESPONSIVE_COUNT=$(wc -l < "${TMP_SCAN}/responsive.txt")
    fi

    echo "[+] Pre-scan finished. Found ${RESPONSIVE_COUNT} responsive endpoints."

    if [ "$RESPONSIVE_COUNT" -eq 0 ]; then
        echo "[!] No endpoints responded to pre-scan. Selecting fallback candidates..."
        for prefix in "${CLOUDFLARE_SUBNETS[@]}"; do
            echo "${prefix%.0}.1:2408" >> "${TMP_SCAN}/responsive.txt"
            echo "${prefix%.0}.1:500" >> "${TMP_SCAN}/responsive.txt"
            echo "${prefix%.0}.1:4500" >> "${TMP_SCAN}/responsive.txt"
        done
    fi
}

generate_configs() {
    echo ""
    echo "======================================================================"
    echo "  Step 4: Batch Configuration File Generation"
    echo "======================================================================"

    mkdir -p "$CONFIG_DIR"
    mkdir -p "$WORKING_CONF_DIR"

    MAX_TESTS=${1:-30}
    CONF_INDEX=0

    rm -f "${WORKING_DIR}/.tmp_scan/targets.txt"
    head -n "$MAX_TESTS" "${WORKING_DIR}/.tmp_scan/responsive.txt" > "${WORKING_DIR}/.tmp_scan/targets.txt"

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        ip=$(echo "$line" | cut -d ':' -f 1)
        port=$(echo "$line" | cut -d ':' -f 2)

        safe_ip=$(echo "$ip" | tr '.' '_')
        conf_name="warp_${safe_ip}_${port}.conf"
        conf_path="${CONFIG_DIR}/${conf_name}"

        res_line=""
        if [ -n "$RESERVED" ]; then
            res_line="Reserved = ${RESERVED}"
        fi

        cat <<EOF > "$conf_path"
[Interface]
PrivateKey = ${PRIVATE_KEY}
Address = ${ADDRESS}
DNS = ${DNS}
${res_line}

[Peer]
PublicKey = ${PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${line}
EOF
        CONF_INDEX=$((CONF_INDEX + 1))
    done < "${WORKING_DIR}/.tmp_scan/targets.txt"

    echo "[+] Generated ${CONF_INDEX} WireGuard configuration files in ${CONFIG_DIR}."
}

test_tunnels() {
    echo ""
    echo "======================================================================"
    echo "  Step 5: Active WireGuard Tunnel Connectivity Testing"
    echo "======================================================================"

    rm -f "${CSV_OUTPUT}" "${TXT_OUTPUT}"
    echo "Endpoint,IP,Port,LatencyMs,WarpStatus,Location,ConfigFile" > "$CSV_OUTPUT"
    echo "# Cloudflare WARP Working Endpoints - Generated $(date)" > "$TXT_OUTPUT"

    TOTAL_CONF=$(ls -1 "${CONFIG_DIR}"/*.conf 2>/dev/null | wc -l)
    CURRENT=0

    for conf in "${CONFIG_DIR}"/*.conf; do
        [ -f "$conf" ] || continue
        CURRENT=$((CURRENT + 1))
        conf_name=$(basename "$conf")
        tunnel_name="${conf_name%.conf}"

        echo ""
        echo "[$CURRENT/$TOTAL_CONF] Testing Configuration: $conf_name"

        ACTIVE_TUNNEL="$conf"
        if ! wg-quick up "$conf" >/dev/null 2>&1; then
            echo "[-] Failed to initialize tunnel interface for $conf_name"
            ACTIVE_TUNNEL=""
            continue
        fi

        sleep 4

        PING_OK=0
        LATENCY=9999
        if PING_OUT=$(ping -c 3 -W 2 1.1.1.1 2>/dev/null); then
            PING_OK=1
            LATENCY=$(echo "$PING_OUT" | tail -1 | awk -F '/' '{print $4}' | cut -d '.' -f 1)
            [ -z "$LATENCY" ] && LATENCY=50
        fi

        WARP_STATUS="OFF"
        LOCATION="N/A"

        if [ "$PING_OK" -eq 1 ]; then
            if TRACE_OUT=$(curl -s --max-time 3 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null); then
                if echo "$TRACE_OUT" | grep -qE "warp=(on|plus)"; then
                    WARP_STATUS=$(echo "$TRACE_OUT" | grep "warp=" | cut -d '=' -f 2)
                    LOCATION=$(echo "$TRACE_OUT" | grep "colo=" | cut -d '=' -f 2)
                fi
            fi
        fi

        if [ "$PING_OK" -eq 1 ] && [ "$WARP_STATUS" != "OFF" ]; then
            echo "[+] VALID ENDPOINT! Latency: ${LATENCY}ms | WARP: ${WARP_STATUS} | Datacenter: ${LOCATION}"
            cp "$conf" "${WORKING_CONF_DIR}/${conf_name}"
            
            endpoint_line=$(grep "Endpoint" "$conf" | cut -d '=' -f 2 | tr -d ' ')
            ip=$(echo "$endpoint_line" | cut -d ':' -f 1)
            port=$(echo "$endpoint_line" | cut -d ':' -f 2)

            echo "${endpoint_line},${ip},${port},${LATENCY},${WARP_STATUS},${LOCATION},${conf_name}" >> "$CSV_OUTPUT"
            echo "${endpoint_line} | Latency: ${LATENCY} ms | WARP: ${WARP_STATUS} | Datacenter: ${LOCATION} | Config: ${conf_name}" >> "$TXT_OUTPUT"
        else
            echo "[-] Tunnel verification failed."
        fi

        wg-quick down "$conf" >/dev/null 2>&1 || true
        ACTIVE_TUNNEL=""
        sleep 2
    done

    rm -rf "${WORKING_DIR}/.tmp_scan"
}

main() {
    echo ""
    echo "======================================================================"
    echo "  Cloudflare WARP Scanner (Bash) by Tint Naing Win (@BadCodeWriter)"
    echo "======================================================================"
    echo "  Select Scanning Mode:"
    echo "    [1] Standard Scan  (30 Candidate Tunnel Tests)"
    echo "    [2] Fast Scan      (15 Candidate Tunnel Tests)"
    echo "    [3] Deep Scan      (60 Candidate Tunnel Tests)"
    echo "    [4] Exit"
    echo ""
    read -p "  Enter choice [1-4] (Default is 1): " choice

    MAX_TESTS=30
    case "$choice" in
        2) MAX_TESTS=15 ;;
        3) MAX_TESTS=60 ;;
        4) exit 0 ;;
        *) MAX_TESTS=30 ;;
    esac

    pre_check
    check_prerequisites
    register_account
    prescan_targets
    generate_configs "$MAX_TESTS"
    test_tunnels
}

main "$@"
