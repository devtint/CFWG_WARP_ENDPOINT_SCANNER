#!/usr/bin/env python3
"""
Cloudflare WARP Mass Endpoint Scanner (Python Fallback Version)
Author: Tint Naing Win (@BadCodeWriter)

Cross-platform Python implementation for scanning Cloudflare WARP endpoints
and testing WireGuard tunnels on Windows, Linux, and macOS.
"""

import os
import sys
import re
import time
import json
import shutil
import socket
import hashlib
import urllib.request
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

CLOUDFLARE_SUBNETS = [
    "162.159.192.0/24",
    "162.159.193.0/24",
    "162.159.195.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24"
]

WARP_PORTS = [2408, 500, 4500, 1701, 854, 859, 864, 939]

WORKING_DIR = Path(__file__).resolve().parent
CONFIG_DIR = WORKING_DIR / "WARP_Configs"
WORKING_CONF_DIR = WORKING_DIR / "Working_Configs"
CSV_OUTPUT = WORKING_DIR / "working_endpoints.csv"
TXT_OUTPUT = WORKING_DIR / "working_endpoints.txt"

IS_WINDOWS = sys.platform.startswith("win")
WGCF_BIN = WORKING_DIR / ("wgcf.exe" if IS_WINDOWS else "wgcf")
WIREGUARD_BIN = Path(r"C:\Program Files\WireGuard\wireguard.exe") if IS_WINDOWS else Path(shutil.which("wg-quick") or "wg-quick")


def is_admin():
    try:
        if IS_WINDOWS:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def test_tcp_reachable(host, port, timeout=5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False


def read_wgcf_profile(path):
    try:
        content = Path(path).read_text(encoding="utf-8")
        pk  = re.search(r"PrivateKey\s*=\s*(.+)", content)
        ad  = re.search(r"Address\s*=\s*(.+)", content)
        dn  = re.search(r"DNS\s*=\s*(.+)", content)
        pub = re.search(r"PublicKey\s*=\s*(.+)", content)
        res = re.search(r"Reserved\s*=\s*(.+)", content)
        if not pk or not ad or not pub:
            return None
        return {
            "PrivateKey": pk.group(1).strip(),
            "Address":    ad.group(1).strip(),
            "DNS":        dn.group(1).strip() if dn else "1.1.1.1",
            "PublicKey":  pub.group(1).strip(),
            "Reserved":   res.group(1).strip() if res else None
        }
    except Exception:
        return None


def pre_check():
    print("\n======================================================================")
    print("  Step 0: Environment Pre-Check")
    print("======================================================================")

    all_passed = True

    # Check 0.1: Active wg-quick / WireGuard tunnel interfaces
    print("[*] Checking for active WireGuard tunnel interfaces...")
    try:
        if IS_WINDOWS:
            result = subprocess.run(["sc", "query", "type=", "all"], capture_output=True, text=True, timeout=5)
            tunnels = [l.strip() for l in result.stdout.splitlines() if "WireGuardTunnel$" in l]
            if tunnels:
                print("  [WARN] Active WireGuard tunnel services found:")
                for t in tunnels:
                    print(f"         {t}")
                print("         These will interfere with tunnel testing in Step 5.")
                choice = input("  Press Enter to continue anyway or type STOP to exit: ").strip().upper()
                if choice == "STOP":
                    sys.exit(1)
            else:
                print("  [PASS] No active WireGuard tunnel services detected.")
        else:
            result = subprocess.run(["ip", "link", "show"], capture_output=True, text=True, timeout=5)
            wg_ifaces = [l for l in result.stdout.splitlines() if "warp_" in l or "wg" in l]
            if wg_ifaces:
                print("  [WARN] Active WireGuard interfaces detected. They may interfere with scanning.")
                input("  Press Enter to continue anyway or Ctrl+C to exit first: ")
            else:
                print("  [PASS] No active WireGuard interfaces detected.")
    except Exception as e:
        print(f"  [WARN] Could not check WireGuard tunnel status: {e}")

    # Check 0.2: Cloudflare WARP app process
    print("[*] Checking for Cloudflare WARP app process...")
    try:
        if IS_WINDOWS:
            result = subprocess.run(["tasklist"], capture_output=True, text=True, timeout=5)
            if "warp-svc" in result.stdout.lower() or "cloudflare warp" in result.stdout.lower():
                print("  [WARN] Cloudflare WARP app is running. Disconnect it before scanning.")
                input("  Press Enter to continue anyway or Ctrl+C to exit and disconnect WARP: ")
            else:
                print("  [PASS] No Cloudflare WARP app process detected.")
        else:
            result = subprocess.run(["pgrep", "-x", "warp-svc"], capture_output=True, timeout=5)
            if result.returncode == 0:
                print("  [WARN] Cloudflare WARP service (warp-svc) is running.")
                input("  Press Enter to continue anyway or Ctrl+C to exit: ")
            else:
                print("  [PASS] No Cloudflare WARP process detected.")
    except Exception as e:
        print(f"  [WARN] Could not check WARP process status: {e}")

    # Check 0.3: Internet connectivity via ping
    print("[*] Checking basic internet connectivity (ping 1.1.1.1)...")
    try:
        cmd = ["ping", "-n" if IS_WINDOWS else "-c", "1",
               "-w" if IS_WINDOWS else "-W", "3000" if IS_WINDOWS else "3",
               "1.1.1.1"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
        if result.returncode == 0:
            print("  [PASS] Internet is reachable. Ping 1.1.1.1 succeeded.")
        else:
            print("  [WARN] Ping to 1.1.1.1 failed. ICMP may be blocked on your network.")
            print("         Scan will still attempt UDP socket probes.")
    except Exception as e:
        print(f"  [WARN] Ping test error: {e}")

    # Check 0.4: DNS resolution
    print("[*] Checking DNS resolution (resolving cloudflare.com)...")
    try:
        addrs = socket.getaddrinfo("cloudflare.com", 443)
        if addrs:
            ip = addrs[0][4][0]
            print(f"  [PASS] DNS working. cloudflare.com resolved to {ip}.")
        else:
            print("  [FAIL] DNS returned no results for cloudflare.com.")
            all_passed = False
    except Exception as e:
        print(f"  [FAIL] DNS resolution failed: {e}")
        print("         Your internet may not be working or DNS is blocked.")
        all_passed = False

    # Check 0.5: Script version / hash check against GitHub
    print("[*] Checking script version against GitHub main branch...")
    try:
        url = "https://raw.githubusercontent.com/devtint/CFWG_WARP_ENDPOINT_SCANNER/main/warp_scanner.py"
        req = urllib.request.Request(url, headers={"User-Agent": "WARP-Scanner-Python"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            remote_bytes = resp.read().decode("utf-8", errors="ignore")

        local_bytes = Path(__file__).read_text(encoding="utf-8", errors="ignore")

        remote_norm = remote_bytes.replace("\r\n", "\n")
        local_norm = local_bytes.replace("\r\n", "\n")

        remote_hash = hashlib.sha256(remote_norm.encode("utf-8")).hexdigest()
        local_hash = hashlib.sha256(local_norm.encode("utf-8")).hexdigest()

        if local_hash == remote_hash:
            print("  [PASS] Script version is up to date (matches GitHub main branch).")
        else:
            print("  [WARN] Update available or local file modified.")
            print("         Your local script hash does not match latest GitHub version.")
            print("         To update, run:")
            print("         curl -sSL https://raw.githubusercontent.com/devtint/CFWG_WARP_ENDPOINT_SCANNER/main/warp_scanner.py -o warp_scanner.py")
            choice = input("  Press Enter to continue with current version, or type UPDATE to exit: ").strip().upper()
            if choice == "UPDATE":
                sys.exit(0)
    except Exception:
        print("  [*] Could not check version (Offline or GitHub unreachable). Proceeding...")
    if all_passed:
        print("[+] Pre-check complete. All critical checks passed. Proceeding with scan.")
    else:
        print("[!] Pre-check complete. One or more checks failed. Scan may not produce results.")
        choice = input("  Type YES to proceed anyway or press Enter to exit: ").strip().upper()
        if choice != "YES":
            sys.exit(1)


def check_prerequisites():
    print("\n======================================================================")
    print("  Step 1: Prerequisite & Environment Checks")
    print("======================================================================")

    if not is_admin():
        print("[!] Warning: Administrator or root privileges required to manage WireGuard services.")
        if IS_WINDOWS:
            print("    Please re-run Command Prompt or PowerShell as Administrator.")
        else:
            print("    Please run with sudo: sudo python3 warp_scanner.py")
        sys.exit(1)
    print("[+] Administrator / root privileges confirmed.")

    if IS_WINDOWS and not WIREGUARD_BIN.exists():
        found = shutil.which("wireguard.exe")
        if not found:
            print(f"[-] WireGuard not found at {WIREGUARD_BIN} or system PATH.")
            print("    Please install WireGuard from https://www.wireguard.com/install/")
            sys.exit(1)

    if not WGCF_BIN.exists():
        print(f"[*] wgcf binary not found in working directory. Downloading latest release...")
        download_wgcf()
    else:
        print(f"[+] wgcf binary verified: {WGCF_BIN}")


def download_wgcf():
    api_url = "https://api.github.com/repos/ViRb3/wgcf/releases/latest"
    req = urllib.request.Request(api_url, headers={"User-Agent": "WARP-Scanner-Python"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        arch = "amd64"
        import platform
        machine = platform.machine().lower()
        if "arm" in machine or "aarch64" in machine:
            arch = "arm64"
        elif "86" in machine or "32" in machine:
            arch = "386"

        target_os = "windows" if IS_WINDOWS else ("darwin" if sys.platform == "darwin" else "linux")
        download_url = None

        for asset in data.get("assets", []):
            name = asset.get("name", "").lower()
            if target_os in name and arch in name and (name.endswith(".exe") if IS_WINDOWS else not name.endswith(".exe")):
                download_url = asset.get("browser_download_url")
                break

        if not download_url:
            for asset in data.get("assets", []):
                name = asset.get("name", "").lower()
                if target_os in name:
                    download_url = asset.get("browser_download_url")
                    break

        if not download_url:
            raise Exception("No matching binary asset found in GitHub releases.")

        print(f"[*] Downloading wgcf from {download_url}...")
        urllib.request.urlretrieve(download_url, WGCF_BIN)
        if not IS_WINDOWS:
            os.chmod(WGCF_BIN, 0o755)
        print(f"[+] Downloaded successfully: {WGCF_BIN}")

    except Exception as e:
        print(f"[-] Failed to download wgcf: {e}")
        sys.exit(1)


def get_warpgen_profile_cloud(profile_path):
    print("[*] Attempting automatic Cloud API fallback via WarpGen (https://warp-conf-gen.vercel.app)...")
    try:
        req = urllib.request.Request(
            "https://warp-conf-gen.vercel.app/api/generate",
            data=b"",
            headers={"User-Agent": "WARP-Scanner-Python"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            conf_str = data.get("conf")
            if conf_str:
                Path(profile_path).write_text(conf_str, encoding="utf-8")
                parsed = read_wgcf_profile(profile_path)
                if parsed:
                    print("[+] Base WARP profile successfully generated & parsed via WarpGen Cloud API!")
                    return parsed
    except Exception as e:
        print(f"[!] WarpGen Cloud API fallback request failed: {e}")
    return None


def register_account():
    print("\n======================================================================")
    print("  Step 2: Cloudflare Account Registration & Key Extraction")
    print("======================================================================")

    account_file = WORKING_DIR / "wgcf-account.toml"
    profile_file = WORKING_DIR / "wgcf-profile.conf"

    # Fast path: reuse existing valid profile
    existing = read_wgcf_profile(profile_file)
    if existing:
        print("[+] Existing valid wgcf-profile.conf found. Skipping registration.")
        return existing

    # Pre-check API reachability before running wgcf
    if not account_file.exists():
        print("[*] Checking reachability of api.cloudflareclient.com...")
        if not test_tcp_reachable("api.cloudflareclient.com", 443, timeout=5):
            print("[!] Cannot reach api.cloudflareclient.com on port 443 (Blocked by ISP).")
            existing = get_warpgen_profile_cloud(profile_file)
            if not existing:
                print("\n[!] Registration server blocked and Cloud API fallback unavailable.")
                print("    Option A: Switch to mobile hotspot, run the script there once.")
                print("    Option B: Place an existing wgcf-profile.conf here and run again.")
                choice = input("  Press Enter to exit, or type SKIP to try registration anyway: ").strip().upper()
                if choice != "SKIP":
                    sys.exit(1)
                print("[!] Skipping pre-check. Attempting registration anyway...")
        else:
            print("[+] api.cloudflareclient.com is reachable. Proceeding with registration.")

        if not existing:
            print("[*] Registering new Cloudflare WARP account via wgcf...")
            try:
                result = subprocess.run(
                    [str(WGCF_BIN), "register", "--accept-tos"],
                    cwd=WORKING_DIR, capture_output=True, text=True, timeout=25
                )
                if result.returncode != 0:
                    print("[!] Local wgcf registration failed. Attempting Cloud API Fallback...")
                    existing = get_warpgen_profile_cloud(profile_file)
                    if not existing:
                        print("[-] Registration failed and Cloud API fallback unavailable.")
                        sys.exit(1)
                else:
                    print("[+] Cloudflare WARP account registered successfully.")
            except subprocess.TimeoutExpired:
                print("[!] Registration timed out. Attempting Cloud API Fallback...")
                existing = get_warpgen_profile_cloud(profile_file)
                if not existing:
                    print("[-] Registration timed out and Cloud API fallback failed.")
                    sys.exit(1)

    if not existing:
        # Generate profile via wgcf if not already obtained from cloud
        print("[*] Generating WireGuard profile via wgcf...")
        try:
            result = subprocess.run(
                [str(WGCF_BIN), "generate"],
                cwd=WORKING_DIR, capture_output=True, text=True, timeout=15
            )
        except subprocess.TimeoutExpired:
            print("[!] Profile generation timed out. Attempting Cloud API Fallback...")
            existing = get_warpgen_profile_cloud(profile_file)
            if not existing:
                sys.exit(1)

        if not existing and not profile_file.exists():
            print("[!] Profile generation failed. Attempting Cloud API Fallback...")
            existing = get_warpgen_profile_cloud(profile_file)
            if not existing:
                sys.exit(1)

        if not existing:
            existing = read_wgcf_profile(profile_file)
            if not existing:
                print("[!] Profile missing keys. Attempting Cloud API Fallback...")
                existing = get_warpgen_profile_cloud(profile_file)
                if not existing:
                    sys.exit(1)

    print("[+] Base profile generated and parsed successfully.")
    print(f"    Address   : {existing['Address']}")
    print(f"    PublicKey : {existing['PublicKey']}")
    return existing


def probe_endpoint(ip, port, timeout=0.8):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        probe_payload = b"\x01\x00\x00\x00" + b"\x00" * 28
        t0 = time.perf_counter()
        s.sendto(probe_payload, (ip, port))
        t1 = time.perf_counter()
        s.close()
        return {"ip": ip, "port": port, "endpoint": f"{ip}:{port}", "reachable": True, "latency": round((t1 - t0) * 1000, 1)}
    except Exception:
        return {"ip": ip, "port": port, "endpoint": f"{ip}:{port}", "reachable": False, "latency": 9999}


def prescan_targets(threads=100):
    print("\n======================================================================")
    print("  Step 3: Mass Target Generation & Fast Multithreaded Pre-Scan")
    print("======================================================================")

    targets = []
    for subnet in CLOUDFLARE_SUBNETS:
        base_ip, mask = subnet.split("/")
        if mask == "24":
            octets = base_ip.split(".")
            prefix = f"{octets[0]}.{octets[1]}.{octets[2]}"
            for i in range(1, 255):
                ip = f"{prefix}.{i}"
                for port in WARP_PORTS:
                    targets.append((ip, port))

    print(f"[*] Generated {len(targets)} candidate endpoints from Cloudflare ranges.")
    print(f"[*] Pre-scanning endpoints with {threads} threads...")

    responsive = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(probe_endpoint, ip, port) for ip, port in targets]
        for f in as_completed(futures):
            res = f.result()
            if res["reachable"]:
                responsive.append(res)

    print(f"[+] Pre-scan complete. Found {len(responsive)} responsive endpoints.")

    if not responsive:
        print("[!] No endpoints responded to UDP socket probe. Falling back to default targets...")
        for ip, port in targets[:30]:
            responsive.append({"ip": ip, "port": port, "endpoint": f"{ip}:{port}", "reachable": True, "latency": 999})

    responsive.sort(key=lambda x: x["latency"])
    return responsive


def generate_configs(candidates, profile, max_tests=30):
    print("\n======================================================================")
    print("  Step 4: Batch Configuration File Generation")
    print("======================================================================")

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    WORKING_CONF_DIR.mkdir(parents=True, exist_ok=True)

    selected = candidates[:max_tests]
    configs = []

    for item in selected:
        safe_ip = item["ip"].replace(".", "_")
        conf_name = f"warp_{safe_ip}_{item['port']}.conf"
        conf_path = CONFIG_DIR / conf_name

        res_line = f"Reserved = {profile['Reserved']}\n" if profile["Reserved"] else ""
        content = f"""[Interface]
PrivateKey = {profile['PrivateKey']}
Address = {profile['Address']}
DNS = {profile['DNS']}
{res_line}
[Peer]
PublicKey = {profile['PublicKey']}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {item['endpoint']}
"""
        conf_path.write_text(content, encoding="utf-8")
        configs.append({"endpoint": item["endpoint"], "ip": item["ip"], "port": item["port"], "path": conf_path, "name": conf_name})

    print(f"[+] Created {len(configs)} configuration files in {CONFIG_DIR}")
    return configs


def remove_tunnel(tunnel_name):
    if not tunnel_name:
        return
    try:
        if IS_WINDOWS:
            subprocess.run([str(WIREGUARD_BIN), "/uninstalltunnelservice", tunnel_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8)
        else:
            subprocess.run(["wg-quick", "down", tunnel_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=8)
    except Exception:
        pass


def test_tunnels(configs, tunnel_wait=4):
    print("\n======================================================================")
    print("  Step 5: Active WireGuard Tunnel Connectivity Testing")
    print("======================================================================")

    verified = []

    for idx, cfg in enumerate(configs, 1):
        tunnel_name = cfg["path"].stem
        print(f"\n[{idx}/{len(configs)}] Testing Endpoint: {cfg['endpoint']} ({tunnel_name})")

        try:
            if IS_WINDOWS:
                subprocess.run([str(WIREGUARD_BIN), "/installtunnelservice", str(cfg["path"])], check=True, timeout=10)
            else:
                subprocess.run(["wg-quick", "up", str(cfg["path"])], check=True, timeout=10)
        except Exception as e:
            print(f"[!] Failed to start tunnel service: {e}")
            remove_tunnel(tunnel_name)
            continue

        print(f"[*] Waiting {tunnel_wait} seconds for WireGuard handshake...")
        time.sleep(tunnel_wait)

        ping_ok = False
        rtt = 9999
        warp_status = "OFF"
        location = "N/A"

        try:
            ping_cmd = ["ping", "-n" if IS_WINDOWS else "-c", "3", "1.1.1.1"]
            proc = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=5)
            if proc.returncode == 0:
                ping_ok = True
                match = re.search(r"(?:Average|avg)\s*=\s*(\d+)ms", proc.stdout)
                if match:
                    rtt = int(match.group(1))
                else:
                    rtt = 50
        except Exception:
            pass

        if ping_ok:
            try:
                req = urllib.request.Request("https://www.cloudflare.com/cdn-cgi/trace", headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    body = resp.read().decode("utf-8", errors="ignore")
                    m_warp = re.search(r"warp=(on|plus)", body)
                    m_colo = re.search(r"colo=([A-Z]+)", body)
                    if m_warp:
                        warp_status = m_warp.group(1)
                    if m_colo:
                        location = m_colo.group(1)
            except Exception:
                pass

        if ping_ok and warp_status in ["on", "plus"]:
            print(f"[+] VALID WARP ENDPOINT: {cfg['endpoint']} | Ping: {rtt}ms | WARP: {warp_status} | Location: {location}")
            dest_conf = WORKING_CONF_DIR / cfg["name"]
            shutil.copy(cfg["path"], dest_conf)

            verified.append({
                "Endpoint": cfg["endpoint"],
                "IP": cfg["ip"],
                "Port": cfg["port"],
                "LatencyMs": rtt,
                "WarpStatus": warp_status,
                "Location": location,
                "ConfigFile": cfg["name"]
            })
        else:
            print(f"[-] Tunnel test failed for {cfg['endpoint']}")

        remove_tunnel(tunnel_name)
        time.sleep(2)

    return verified


def export_results(results):
    print("\n======================================================================")
    print("  Step 6: Results Summary & Export")
    print("======================================================================")

    if not results:
        print("[!] No working endpoints found.")
        return

    results.sort(key=lambda x: x["LatencyMs"])

    print(f"\n[+] Found {len(results)} working Cloudflare WARP endpoints!\n")
    print(f"{'Endpoint':<22} {'Latency (ms)':<12} {'WARP Status':<12} {'Location':<10} {'Config File':<25}")
    print("-" * 80)
    for r in results:
        print(f"{r['Endpoint']:<22} {r['LatencyMs']:<12} {r['WarpStatus']:<12} {r['Location']:<10} {r['ConfigFile']:<25}")

    with open(CSV_OUTPUT, "w", encoding="utf-8") as f:
        f.write("Endpoint,IP,Port,LatencyMs,WarpStatus,Location,ConfigFile\n")
        for r in results:
            f.write(f"{r['Endpoint']},{r['IP']},{r['Port']},{r['LatencyMs']},{r['WarpStatus']},{r['Location']},{r['ConfigFile']}\n")
    print(f"[+] Exported CSV: {CSV_OUTPUT}")

    with open(TXT_OUTPUT, "w", encoding="utf-8") as f:
        f.write(f"# Cloudflare WARP Working Endpoints - Generated {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        for r in results:
            f.write(f"{r['Endpoint']} | Latency: {r['LatencyMs']} ms | WARP: {r['WarpStatus']} | Location: {r['Location']} | Config: {r['ConfigFile']}\n")
    print(f"[+] Exported TXT: {TXT_OUTPUT}")


def main():
    print("\n======================================================================")
    print("  Cloudflare WARP Scanner (Python) by Tint Naing Win (@BadCodeWriter)")
    print("======================================================================")

    pre_check()

    threads = 100
    max_tests = 30

    if len(sys.argv) == 1:
        print("  Select Scanning Mode:")
        print("    [1] Standard Scan  (100 Threads, 30 Candidate Tests)")
        print("    [2] Fast Scan      (150 Threads, 15 Candidate Tests)")
        print("    [3] Deep Scan      (100 Threads, 60 Candidate Tests)")
        print("    [4] Exit")
        choice = input("\n  Enter choice [1-4] (Default is 1): ").strip()
        if choice == "2":
            threads, max_tests = 150, 15
        elif choice == "3":
            threads, max_tests = 100, 60
        elif choice == "4":
            sys.exit(0)

    check_prerequisites()
    profile = register_account()
    responsive = prescan_targets(threads=threads)
    configs = generate_configs(responsive, profile, max_tests=max_tests)
    verified = test_tunnels(configs)
    export_results(verified)


if __name__ == "__main__":
    main()
