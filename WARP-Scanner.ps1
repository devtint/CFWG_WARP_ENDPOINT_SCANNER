<#
.SYNOPSIS
    Cloudflare WARP Mass Endpoint Scanner & WireGuard Tunnel Validator for Windows.
.DESCRIPTION
    A comprehensive, high-performance PowerShell script (v5.1/v7+) that automatically:
      1. Verifies Administrator execution rights and prerequisite binaries (wireguard.exe, wgcf.exe).
      2. Downloads wgcf.exe from GitHub if missing.
      3. Registers a Cloudflare WARP account & generates base profile via wgcf.
      4. Expands Cloudflare IP subnets & ports and performs a fast multi-threaded pre-scan using RunspacePool.
      5. Generates batch WireGuard .conf profiles for responsive endpoints.
      6. Tests active WireGuard tunnel connectivity, 1.1.1.1 ping, and cloudflare.com/cdn-cgi/trace verification.
      7. Exports top-performing working endpoints to CSV and TXT files sorted by latency.
.PARAMETER PreScanThreads
    Number of concurrent threads for UDP/ICMP pre-scanning (Default: 100).
.PARAMETER PreScanTimeoutMs
    Socket timeout in milliseconds for pre-scan reachability check (Default: 800ms).
.PARAMETER MaxTunnelTests
    Maximum number of top pre-scanned endpoints to test full WireGuard tunnels on (Default: 30).
.PARAMETER TunnelWaitSec
    Handshake wait time in seconds after installing tunnel service (Default: 4).
.PARAMETER CleanUpOnly
    Switch parameter to cleanly remove any leftover WireGuard tunnel services created by this script.
.EXAMPLE
    .\WARP-Scanner.ps1
.EXAMPLE
    .\WARP-Scanner.ps1 -PreScanThreads 150 -MaxTunnelTests 50
.EXAMPLE
    .\WARP-Scanner.ps1 -CleanUpOnly
#>

[CmdletBinding()]
param (
    [int]$PreScanThreads = 100,
    [int]$PreScanTimeoutMs = 800,
    [int]$MaxTunnelTests = 30,
    [int]$TunnelWaitSec = 4,
    [switch]$CleanUpOnly
)

# -----------------------------------------------------------------------------
# GLOBAL CONSTANTS & CONFIGURATION
# -----------------------------------------------------------------------------
$ErrorActionPreference = "Stop"

$CLOUDFLARE_SUBNETS = @(
    "162.159.192.0/24",
    "162.159.193.0/24",
    "162.159.195.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24"
)

$WARP_PORTS = @(2408, 500, 4500, 1701, 854, 859, 864, 939)

$WORKING_DIR      = $PSScriptRoot
if (-not $WORKING_DIR) { $WORKING_DIR = Get-Location }

$CONFIG_DIR       = Join-Path $WORKING_DIR "WARP_Configs"
$SUCCESS_CONF_DIR = Join-Path $WORKING_DIR "Working_Configs"
$WGCF_EXE         = Join-Path $WORKING_DIR "wgcf.exe"
$WIREGUARD_PATH   = "C:\Program Files\WireGuard\wireguard.exe"

$CSV_OUTPUT_PATH  = Join-Path $WORKING_DIR "working_endpoints.csv"
$TXT_OUTPUT_PATH  = Join-Path $WORKING_DIR "working_endpoints.txt"

$script:ActiveTunnelName = $null

# -----------------------------------------------------------------------------
# HELPER FUNCTIONS & LOGGING
# -----------------------------------------------------------------------------
function Write-Header {
    param([string]$Message)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
}

function Write-Info {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Write-Err {
    param([string]$Message)
    Write-Host "[-] $Message" -ForegroundColor Red
}

# Cleanup leftover tunnel services
function Remove-WarpTunnelService {
    param(
        [string]$TunnelName,
        [string]$WireGuardExePath
    )

    if (-not $TunnelName) { return }

    Write-Info "Uninstalling tunnel service: '$TunnelName'..."
    try {
        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName = $WireGuardExePath
        $pinfo.Arguments = "/uninstalltunnelservice `"$TunnelName`""
        $pinfo.UseShellExecute = $false
        $pinfo.RedirectStandardOutput = $true
        $pinfo.RedirectStandardError = $true
        $pinfo.CreateNoWindow = $true

        $process = [System.Diagnostics.Process]::Start($pinfo)
        $finished = $process.WaitForExit(8000)

        if (-not $finished) {
            Write-Warn "Tunnel service uninstall command timed out. Killing process..."
            try { $process.Kill() } catch {}
        }
    } catch {
        Write-Warn "Error removing tunnel service '$TunnelName': $_"
    } finally {
        $script:ActiveTunnelName = $null
    }
}

# Global Exit / Interruption Handler
function Cleanup-All {
    if ($script:ActiveTunnelName) {
        Write-Warn "Script interrupted. Cleaning up active tunnel: $script:ActiveTunnelName"
        $wgExe = $script:ResolvedWgExe
        if (-not $wgExe) { $wgExe = $WIREGUARD_PATH }
        Remove-WarpTunnelService -TunnelName $script:ActiveTunnelName -WireGuardExePath $wgExe
    }
}

# Register CancelKeyPress trap
try {
    [Console]::TreatControlCAsInput = $false
    Register-EngineEvent -SourceIdentifier ([System.Management.Automation.PsEngineEvent]::Exiting) -Action { Cleanup-All } | Out-Null
} catch {}

# -----------------------------------------------------------------------------
# INTERACTIVE SELECTION MENU (When run without explicit switches)
# -----------------------------------------------------------------------------
if ($PSBoundParameters.Count -eq 0) {
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Cloudflare WARP Scanner by Tint Naing Win (@BadCodeWriter)" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  Select Scanning Mode:" -ForegroundColor White
    Write-Host "    [1] Standard Scan  (100 Threads, 30 Candidate Tunnel Tests)" -ForegroundColor Green
    Write-Host "    [2] Fast Scan      (150 Threads, 15 Candidate Tunnel Tests)" -ForegroundColor Yellow
    Write-Host "    [3] Deep Scan      (100 Threads, 60 Candidate Tunnel Tests)" -ForegroundColor Magenta
    Write-Host "    [4] Cleanup        (Remove leftover WireGuard tunnel services)" -ForegroundColor Cyan
    Write-Host "    [5] Exit" -ForegroundColor Red
    Write-Host ""
    
    $userChoice = Read-Host "  Enter choice [1-5] (Default is 1)"
    if (-not $userChoice) { $userChoice = "1" }

    switch ($userChoice.Trim()) {
        "2" {
            $PreScanThreads = 150
            $MaxTunnelTests = 15
        }
        "3" {
            $PreScanThreads = 100
            $MaxTunnelTests = 60
        }
        "4" {
            $CleanUpOnly = $true
        }
        "5" {
            Write-Host "  Exiting scanner script." -ForegroundColor Yellow
            exit 0
        }
        default {
            $PreScanThreads = 100
            $MaxTunnelTests = 30
        }
    }
}

# -----------------------------------------------------------------------------
# CLEANUP ONLY MODE
# -----------------------------------------------------------------------------
if ($CleanUpOnly) {
    Write-Header "WireGuard Cleanup Mode"
    $services = Get-Service -Name "WireGuardTunnel$*" -ErrorAction SilentlyContinue
    if ($services) {
        foreach ($svc in $services) {
            $tName = $svc.ServiceName.Replace("WireGuardTunnel$", "")
            Write-Warn "Found active leftover service: $($svc.ServiceName). Removing..."
            Remove-WarpTunnelService -TunnelName $tName -WireGuardExePath $WIREGUARD_PATH
        }
        Write-Success "All WireGuard tunnel services cleaned up."
    } else {
        Write-Info "No active WireGuard tunnel services found."
    }
    exit 0
}

# -----------------------------------------------------------------------------
# STEP 0: ENVIRONMENT PRE-CHECK
# -----------------------------------------------------------------------------
Write-Header "Step 0: Environment Pre-Check"

$preCheckPassed = $true

# --- Check 0.1: Active WireGuard tunnel services ---
Write-Info "Checking for active WireGuard tunnel services..."
$activeTunnels = Get-Service -Name "WireGuardTunnel$*" -ErrorAction SilentlyContinue |
                 Where-Object { $_.Status -eq "Running" }

if ($activeTunnels) {
    Write-Host "  [WARN] Active WireGuard tunnels found:" -ForegroundColor Yellow
    foreach ($t in $activeTunnels) {
        Write-Host "         $($t.ServiceName) ($($t.Status))" -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "  Having an active WireGuard tunnel will interfere with the scan." -ForegroundColor Yellow
    Write-Host "  The script installs its own test tunnels during Step 5." -ForegroundColor Yellow
    Write-Host "  Running two tunnels at the same time causes false failures." -ForegroundColor Yellow
    Write-Host ""
    $killChoice = Read-Host "  Type STOP to remove them now, or press Enter to continue anyway"
    if ($killChoice.Trim().ToUpper() -eq "STOP") {
        # Resolve WireGuard path early for cleanup
        $earlyWgPath = $WIREGUARD_PATH
        $cmdWgEarly = Get-Command "wireguard.exe" -ErrorAction SilentlyContinue
        if ($cmdWgEarly) { $earlyWgPath = $cmdWgEarly.Source }
        foreach ($t in $activeTunnels) {
            $tName = $t.ServiceName.Replace("WireGuardTunnel$", "")
            Remove-WarpTunnelService -TunnelName $tName -WireGuardExePath $earlyWgPath
        }
        Write-Success "Active tunnels removed. Continuing."
    } else {
        Write-Warn "Continuing with active tunnel. Results may be unreliable."
    }
} else {
    Write-Host "  [PASS] No active WireGuard tunnel services detected." -ForegroundColor Green
}

# --- Check 0.2: Active WARP app process ---
Write-Info "Checking for running Cloudflare WARP app process..."
$warpProc = Get-Process -Name "warp-svc","Cloudflare WARP" -ErrorAction SilentlyContinue
if ($warpProc) {
    Write-Host "  [WARN] Cloudflare WARP app is currently running." -ForegroundColor Yellow
    Write-Host "         Process: $($warpProc.Name -join ', ')" -ForegroundColor Yellow
    Write-Host "         Please disconnect from WARP in the system tray before scanning." -ForegroundColor Yellow
    Write-Host ""
    $warpChoice = Read-Host "  Press Enter to continue anyway or Ctrl+C to exit and disconnect WARP first"
    Write-Warn "Continuing with WARP app running. Tunnel tests may fail."
} else {
    Write-Host "  [PASS] No Cloudflare WARP app process detected." -ForegroundColor Green
}

# --- Check 0.3: Basic internet connectivity (ping 1.1.1.1) ---
Write-Info "Checking basic internet connectivity (ping 1.1.1.1)..."
try {
    $ping  = New-Object System.Net.NetworkInformation.Ping
    $reply = $ping.Send("1.1.1.1", 3000)
    if ($reply.Status -eq "Success") {
        Write-Host "  [PASS] Internet is reachable. Ping 1.1.1.1 replied in $($reply.RoundtripTime) ms." -ForegroundColor Green
    } else {
        Write-Host "  [WARN] Ping to 1.1.1.1 returned status: $($reply.Status)." -ForegroundColor Yellow
        Write-Host "         ICMP may be blocked on your network. Scan will still attempt TCP probes." -ForegroundColor Yellow
    }
} catch {
    Write-Host "  [WARN] Ping test failed: $_" -ForegroundColor Yellow
    Write-Host "         This may mean ICMP is blocked, not necessarily that internet is down." -ForegroundColor Yellow
}

# --- Check 0.4: DNS resolution test ---
Write-Info "Checking DNS resolution (resolving cloudflare.com)..."
try {
    $dns = [System.Net.Dns]::GetHostAddresses("cloudflare.com")
    if ($dns.Count -gt 0) {
        Write-Host "  [PASS] DNS working. cloudflare.com resolved to $($dns[0].ToString())." -ForegroundColor Green
    } else {
        Write-Host "  [WARN] DNS returned no addresses for cloudflare.com." -ForegroundColor Yellow
        $preCheckPassed = $false
    }
} catch {
    Write-Host "  [FAIL] DNS resolution failed. Cannot resolve cloudflare.com." -ForegroundColor Red
    Write-Host "         Your internet connection may not be working, or DNS is blocked." -ForegroundColor Yellow
    $preCheckPassed = $false
}

Write-Host ""
if ($preCheckPassed) {
    Write-Success "Pre-check complete. All critical checks passed. Proceeding with scan."
} else {
    Write-Warn "Pre-check complete. One or more checks failed. The scan may not produce results."
    Write-Host "  Check your network connection before continuing." -ForegroundColor Yellow
    Write-Host ""
    $proceed = Read-Host "  Type YES to proceed anyway or press Enter to exit"
    if ($proceed.Trim().ToUpper() -ne "YES") { exit 1 }
}

# -----------------------------------------------------------------------------
# STEP 1: PREREQUISITE & ENVIRONMENT CHECKS
# -----------------------------------------------------------------------------
try {
    Write-Header "Step 1: Prerequisite & Environment Checks"

    # 1.1 Admin Privileges Check
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Err "ADMINISTRATOR PRIVILEGES REQUIRED!"
        Write-Warn "This script installs/uninstalls temporary WireGuard tunnel services."
        Write-Warn "Please restart PowerShell as Administrator and run the script again."
        exit 1
    }
    Write-Success "Administrator privileges confirmed."

    # 1.2 WireGuard Executable Check
    $wgExePath = $WIREGUARD_PATH
    if (-not (Test-Path $wgExePath)) {
        $cmdWg = Get-Command "wireguard.exe" -ErrorAction SilentlyContinue
        if ($cmdWg) {
            $wgExePath = $cmdWg.Source
        } else {
            Write-Err "WireGuard executable NOT found at '$WIREGUARD_PATH' or system PATH!"
            Write-Warn "Please install WireGuard for Windows from: https://www.wireguard.com/install/"
            exit 1
        }
    }
    $script:ResolvedWgExe = $wgExePath
    Write-Success "WireGuard binary verified: $wgExePath"

    # 1.3 wgcf.exe Check & Automatic Download
    if (-not (Test-Path $WGCF_EXE)) {
        Write-Warn "wgcf.exe not found in working directory ($WORKING_DIR)."
        Write-Info "Attempting to auto-download latest wgcf release from GitHub..."

        # Enable TLS 1.2 / 1.3
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13

        $githubApiUrl = "https://api.github.com/repos/ViRb3/wgcf/releases/latest"
        $headers = @{ "User-Agent" = "PowerShell-WARP-Scanner" }
        $release = Invoke-RestMethod -Uri $githubApiUrl -Headers $headers -ErrorAction Stop

        $arch = "amd64"
        if ($env:PROCESSOR_ARCHITECTURE -match "ARM64") {
            $arch = "arm64"
        } elseif ($env:PROCESSOR_ARCHITECTURE -match "x86") {
            $arch = "386"
        }

        $asset = $release.assets | Where-Object { $_.name -like "*windows*$arch*.exe" } | Select-Object -First 1

        if (-not $asset) {
            # Fallback to any windows exe
            $asset = $release.assets | Where-Object { $_.name -like "*windows*.exe" } | Select-Object -First 1
        }

        if (-not $asset) {
            throw "Failed to locate a compatible Windows release binary for wgcf on GitHub."
        }

        Write-Info "Downloading '$($asset.name)' from $($asset.browser_download_url)..."
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $WGCF_EXE -UseBasicParsing
        Write-Success "wgcf.exe downloaded successfully to $WGCF_EXE"
    } else {
        Write-Success "wgcf.exe verified in working directory."
    }

} catch {
    Write-Err "Prerequisite check failed: $_"
    exit 1
}

# -----------------------------------------------------------------------------
# STEP 2: CLOUDFLARE ACCOUNT REGISTRATION & PROFILE PARSING
# -----------------------------------------------------------------------------

# Internal helper: tests if a TCP connection to a host:port can be opened
function Test-TcpReachable {
    param([string]$Hostname, [int]$Port, [int]$TimeoutMs = 4000)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $ar  = $tcp.BeginConnect($Hostname, $Port, $null, $null)
        $ok  = $ar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($ok -and $tcp.Connected) {
            $tcp.Close()
            return $true
        }
        $tcp.Close()
        return $false
    } catch {
        return $false
    }
}

# Internal helper: tries to parse a profile file and returns a hashtable or $null
function Read-WgcfProfile {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    $raw = Get-Content -Path $Path -Raw
    $pk  = if ($raw -match "PrivateKey\s*=\s*(.+)") { $matches[1].Trim() } else { $null }
    $ad  = if ($raw -match "Address\s*=\s*(.+)")    { $matches[1].Trim() } else { $null }
    $dn  = if ($raw -match "DNS\s*=\s*(.+)")        { $matches[1].Trim() } else { $null }
    $pub = if ($raw -match "PublicKey\s*=\s*(.+)")  { $matches[1].Trim() } else { $null }
    $res = if ($raw -match "Reserved\s*=\s*(.+)")   { $matches[1].Trim() } else { $null }
    if (-not $pk -or -not $pub -or -not $ad) { return $null }
    return @{ PrivateKey = $pk; Address = $ad; DNS = $dn; PublicKey = $pub; Reserved = $res }
}

try {
    Write-Header "Step 2: Cloudflare Account Registration & Key Extraction"

    $accountFile = Join-Path $WORKING_DIR "wgcf-account.toml"
    $profileFile = Join-Path $WORKING_DIR "wgcf-profile.conf"

    # ------------------------------------------------------------------
    # FAST PATH: existing valid profile from a previous run
    # If the user already has a working wgcf-profile.conf, skip everything.
    # ------------------------------------------------------------------
    $existingProfile = Read-WgcfProfile -Path $profileFile
    if ($existingProfile) {
        Write-Success "Existing valid wgcf-profile.conf found. Skipping registration."
    } else {
        # ------------------------------------------------------------------
        # PRE-CHECK: test API reachability BEFORE running wgcf
        # This gives a clean, instant error instead of waiting for wgcf to
        # fail with a cryptic Go stack trace.
        # ------------------------------------------------------------------
        Write-Info "Checking reachability of api.cloudflareclient.com before registration..."
        $apiReachable = Test-TcpReachable -Hostname "api.cloudflareclient.com" -Port 443 -TimeoutMs 5000

        if (-not $apiReachable) {
            Write-Host ""
            Write-Warn "Cannot reach api.cloudflareclient.com on port 443."
            Write-Host ""
            Write-Host "  What this means:" -ForegroundColor Yellow
            Write-Host "  Your current network is blocking Cloudflare's WARP registration server." -ForegroundColor Yellow
            Write-Host "  wgcf cannot create a new account without reaching this server." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  Your options:" -ForegroundColor Cyan
            Write-Host "  A) Switch to mobile hotspot, run this script there once, then copy" -ForegroundColor Cyan
            Write-Host "     wgcf-account.toml back to this folder and run the script again." -ForegroundColor Cyan
            Write-Host "  B) Ask someone on an open network to run wgcf register and send" -ForegroundColor Cyan
            Write-Host "     you their wgcf-account.toml file." -ForegroundColor Cyan
            Write-Host "  C) Place an existing wgcf-profile.conf in this folder and run again." -ForegroundColor Cyan
            Write-Host ""

            $choice = Read-Host "  Press Enter to exit, or type SKIP to try registration anyway"
            if ($choice.Trim().ToUpper() -ne "SKIP") {
                exit 1
            }
            Write-Warn "Skipping pre-check. Attempting registration anyway..."
        } else {
            Write-Success "api.cloudflareclient.com is reachable. Proceeding with registration."
        }

        # ------------------------------------------------------------------
        # REGISTRATION
        # ------------------------------------------------------------------
        if (-not (Test-Path $accountFile)) {
            Write-Info "Registering new Cloudflare WARP account via wgcf..."

            $pinfo = New-Object System.Diagnostics.ProcessStartInfo
            $pinfo.FileName        = $WGCF_EXE
            $pinfo.Arguments       = "register --accept-tos"
            $pinfo.WorkingDirectory = $WORKING_DIR
            $pinfo.UseShellExecute  = $false
            $pinfo.RedirectStandardOutput = $true
            $pinfo.RedirectStandardError  = $true

            $proc   = [System.Diagnostics.Process]::Start($pinfo)
            $stdOut = $proc.StandardOutput.ReadToEnd()
            $stdErr = $proc.StandardError.ReadToEnd()
            $registerFinished = $proc.WaitForExit(25000)
            $combined = "$stdOut $stdErr"

            if (-not $registerFinished) {
                try { $proc.Kill() } catch {}
                Write-Err "Registration timed out after 25 seconds."
                Write-Host ""
                Write-Host "  The network is responding but very slowly. This often means" -ForegroundColor Yellow
                Write-Host "  the ISP is throttling rather than outright blocking the connection." -ForegroundColor Yellow
                Write-Host "  Try on a different network or wait a few minutes and try again." -ForegroundColor Cyan
                exit 1
            }

            if ($proc.ExitCode -ne 0) {
                Write-Host ""
                Write-Host "  Registration failed. Reading error output..." -ForegroundColor Yellow
                Write-Host ""

                if ($combined -match "refused|connectex|No connection could be made|actively refused") {
                    Write-Err "Connection was actively refused by the ISP or network firewall."
                    Write-Host ""
                    Write-Host "  The pre-check passed but the actual registration was blocked." -ForegroundColor Yellow
                    Write-Host "  The ISP may be doing deep packet inspection and blocking" -ForegroundColor Yellow
                    Write-Host "  specifically the /reg API path while allowing other HTTPS traffic." -ForegroundColor Yellow
                    Write-Host ""
                    Write-Host "  Option A: Switch to mobile hotspot and run this script there first." -ForegroundColor Cyan
                    Write-Host "  Option B: Place someone else's wgcf-account.toml here and rerun." -ForegroundColor Cyan
                    Write-Host "  Option C: Place a ready wgcf-profile.conf here and rerun." -ForegroundColor Cyan
                }
                elseif ($combined -match "timeout|timed out|deadline|context deadline") {
                    Write-Err "Registration connection timed out while waiting for a response."
                    Write-Host ""
                    Write-Host "  The server was reached but did not respond in time." -ForegroundColor Yellow
                    Write-Host "  Try again in a few minutes, or switch to mobile hotspot." -ForegroundColor Cyan
                }
                elseif ($combined -match "TLS|certificate|x509|ssl|handshake") {
                    Write-Err "TLS handshake failed. A proxy or firewall is intercepting HTTPS."
                    Write-Host ""
                    Write-Host "  Something between your computer and Cloudflare is intercepting" -ForegroundColor Yellow
                    Write-Host "  the encrypted connection. This could be a corporate firewall," -ForegroundColor Yellow
                    Write-Host "  antivirus SSL scanning, or a network proxy." -ForegroundColor Yellow
                    Write-Host ""
                    Write-Host "  Try disabling any antivirus SSL scanning or switch to mobile hotspot." -ForegroundColor Cyan
                }
                elseif ($combined -match "rate limit|too many|429") {
                    Write-Err "Cloudflare rate-limited this registration attempt."
                    Write-Host ""
                    Write-Host "  Too many registration attempts were made from this IP recently." -ForegroundColor Yellow
                    Write-Host "  Wait 10 to 15 minutes and try again." -ForegroundColor Cyan
                }
                else {
                    Write-Err "wgcf register failed with an unrecognised error."
                    Write-Host ""
                    Write-Host "  Error output:" -ForegroundColor Yellow
                    Write-Host "  $combined" -ForegroundColor DarkGray
                }

                exit 1
            }

            Write-Success "Cloudflare WARP account registered successfully."

        } else {
            Write-Success "Existing wgcf-account.toml found. Skipping registration step."
        }

        # ------------------------------------------------------------------
        # PROFILE GENERATION
        # ------------------------------------------------------------------
        Write-Info "Generating WireGuard profile via wgcf..."

        $pinfo = New-Object System.Diagnostics.ProcessStartInfo
        $pinfo.FileName        = $WGCF_EXE
        $pinfo.Arguments       = "generate"
        $pinfo.WorkingDirectory = $WORKING_DIR
        $pinfo.UseShellExecute  = $false
        $pinfo.RedirectStandardOutput = $true
        $pinfo.RedirectStandardError  = $true

        $proc        = [System.Diagnostics.Process]::Start($pinfo)
        $genFinished = $proc.WaitForExit(15000)
        $genErr      = $proc.StandardError.ReadToEnd()

        if (-not $genFinished) {
            try { $proc.Kill() } catch {}
            Write-Err "Profile generation timed out."
            Write-Host "  Delete wgcf-account.toml and run again to start fresh." -ForegroundColor Cyan
            exit 1
        }

        if (-not (Test-Path $profileFile)) {
            Write-Err "wgcf generate ran but wgcf-profile.conf was not created."
            Write-Host ""
            Write-Host "  The account file may be corrupt or the account may have been revoked." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  Delete wgcf-account.toml from this folder and run the script again" -ForegroundColor Cyan
            Write-Host "  to register a fresh account." -ForegroundColor Cyan
            if ($genErr) { Write-Host "  Raw error: $genErr" -ForegroundColor DarkGray }
            exit 1
        }

        Write-Success "wgcf-profile.conf generated."
        $existingProfile = Read-WgcfProfile -Path $profileFile

        if (-not $existingProfile) {
            Write-Err "Profile file was created but is missing required keys."
            Write-Host ""
            Write-Host "  Delete both wgcf-account.toml and wgcf-profile.conf and run again." -ForegroundColor Cyan
            exit 1
        }
    }

    # ------------------------------------------------------------------
    # EXPOSE PARSED KEYS TO THE REST OF THE SCRIPT
    # ------------------------------------------------------------------
    $privateKey = $existingProfile.PrivateKey
    $address    = $existingProfile.Address
    $dns        = $existingProfile.DNS
    $publicKey  = $existingProfile.PublicKey
    $reserved   = $existingProfile.Reserved

    Write-Success "Profile keys loaded."
    Write-Host "   Address   : $address"  -ForegroundColor Gray
    Write-Host "   DNS       : $dns"      -ForegroundColor Gray
    Write-Host "   PublicKey : $publicKey" -ForegroundColor Gray
    if ($reserved) { Write-Host "   Reserved  : $reserved" -ForegroundColor Gray }

} catch {
    Write-Err "Step 2 failed unexpectedly: $_"
    exit 1
}


# -----------------------------------------------------------------------------
# STEP 3: MASS ENDPOINT GENERATION & RUNSPACE PRE-SCAN
# -----------------------------------------------------------------------------
try {
    Write-Header "Step 3: Mass Target Generation & Fast Multithreaded Pre-Scan"

    # 3.1 Subnet Expansion
    $targetCandidates = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($subnet in $CLOUDFLARE_SUBNETS) {
        $parts = $subnet.Split('/')
        $baseIp = $parts[0]
        $mask   = [int]$parts[1]

        if ($mask -eq 24) {
            $octets = $baseIp.Split('.')
            $prefix = "$($octets[0]).$($octets[1]).$($octets[2])"
            
            # Scan host IPs .1 to .254
            for ($i = 1; $i -le 254; $i++) {
                $ip = "$prefix.$i"
                foreach ($port in $WARP_PORTS) {
                    $targetCandidates.Add([PSCustomObject]@{
                        IP       = $ip
                        Port     = $port
                        Endpoint = "$ip`:$port"
                    })
                }
            }
        }
    }

    $totalCandidates = $targetCandidates.Count
    Write-Info "Generated $totalCandidates candidate IP:Port combinations from Cloudflare ranges."
    Write-Info "Starting fast multi-threaded pre-scan (Threads: $PreScanThreads, Timeout: ${PreScanTimeoutMs}ms)..."

    # 3.2 RunspacePool Multithreaded Scanner
    $iss = [initialsessionstate]::CreateDefault()
    $pool = [runspacefactory]::CreateRunspacePool(1, $PreScanThreads, $iss, $Host)
    $pool.Open()

    $scriptBlock = {
        param($ip, $port, $timeoutMs)

        $result = [PSCustomObject]@{
            IP         = $ip
            Port       = $port
            Endpoint   = "$ip`:$port"
            Reachable  = $false
            LatencyMs  = 9999
        }

        # 1. Fast UDP Socket Probe
        try {
            $udpClient = New-Object System.Net.Sockets.UdpClient
            $udpClient.Client.ReceiveTimeout = $timeoutMs
            $udpClient.Client.SendTimeout    = $timeoutMs

            # Connect socket
            $udpClient.Connect($ip, $port)

            # Send a 32-byte probe payload (WireGuard handshake dummy or probe)
            $probeBytes = [byte[]](0x01,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00)
            
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $udpClient.Send($probeBytes, $probeBytes.Length) | Out-Null
            $sw.Stop()

            $udpClient.Close()
            $result.Reachable = $true
            $result.LatencyMs = [math]::Round($sw.Elapsed.TotalMilliseconds, 2)
        } catch {
            # Socket fallback check via ICMP Ping
            try {
                $ping = New-Object System.Net.NetworkInformation.Ping
                $reply = $ping.Send($ip, $timeoutMs)
                if ($reply.Status -eq 'Success') {
                    $result.Reachable = $true
                    $result.LatencyMs = $reply.RoundtripTime
                }
            } catch {}
        }

        return $result
    }

    $jobs = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($item in $targetCandidates) {
        $powershell = [powershell]::Create().AddScript($scriptBlock).AddArgument($item.IP).AddArgument($item.Port).AddArgument($PreScanTimeoutMs)
        $powershell.RunspacePool = $pool
        $jobs.Add([PSCustomObject]@{
            Pipe   = $powershell
            Handle = $powershell.BeginInvoke()
        })
    }

    # Collect Results with Progress Bar
    $responsiveEndpoints = [System.Collections.Generic.List[PSCustomObject]]::new()
    $completedCount = 0

    while ($jobs.Count -gt 0) {
        for ($i = $jobs.Count - 1; $i -ge 0; $i--) {
            $job = $jobs[$i]
            if ($job.Handle.IsCompleted) {
                $res = $job.Pipe.EndInvoke($job.Handle)
                $job.Pipe.Dispose()
                $jobs.RemoveAt($i)

                $completedCount++
                if ($res -and $res.Reachable) {
                    $responsiveEndpoints.Add($res[0])
                }

                if ($completedCount % 500 -eq 0 -or $completedCount -eq $totalCandidates) {
                    $percent = [math]::Round(($completedCount / $totalCandidates) * 100, 1)
                    Write-Progress -Activity "Pre-scanning Cloudflare WARP Endpoints" -Status "$completedCount / $totalCandidates ($percent%) completed | Found: $($responsiveEndpoints.Count)" -PercentComplete $percent
                }
            }
        }
        Start-Sleep -Milliseconds 50
    }

    $pool.Close()
    $pool.Dispose()
    Write-Progress -Activity "Pre-scanning Cloudflare WARP Endpoints" -Completed

    Write-Success "Pre-scan complete! Found $($responsiveEndpoints.Count) responsive IP:Port candidates out of $totalCandidates scanned."

    if ($responsiveEndpoints.Count -eq 0) {
        Write-Warn "No endpoints responded to initial pre-scan probe."
        Write-Warn "Selecting top candidate IP:Port combinations as fallback targets..."
        # Fallback select first N candidates with default ports 2408, 500, 4500
        $fallbackTargets = $targetCandidates | Where-Object { $_.Port -in @(2408, 500, 4500) } | Select-Object -First $MaxTunnelTests
        foreach ($fb in $fallbackTargets) {
            $responsiveEndpoints.Add([PSCustomObject]@{
                IP        = $fb.IP
                Port      = $fb.Port
                Endpoint  = $fb.Endpoint
                Reachable = $true
                LatencyMs = 999
            })
        }
    }

} catch {
    Write-Err "Pre-scan stage failed: $_"
    exit 1
}

# -----------------------------------------------------------------------------
# STEP 4: BATCH CONFIGURATION GENERATION
# -----------------------------------------------------------------------------
try {
    Write-Header "Step 4: Batch Configuration File Generation"

    if (-not (Test-Path $CONFIG_DIR)) {
        New-Item -ItemType Directory -Path $CONFIG_DIR -Force | Out-Null
    }
    if (-not (Test-Path $SUCCESS_CONF_DIR)) {
        New-Item -ItemType Directory -Path $SUCCESS_CONF_DIR -Force | Out-Null
    }

    # Sort pre-scan endpoints by latency and select top candidate limit
    $topCandidates = $responsiveEndpoints | Sort-Object LatencyMs | Select-Object -First $MaxTunnelTests

    Write-Info "Generating WireGuard configuration files in '$CONFIG_DIR' for $($topCandidates.Count) top candidates..."

    $generatedConfs = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($cand in $topCandidates) {
        # Safe filename escaping for IP and Port
        $safeIpName = $cand.IP -replace '\.', '_'
        $confFileName = "warp_${safeIpName}_$($cand.Port).conf"
        $confFilePath = Join-Path $CONFIG_DIR $confFileName

        $reservedLine = if ($reserved) { "Reserved = $reserved`n" } else { "" }

        $confText = @"
[Interface]
PrivateKey = $privateKey
Address = $address
DNS = $dns
${reservedLine}
[Peer]
PublicKey = $publicKey
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $($cand.Endpoint)
"@
        Set-Content -Path $confFilePath -Value $confText -Encoding ASCII -Force

        $generatedConfs.Add([PSCustomObject]@{
            Endpoint     = $cand.Endpoint
            IP           = $cand.IP
            Port         = $cand.Port
            ConfPath     = $confFilePath
            ConfName     = [System.IO.Path]::GetFileNameWithoutExtension($confFileName)
            InitLatency  = $cand.LatencyMs
        })
    }

    Write-Success "Generated $($generatedConfs.Count) configuration files in $CONFIG_DIR."

} catch {
    Write-Err "Configuration file generation failed: $_"
    exit 1
}

# -----------------------------------------------------------------------------
# STEP 5: AUTOMATED TUNNEL CONNECTION VERIFICATION LOOP
# -----------------------------------------------------------------------------
$verifiedEndpoints = [System.Collections.Generic.List[PSCustomObject]]::new()

try {
    Write-Header "Step 5: Active WireGuard Tunnel Connectivity Testing"
    Write-Info "Testing $($generatedConfs.Count) candidates with active tunnel service creation..."
    Write-Info "Tunnel Wait Time: ${TunnelWaitSec}s per configuration."

    $testIndex = 0
    foreach ($item in $generatedConfs) {
        $testIndex++
        $tunnelName = $item.ConfName
        $confPath   = $item.ConfPath
        $endpoint   = $item.Endpoint

        Write-Host ""
        Write-Host "[$testIndex/$($generatedConfs.Count)] Testing Endpoint: $endpoint ($tunnelName)" -ForegroundColor Yellow

        $script:ActiveTunnelName = $tunnelName

        # 5.1 Install and Start WireGuard Tunnel Service
        try {
            $pinfo = New-Object System.Diagnostics.ProcessStartInfo
            $pinfo.FileName = $script:ResolvedWgExe
            $pinfo.Arguments = "/installtunnelservice `"$confPath`""
            $pinfo.UseShellExecute = $false
            $pinfo.RedirectStandardOutput = $true
            $pinfo.RedirectStandardError = $true
            $pinfo.CreateNoWindow = $true

            $proc = [System.Diagnostics.Process]::Start($pinfo)
            $finished = $proc.WaitForExit(10000)

            if (-not $finished) {
                Write-Warn "Tunnel service install timed out for $endpoint. Killing process..."
                try { $proc.Kill() } catch {}
                Remove-WarpTunnelService -TunnelName $tunnelName -WireGuardExePath $script:ResolvedWgExe
                continue
            }
        } catch {
            Write-Warn "Failed to launch tunnel service for $($endpoint): $_"
            Remove-WarpTunnelService -TunnelName $tunnelName -WireGuardExePath $script:ResolvedWgExe
            continue
        }

        # 5.2 Wait for Handshake & Interface Initialization
        Write-Info "Waiting ${TunnelWaitSec}s for handshake completion..."
        Start-Sleep -Seconds $TunnelWaitSec

        # 5.3 Validation Checks
        $pingSuccess = $false
        $avgPingRtt  = 9999
        $traceResult = "OFF"
        $warpStatus  = "OFF"
        $colo        = "N/A"

        # Check 1: ICMP Ping to 1.1.1.1 through tunnel
        try {
            $ping = New-Object System.Net.NetworkInformation.Ping
            $rtts = @()
            for ($p = 1; $p -le 3; $p++) {
                $reply = $ping.Send("1.1.1.1", 2000)
                if ($reply.Status -eq 'Success') {
                    $rtts += $reply.RoundtripTime
                }
                Start-Sleep -Milliseconds 150
            }

            if ($rtts.Count -gt 0) {
                $pingSuccess = $true
                $avgPingRtt  = [math]::Round(($rtts | Measure-Object -Average).Average, 1)
            }
        } catch {}

        # Check 2: HTTP Request to Cloudflare Trace Endpoint
        if ($pingSuccess) {
            try {
                [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
                $req = [System.Net.HttpWebRequest]::Create("https://www.cloudflare.com/cdn-cgi/trace")
                $req.Timeout = 3000
                $req.ReadWriteTimeout = 3000
                $req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"

                $resp = $req.GetResponse()
                $stream = $resp.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $traceText = $reader.ReadToEnd()
                $reader.Close()
                $resp.Close()

                if ($traceText -match "warp=(on|plus)") {
                    $warpStatus = $matches[1]
                }
                if ($traceText -match "colo=([A-Z]+)") {
                    $colo = $matches[1]
                }
            } catch {
                Write-Warn "HTTP trace request check failed: $_"
            }
        }

        # 5.4 Evaluate Tunnel Health
        if ($pingSuccess -and ($warpStatus -eq "on" -or $warpStatus -eq "plus")) {
            Write-Success "VALID WARP ENDPOINT FOUND!"
            Write-Host "   - Endpoint   : $endpoint" -ForegroundColor Green
            Write-Host "   - Ping 1.1.1.1: SUCCESS ($avgPingRtt ms)" -ForegroundColor Green
            Write-Host "   - WARP Trace : $warpStatus (Colo: $colo)" -ForegroundColor Green

            # Copy successful config to Working_Configs folder
            $destWorkingConf = Join-Path $SUCCESS_CONF_DIR ([System.IO.Path]::GetFileName($confPath))
            Copy-Item -Path $confPath -Destination $destWorkingConf -Force

            $verifiedEndpoints.Add([PSCustomObject]@{
                Endpoint   = $endpoint
                IP         = $item.IP
                Port       = $item.Port
                LatencyMs  = $avgPingRtt
                WarpStatus = $warpStatus
                Location   = $colo
                ConfigFile = [System.IO.Path]::GetFileName($confPath)
            })
        } else {
            Write-Err "Tunnel validation failed for $endpoint (Ping: $pingSuccess, WARP Trace: $warpStatus)"
        }

        # 5.5 Uninstall Tunnel Service & Interface Cleanup Delay
        Remove-WarpTunnelService -TunnelName $tunnelName -WireGuardExePath $script:ResolvedWgExe
        Start-Sleep -Seconds 2
    }

} catch {
    Write-Err "Tunnel verification loop interrupted: $_"
} finally {
    Cleanup-All
}

# -----------------------------------------------------------------------------
# STEP 6: REPORTING, SORTING & OUTPUT EXPORT
# -----------------------------------------------------------------------------
Write-Header "Step 6: Results Summary & File Export"

if ($verifiedEndpoints.Count -gt 0) {
    # Sort endpoints by latency ascending
    $sortedResults = $verifiedEndpoints | Sort-Object LatencyMs

    Write-Success "Found $($sortedResults.Count) working Cloudflare WARP endpoints!"
    Write-Host ""
    Write-Host "Top Performing Endpoints:" -ForegroundColor Yellow
    Write-Host ("{0,-22} {1,-12} {2,-12} {3,-10} {4,-25}" -f "Endpoint", "Latency (ms)", "WARP Status", "DataCenter", "Config File") -ForegroundColor Cyan
    Write-Host ("-" * 82) -ForegroundColor Gray

    foreach ($res in $sortedResults) {
        Write-Host ("{0,-22} {1,-12} {2,-12} {3,-10} {4,-25}" -f $res.Endpoint, $res.LatencyMs, $res.WarpStatus, $res.Location, $res.ConfigFile) -ForegroundColor Green
    }

    # Export to CSV
    $sortedResults | Export-Csv -Path $CSV_OUTPUT_PATH -NoTypeInformation -Encoding UTF8 -Force
    Write-Success "Exported CSV summary to: $CSV_OUTPUT_PATH"

    # Export to TXT
    $txtLines = @(
        "# Cloudflare WARP Working Endpoints - Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
        "# Total Verified: $($sortedResults.Count)",
        "#" + ("-" * 60)
    )
    foreach ($res in $sortedResults) {
        $txtLines += "$($res.Endpoint) | Latency: $($res.LatencyMs) ms | WARP: $($res.WarpStatus) | Datacenter: $($res.Location) | Config: $($res.ConfigFile)"
    }
    Set-Content -Path $TXT_OUTPUT_PATH -Value $txtLines -Encoding UTF8 -Force
    Write-Success "Exported TXT summary to: $TXT_OUTPUT_PATH"

    Write-Success "Saved working WireGuard configuration files to: $SUCCESS_CONF_DIR"

} else {
    Write-Warn "No endpoints passed active tunnel verification."
    Write-Info "You may try running the script again with a higher -PreScanTimeoutMs or check your network/firewall."
}

Write-Header "Execution Completed"
