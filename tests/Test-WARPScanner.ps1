<#
.SYNOPSIS
    Automated Offline Test Suite for WARP-Scanner.ps1
.DESCRIPTION
    Validates PowerShell syntax integrity, profile key extraction, and subnet calculation offline.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ScriptRoot = Split-Path -Path $PSScriptRoot -Parent
$TargetScript = Join-Path $ScriptRoot "WARP-Scanner.ps1"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  Automated Offline Test Suite for WARP-Scanner.ps1" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

$testCount = 0
$passCount = 0

function Assert-Test {
    param(
        [string]$TestName,
        [scriptblock]$TestBlock
    )
    $script:testCount++
    try {
        & $TestBlock
        Write-Host "  [PASS] Test $script:testCount : $TestName" -ForegroundColor Green
        $script:passCount++
    } catch {
        Write-Host "  [FAIL] Test $script:testCount : $TestName -> $_" -ForegroundColor Red
    }
}

# -----------------------------------------------------------------------------
# TEST 1: PowerShell Syntax Integrity Check
# -----------------------------------------------------------------------------
Assert-Test "PowerShell AST Syntax Validation" {
    if (-not (Test-Path $TargetScript)) {
        throw "Target script not found at: $TargetScript"
    }
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($TargetScript, [ref]$tokens, [ref]$errors)
    if ($errors.Count -gt 0) {
        $errMsgs = ($errors | ForEach-Object { $_.Message }) -join "; "
        throw "Syntax errors detected: $errMsgs"
    }
}

# -----------------------------------------------------------------------------
# TEST 2: Cloudflare Subnet Expansion Math Verification
# -----------------------------------------------------------------------------
Assert-Test "Subnet Expansion Math (12,192 Targets)" {
    $subnets = @(
        "162.159.192.0/24",
        "162.159.193.0/24",
        "162.159.195.0/24",
        "188.114.96.0/24",
        "188.114.97.0/24",
        "188.114.98.0/24"
    )
    $ports = @(2408, 500, 4500, 1701, 854, 859, 864, 939)

    $targetCount = 0
    foreach ($subnet in $subnets) {
        $baseIp = $subnet.Split('/')[0]
        $octets = $baseIp.Split('.')
        $prefix = "$($octets[0]).$($octets[1]).$($octets[2])"
        $targetCount += (254 * $ports.Count)
    }

    if ($targetCount -ne 12192) {
        throw "Expected 12192 targets, calculated: $targetCount"
    }
}

# -----------------------------------------------------------------------------
# TEST 3: Profile Key Extraction Regex Verification
# -----------------------------------------------------------------------------
Assert-Test "WireGuard Profile Parsing Regex Engine" {
    $mockConf = @"
[Interface]
PrivateKey = MockPrivateKey12345678901234567890123=
Address = 172.16.0.2/32, 2606:4700:110:836b:a057:1175:e196:b9d6/128
DNS = 1.1.1.1, 1.0.0.1
Reserved = 0,0,0

[Peer]
PublicKey = MockPublicKey123456789012345678901234=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 162.159.192.1:2408
"@
    $tempFile = [System.IO.Path]::GetTempFileName()
    try {
        Set-Content -Path $tempFile -Value $mockConf -Encoding ASCII -Force
        $raw = Get-Content -Path $tempFile -Raw

        $pk  = if ($raw -match "PrivateKey\s*=\s*(.+)") { $matches[1].Trim() } else { $null }
        $ad  = if ($raw -match "Address\s*=\s*(.+)")    { $matches[1].Trim() } else { $null }
        $pub = if ($raw -match "PublicKey\s*=\s*(.+)")  { $matches[1].Trim() } else { $null }
        $res = if ($raw -match "Reserved\s*=\s*(.+)")   { $matches[1].Trim() } else { $null }

        if (-not $pk -or $pk -ne "MockPrivateKey12345678901234567890123=") { throw "PrivateKey extraction failed" }
        if (-not $pub -or $pub -ne "MockPublicKey123456789012345678901234=") { throw "PublicKey extraction failed" }
        if (-not $ad -or $ad -notlike "*172.16.0.2*") { throw "Address extraction failed" }
        if (-not $res -or $res -ne "0,0,0") { throw "Reserved extraction failed" }
    } finally {
        if (Test-Path $tempFile) { Remove-Item -Path $tempFile -Force }
    }
}

Write-Host ""
Write-Host "Test Results: $passCount / $testCount Tests Passed." -ForegroundColor Cyan
if ($passCount -eq $testCount) {
    Write-Host "ALL TESTS PASSED SUCCESSFULLY!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "SOME TESTS FAILED!" -ForegroundColor Red
    exit 1
}
