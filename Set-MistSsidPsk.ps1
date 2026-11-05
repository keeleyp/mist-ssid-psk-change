<#
.SYNOPSIS
    Change the PSK (pre-shared key) of a single Juniper Mist WLAN.

.DESCRIPTION
    Reads cloud, API token, org ID and WLAN ID from an .ini file, fetches the
    WLAN, shows its SSID and current PSK, prompts for a new PSK (entered twice),
    asks for confirmation, writes the change and reads the WLAN back to verify.

.PARAMETER IniPath
    Path to the settings file. Defaults to mist_ssid_psk_change.ini next to
    this script.

.PARAMETER NewPsk
    Optional. The new PSK. When given, the script runs non-interactively:
    no prompts, no confirmation, and the only output is the completion line
    (or an error).

.EXAMPLE
    ./Set-MistSsidPsk.ps1
    ./Set-MistSsidPsk.ps1 -IniPath .\Customer_A.ini
    ./Set-MistSsidPsk.ps1 -NewPsk 'Summer2026!Guest'
#>
[CmdletBinding()]
param(
    [string]$IniPath = (Join-Path $PSScriptRoot 'mist_ssid_psk_change.ini'),
    [string]$NewPsk
)

$Quiet = $PSBoundParameters.ContainsKey('NewPsk')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- helpers ---

function Fail([string]$Message) {
    Write-Host "ERROR: $Message" -ForegroundColor Red
    exit 1
}

function Read-IniFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        Fail "Settings file not found: $Path`n       Copy mist_ssid_psk_change.ini.example to mist_ssid_psk_change.ini and fill it in."
    }
    $ini = @{}
    $section = ''
    foreach ($raw in Get-Content -LiteralPath $Path) {
        $line = $raw.Trim()
        if ($line -eq '' -or $line.StartsWith(';') -or $line.StartsWith('#')) { continue }
        if ($line -match '^\[(.+)\]$') {
            $section = $Matches[1].Trim().ToLower()
            if (-not $ini.ContainsKey($section)) { $ini[$section] = @{} }
            continue
        }
        if ($line -match '^([^=]+)=(.*)$') {
            if ($section -eq '') { Fail "Key '$($Matches[1].Trim())' in $Path is outside any [section]." }
            $ini[$section][$Matches[1].Trim().ToLower()] = $Matches[2].Trim()
        }
    }
    return $ini
}

function Get-IniValue($Ini, [string]$Section, [string]$Key, [switch]$Required) {
    $value = ''
    if ($Ini.ContainsKey($Section) -and $Ini[$Section].ContainsKey($Key)) { $value = $Ini[$Section][$Key] }
    if ($Required -and [string]::IsNullOrWhiteSpace($value)) { Fail "[$Section] $Key is missing or empty in the .ini file." }
    return $value
}

function Resolve-ApiHost([string]$Cloud) {
    $c = $Cloud.Trim().ToLower() -replace '^https?://', '' -replace '/.*$', ''
    if ($c -match '\.') {
        # Full hostname supplied; accept manage.* or api.* forms.
        return ($c -replace '^manage\.', 'api.')
    }
    if ($c -in @('global01', 'us', 'global', 'mist')) { return 'api.mist.com' }
    return "api.$c.mist.com"
}

function Test-Bool([string]$Value, [bool]$Default) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return $Default }
    return $Value.Trim().ToLower() -in @('true', 'yes', '1', 'on')
}

function Invoke-Mist([string]$Method, [string]$Path, $Body = $null) {
    $params = @{
        Method      = $Method
        Uri         = "$script:BaseUrl$Path"
        Headers     = @{ Authorization = "Token $script:Token"; Accept = 'application/json' }
        ContentType = 'application/json'
    }
    if ($null -ne $Body)  { $params.Body = ($Body | ConvertTo-Json -Depth 20 -Compress) }
    if ($script:Proxy)    { $params.Proxy = $script:Proxy }
    if ($script:ProxyDefaultCreds) { $params.ProxyUseDefaultCredentials = $true }
    if (-not $script:VerifySsl -and $PSVersionTable.PSVersion.Major -ge 6) { $params.SkipCertificateCheck = $true }

    try {
        return Invoke-RestMethod @params
    }
    catch {
        $status = $null
        if ($_.Exception.PSObject.Properties['Response'] -and $_.Exception.Response) {
            $status = [int]$_.Exception.Response.StatusCode
        }
        $detail = if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }

        if ($null -eq $status) {
            # Never reached the API - usually TLS inspection or proxy problems.
            $msg = "Could not reach $script:BaseUrl : $detail"
            if ($detail -match 'SSL|TLS|certificate|trust') {
                $msg += "`n       Looks like a certificate problem (Zscaler / TLS inspection?)." +
                        "`n       Install the proxy's root CA in the OS certificate store, or as a last resort set [network] verify_ssl = false."
            }
            elseif ($detail -match 'proxy|407') {
                $msg += "`n       Check [network] proxy / proxy_use_default_credentials in the .ini."
            }
            Fail $msg
        }
        switch ($status) {
            401 { Fail "HTTP 401 Unauthorized - the API token is invalid or for a different cloud ($script:BaseUrl)." }
            403 { Fail "HTTP 403 Forbidden - the token has no (write) access to this org/site.`n       $detail" }
            404 { Fail "HTTP 404 Not Found - $Method $Path`n       Check org_id / site_id / wlan_id (site-level WLANs need site_id set)." }
            default { Fail "HTTP $status on $Method $Path`n       $detail" }
        }
    }
}

function Test-PskFormat([string]$Psk) {
    if ($Psk -match '^[0-9A-Fa-f]{64}$') { return $null }   # raw 256-bit hex key
    if ($Psk.Length -lt 8)  { return 'must be at least 8 characters.' }
    if ($Psk.Length -gt 63) { return 'must be at most 63 characters (or exactly 64 hex digits).' }
    if ($Psk -notmatch '^[\x20-\x7E]+$') { return 'may only contain printable ASCII characters.' }
    return $null
}

# ----------------------------------------------------------------- config ---

$ini = Read-IniFile $IniPath

$cloud         = Get-IniValue $ini 'mist' 'cloud'     -Required
$script:Token  = Get-IniValue $ini 'mist' 'api_token' -Required
$orgId         = Get-IniValue $ini 'mist' 'org_id'    -Required
$wlanId        = Get-IniValue $ini 'mist' 'wlan_id'   -Required
$siteId        = Get-IniValue $ini 'mist' 'site_id'

$script:VerifySsl         = Test-Bool (Get-IniValue $ini 'network' 'verify_ssl') $true
$script:Proxy             = Get-IniValue $ini 'network' 'proxy'
$script:ProxyDefaultCreds = Test-Bool (Get-IniValue $ini 'network' 'proxy_use_default_credentials') $false

if ($PSVersionTable.PSVersion.Major -lt 6) {
    # Windows PowerShell 5.1: force TLS 1.2 and handle verify_ssl the old way.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    if (-not $script:VerifySsl) { [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true } }
}
if (-not $script:VerifySsl) {
    Write-Host 'WARNING: verify_ssl = false - TLS certificate checks are disabled.' -ForegroundColor Yellow
}

$apiHost        = Resolve-ApiHost $cloud
$script:BaseUrl = "https://$apiHost/api/v1"
$wlanPath       = if ($siteId) { "/sites/$siteId/wlans/$wlanId" } else { "/orgs/$orgId/wlans/$wlanId" }

# -------------------------------------------------------------- read WLAN ---

if (-not $Quiet) {
    Write-Host ''
    Write-Host "Mist API : $script:BaseUrl"
    Write-Host "Scope    : $(if ($siteId) { "site $siteId" } else { "org $orgId" })"
    Write-Host ''
}

$wlan = Invoke-Mist 'GET' $wlanPath

if (-not $wlan.PSObject.Properties['auth'] -or -not $wlan.auth) { Fail "WLAN '$($wlan.ssid)' has no auth block." }
$authType = [string]$wlan.auth.type
if ($authType -notlike 'psk*') {
    Fail "WLAN '$($wlan.ssid)' uses auth type '$authType', not a PSK - nothing to change."
}
$currentPsk = if ($wlan.auth.PSObject.Properties['psk']) { [string]$wlan.auth.psk } else { '' }

# ------------------------------------------------------------ new PSK -------

if ($Quiet) {
    $newPsk = $NewPsk
    $problem = Test-PskFormat $newPsk
    if ($problem) { Fail "New PSK $problem" }
    if ($newPsk -ceq $currentPsk) { Fail "New PSK is the same as the current PSK for SSID '$($wlan.ssid)' - nothing changed." }
}
else {
    $org = Invoke-Mist 'GET' "/orgs/$orgId"
    Write-Host "Org         : $($org.name)"
    Write-Host "SSID        : $($wlan.ssid)" -ForegroundColor Cyan
    Write-Host "Enabled     : $($wlan.enabled)"
    Write-Host "Auth type   : $authType"
    Write-Host "Current PSK : $(if ($currentPsk) { $currentPsk } else { '(empty / not returned by API)' })" -ForegroundColor Cyan
    if ($wlan.auth.PSObject.Properties['multi_psk_only'] -and $wlan.auth.multi_psk_only) {
        Write-Host 'NOTE: this WLAN is set to multi-PSK only - the single PSK may not be used by clients.' -ForegroundColor Yellow
    }
    Write-Host ''

    while ($true) {
        $newPsk = Read-Host 'Enter new PSK (blank to cancel)'
        if ([string]::IsNullOrEmpty($newPsk)) { Write-Host 'Cancelled - nothing changed.'; exit 0 }
        $problem = Test-PskFormat $newPsk
        if ($problem) { Write-Host "  PSK $problem" -ForegroundColor Yellow; continue }
        if ($newPsk -ceq $currentPsk) { Write-Host '  That is the same as the current PSK.' -ForegroundColor Yellow; continue }
        $again = Read-Host 'Re-enter new PSK'
        if ($again -cne $newPsk) { Write-Host '  The two entries do not match - try again.' -ForegroundColor Yellow; continue }
        break
    }

    Write-Host ''
    Write-Host "SSID    : $($wlan.ssid)"
    Write-Host "Old PSK : $currentPsk"
    Write-Host "New PSK : $newPsk"
    $confirm = Read-Host 'Write this change to Mist? (y/N)'
    if ($confirm -notmatch '^(y|yes)$') { Write-Host 'Cancelled - nothing changed.'; exit 0 }
}

# -------------------------------------------------------------- write -------

# Send the whole existing auth object with only psk replaced, so pairwise,
# multi-PSK and other auth settings stay exactly as they were.
$wlan.auth | Add-Member -NotePropertyName psk -NotePropertyValue $newPsk -Force
$null = Invoke-Mist 'PUT' $wlanPath @{ auth = $wlan.auth }

# A 200 doesn't guarantee the field stuck - read it back.
$check = Invoke-Mist 'GET' $wlanPath
if ([string]$check.auth.psk -cne $newPsk) {
    Fail "The PUT returned OK but the WLAN still reports a different PSK. Check the WLAN in the Mist portal."
}

if (-not $Quiet) { Write-Host '' }
Write-Host "Done - PSK for SSID '$($check.ssid)' updated and verified." -ForegroundColor Green
