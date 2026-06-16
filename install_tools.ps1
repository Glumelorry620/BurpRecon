param()
$ErrorActionPreference = "Stop"
$ToolsDir = Join-Path $PSScriptRoot "tools"

function Write-OK   { param($m) Write-Host "  [+] $m" -ForegroundColor Green }
function Write-Info { param($m) Write-Host "  [*] $m" -ForegroundColor Cyan }
function Write-Warn { param($m) Write-Host "  [!] $m" -ForegroundColor Yellow }
function Write-Err  { param($m) Write-Host "  [x] $m" -ForegroundColor Red }

Write-Host ""
Write-Host "  BurpRecon -- Tool Installer for Windows" -ForegroundColor Magenta
Write-Host ""

if (-not (Test-Path $ToolsDir)) {
    New-Item -ItemType Directory -Path $ToolsDir | Out-Null
    Write-Info "Created: $ToolsDir"
}

$env:PATH = "$ToolsDir;" + $env:PATH

function Get-GithubLatestTag {
    param([string]$Repo)
    $api = "https://api.github.com/repos/$Repo/releases/latest"
    $resp = Invoke-RestMethod -Uri $api -Headers @{
        "User-Agent" = "BurpRecon-installer"
        "Accept"     = "application/vnd.github+json"
    }
    return $resp.tag_name
}

function Get-GithubAssetUrl {
    param([string]$Repo, [string]$Tag, [string]$Pattern)
    $api = "https://api.github.com/repos/$Repo/releases/tags/$Tag"
    $resp = Invoke-RestMethod -Uri $api -Headers @{
        "User-Agent" = "BurpRecon-installer"
        "Accept"     = "application/vnd.github+json"
    }
    $asset = $resp.assets | Where-Object { $_.name -like $Pattern } | Select-Object -First 1
    if (-not $asset) { throw "No asset matching '$Pattern' found in $Repo $Tag" }
    return $asset.browser_download_url
}

function Install-Binary {
    param(
        [string]$Name,
        [string]$Url,
        [string]$ExeName
    )
    $destExe = Join-Path $ToolsDir $ExeName
    if (Test-Path $destExe) {
        Write-OK "$Name already installed: $destExe"
        return
    }

    $isTarGz = $Url -like "*.tar.gz"
    $ext = if ($isTarGz) { ".tar.gz" } else { ".zip" }
    $archivePath = Join-Path $env:TEMP "$Name-install$ext"

    Write-Info "Downloading $Name ..."
    try {
        Invoke-WebRequest -Uri $Url -OutFile $archivePath -UseBasicParsing
    } catch {
        Write-Err "Download failed for $Name : $_"
        return
    }

    $extractDir = Join-Path $env:TEMP "$Name-extract"
    if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
    New-Item -ItemType Directory $extractDir | Out-Null

    Write-Info "Extracting $Name ..."
    try {
        if ($isTarGz) {
            tar -xzf $archivePath -C $extractDir
        } else {
            Expand-Archive -Path $archivePath -DestinationPath $extractDir -Force
        }
    } catch {
        Write-Err "Extraction failed for $Name : $_"
        return
    }

    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($ExeName)
    $found = Get-ChildItem -Path $extractDir -Filter "$baseName.exe" -Recurse | Select-Object -First 1
    if (-not $found) {
        $found = Get-ChildItem -Path $extractDir -Filter "*.exe" -Recurse | Select-Object -First 1
    }
    if (-not $found) {
        Write-Err "Could not find $ExeName inside archive."
        Get-ChildItem $extractDir -Recurse | ForEach-Object { Write-Host "    $_" }
        return
    }
    Copy-Item $found.FullName -Destination $destExe -Force
    Write-OK "$Name installed --> $destExe"
    Remove-Item $archivePath -Force -ErrorAction SilentlyContinue
    Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
}

# subfinder
Write-Host ""
Write-Host "  -- subfinder --" -ForegroundColor Yellow
try {
    $tag = Get-GithubLatestTag "projectdiscovery/subfinder"
    Write-Info "Latest: $tag"
    $url = Get-GithubAssetUrl "projectdiscovery/subfinder" $tag "*windows_amd64.zip"
    Install-Binary -Name "subfinder" -Url $url -ExeName "subfinder.exe"
} catch { Write-Err "subfinder failed: $_" }

# amass
Write-Host ""
Write-Host "  -- amass --" -ForegroundColor Yellow
try {
    $tag = Get-GithubLatestTag "owasp-amass/amass"
    Write-Info "Latest: $tag"
    $url = Get-GithubAssetUrl "owasp-amass/amass" $tag "*windows*amd64*"
    Install-Binary -Name "amass" -Url $url -ExeName "amass.exe"
} catch { Write-Err "amass failed: $_" }

# httpx
Write-Host ""
Write-Host "  -- httpx --" -ForegroundColor Yellow
$httpxExe = Join-Path $ToolsDir "httpx.exe"
if ((Test-Path $httpxExe) -or (Get-Command "httpx" -ErrorAction SilentlyContinue)) {
    Write-OK "httpx already installed"
} else {
    try {
        $tag = Get-GithubLatestTag "projectdiscovery/httpx"
        Write-Info "Latest: $tag"
        $url = Get-GithubAssetUrl "projectdiscovery/httpx" $tag "*windows_amd64.zip"
        Install-Binary -Name "httpx" -Url $url -ExeName "httpx.exe"
    } catch { Write-Err "httpx failed: $_" }
}

# searchsploit
Write-Host ""
Write-Host "  -- searchsploit --" -ForegroundColor Yellow
Write-Warn "searchsploit requires WSL on Windows (bash script)."
Write-Host "    WSL/Kali/Debian:  sudo apt install exploitdb" -ForegroundColor DarkGray
Write-Host "    BurpRecon uses NVD API as fallback when searchsploit is not found." -ForegroundColor DarkGray
$wsl = Get-Command "wsl" -ErrorAction SilentlyContinue
if ($wsl) {
    $ssCheck = wsl which searchsploit 2>$null
    if ($ssCheck) {
        Write-OK "searchsploit found via WSL: $ssCheck"
    } else {
        Write-Warn "WSL found but exploitdb not installed inside WSL."
        Write-Host "    Run inside WSL: sudo apt install exploitdb" -ForegroundColor DarkGray
    }
} else {
    Write-Warn "WSL not found -- NVD fallback will be used automatically."
}

# Add to PATH
Write-Host ""
$addPath = Read-Host "  Add $ToolsDir to your permanent user PATH? [y/N]"
if ($addPath -match "^[yY]") {
    $curPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
    if ($curPath -notlike "*$ToolsDir*") {
        [System.Environment]::SetEnvironmentVariable("PATH", "$ToolsDir;$curPath", "User")
        Write-OK "Added to PATH. Restart terminal to apply."
    } else {
        Write-OK "Already in PATH."
    }
}

# Verify
Write-Host ""
Write-Host "  -- Verification --" -ForegroundColor Cyan
foreach ($t in @("subfinder", "amass", "httpx")) {
    $exe = Join-Path $ToolsDir "$t.exe"
    if (Test-Path $exe) {
        Write-OK "$t --> $exe"
    } elseif (Get-Command $t -ErrorAction SilentlyContinue) {
        Write-OK "$t --> $(Get-Command $t | Select-Object -ExpandProperty Source)"
    } else {
        Write-Warn "$t --> not found"
    }
}

Write-Host ""
Write-Host "  Done. Run: python burprecon_ui.py" -ForegroundColor Green
Write-Host ""