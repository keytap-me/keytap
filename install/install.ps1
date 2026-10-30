# KeyTap bridge installer for Windows — https://keytap.me/install
#
#   irm https://keytap.me/install.ps1 | iex                               # install the bridge
#   & ([scriptblock]::Create((irm https://keytap.me/install.ps1))) -Shim   # ... and route age's YubiKey plugin through it
#
# Downloads age-plugin-yubikey-phone from the latest GitHub release of keytap-me/keytap, verifies it
# against the release's SHA256SUMS and installs it into %LOCALAPPDATA%\KeyTap\bin, which is put first
# on your user PATH. With -Shim it also places a copy named age-plugin-yubikey.exe there, so age asks
# the phone; the bridge hands everything except decryption to the real plugin. No admin rights needed.
param(
    [switch]$Shim,
    [string]$Version = $env:KEYTAP_VERSION
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repo = 'keytap-me/keytap'
$bin = Join-Path $env:LOCALAPPDATA 'KeyTap\bin'
$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'ARM64' { 'arm64' }
    'AMD64' { 'amd64' }
    default { throw "keytap: unsupported architecture $($env:PROCESSOR_ARCHITECTURE)" }
}
$asset = "age-plugin-yubikey-phone-windows-$arch.zip"
$base = if ($Version) { "https://github.com/$repo/releases/download/$Version" } else { "https://github.com/$repo/releases/latest/download" }

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("keytap-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "Downloading $asset ..."
    Invoke-WebRequest -UseBasicParsing "$base/$asset" -OutFile (Join-Path $tmp $asset)
    Invoke-WebRequest -UseBasicParsing "$base/SHA256SUMS" -OutFile (Join-Path $tmp 'SHA256SUMS')
    $line = Get-Content (Join-Path $tmp 'SHA256SUMS') | Where-Object { ($_ -split '\s+')[1] -replace '^\*', '' -eq $asset }
    if (-not $line) { throw "keytap: $asset is not listed in SHA256SUMS" }
    $want = ($line -split '\s+')[0].ToLower()
    $got = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $asset)).Hash.ToLower()
    if ($got -ne $want) { throw "keytap: checksum mismatch for $asset - not installing" }
    Write-Host 'Checksum verified.'

    Expand-Archive -Path (Join-Path $tmp $asset) -DestinationPath (Join-Path $tmp 'x') -Force
    New-Item -ItemType Directory -Force -Path $bin | Out-Null
    Copy-Item (Join-Path $tmp 'x\age-plugin-yubikey-phone.exe') (Join-Path $bin 'age-plugin-yubikey-phone.exe') -Force
    Write-Host "Installed $bin\age-plugin-yubikey-phone.exe"

    if ($Shim) {
        Copy-Item (Join-Path $bin 'age-plugin-yubikey-phone.exe') (Join-Path $bin 'age-plugin-yubikey.exe') -Force
        Write-Host "Shim installed: $bin\age-plugin-yubikey.exe (decryptions go to the phone)"
    }
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$parts = @($userPath -split ';' | Where-Object { $_ -and $_ -ne $bin })
[Environment]::SetEnvironmentVariable('Path', (@($bin) + $parts) -join ';', 'User')
Write-Host "$bin is first on your user PATH (open a new terminal to pick it up)."

if (-not (Get-Command age -ErrorAction SilentlyContinue)) { Write-Host "Note: 'age' is not installed yet (winget install FiloSottile.age)." }
Write-Host ''
Write-Host 'Next: open KeyTap on your iPhone and run'
Write-Host '  age-plugin-yubikey-phone pair --host <IP address of this computer>'
Write-Host 'Guide: https://keytap.me/install'
