[CmdletBinding()]
param(
    [switch]$NoDesktopShortcut,
    [switch]$ResetDomains,
    [switch]$Launch
)

$ErrorActionPreference = 'Stop'
$sourceRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$installRoot = [IO.Path]::GetFullPath(
    (Join-Path $env:LOCALAPPDATA 'Programs\DiscordBypass')
)

$required = @(
    'discord_bypass',
    'domains.txt',
    'bootstrap_python.ps1',
    'run_python.cmd',
    'start_discord.bat',
    'start.cmd',
    'diagnose.cmd',
    'README.md',
    'LICENSE',
    'THIRD_PARTY_NOTICES.md',
    'UPSTREAM_AUDIT.md',
    'UPSTREAMS.lock',
    'uninstall.ps1'
)
foreach ($item in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $sourceRoot $item))) {
        throw "Package is incomplete; missing $item"
    }
}

New-Item -ItemType Directory -Path $installRoot -Force | Out-Null

$packageTarget = Join-Path $installRoot 'discord_bypass'
if (Test-Path -LiteralPath $packageTarget) {
    $resolvedTarget = [IO.Path]::GetFullPath($packageTarget)
    $expectedTarget = [IO.Path]::GetFullPath(
        (Join-Path $installRoot 'discord_bypass')
    )
    if ($resolvedTarget -cne $expectedTarget) {
        throw 'Refusing to replace an unexpected package path.'
    }
    Remove-Item -LiteralPath $resolvedTarget -Recurse -Force
}
New-Item -ItemType Directory -Path $packageTarget -Force | Out-Null
Get-ChildItem -LiteralPath (Join-Path $sourceRoot 'discord_bypass') `
    -File -Filter '*.py' | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $packageTarget
    }

$filesToReplace = @(
    'bootstrap_python.ps1',
    'run_python.cmd',
    'start_discord.bat',
    'start.cmd',
    'diagnose.cmd',
    'README.md',
    'LICENSE',
    'THIRD_PARTY_NOTICES.md',
    'UPSTREAM_AUDIT.md',
    'UPSTREAMS.lock',
    'uninstall.ps1'
)
foreach ($file in $filesToReplace) {
    Copy-Item -LiteralPath (Join-Path $sourceRoot $file) `
        -Destination (Join-Path $installRoot $file) -Force
}

$installedDomains = Join-Path $installRoot 'domains.txt'
if ($ResetDomains -or -not (Test-Path -LiteralPath $installedDomains)) {
    Copy-Item -LiteralPath (Join-Path $sourceRoot 'domains.txt') `
        -Destination $installedDomains -Force
}

$shell = New-Object -ComObject WScript.Shell
$startMenuDirectory = Join-Path $env:APPDATA `
    'Microsoft\Windows\Start Menu\Programs\DiscordBypass'
New-Item -ItemType Directory -Path $startMenuDirectory -Force | Out-Null

$startShortcut = $shell.CreateShortcut(
    (Join-Path $startMenuDirectory 'DiscordBypass.lnk')
)
$startShortcut.TargetPath = Join-Path $installRoot 'start_discord.bat'
$startShortcut.WorkingDirectory = $installRoot
$startShortcut.Description = 'Launch official Discord through the local Discord bypass'
$startShortcut.Save()

$uninstallShortcut = $shell.CreateShortcut(
    (Join-Path $startMenuDirectory 'Uninstall DiscordBypass.lnk')
)
$uninstallShortcut.TargetPath = 'powershell.exe'
$uninstallShortcut.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + `
    (Join-Path $installRoot 'uninstall.ps1') + '"'
$uninstallShortcut.WorkingDirectory = $installRoot
$uninstallShortcut.Description = 'Remove DiscordBypass and its shortcuts'
$uninstallShortcut.Save()

if (-not $NoDesktopShortcut) {
    $desktop = [Environment]::GetFolderPath('Desktop')
    $desktopShortcut = $shell.CreateShortcut(
        (Join-Path $desktop 'DiscordBypass.lnk')
    )
    $desktopShortcut.TargetPath = Join-Path $installRoot 'start_discord.bat'
    $desktopShortcut.WorkingDirectory = $installRoot
    $desktopShortcut.Description = 'Launch official Discord through the local Discord bypass'
    $desktopShortcut.Save()
}

Write-Host "Installed to $installRoot"
Write-Host 'No service, driver, registry entry, firewall rule, or system proxy was created.'

if ($Launch) {
    Start-Process -FilePath (Join-Path $installRoot 'start_discord.bat') `
        -WorkingDirectory $installRoot
}
