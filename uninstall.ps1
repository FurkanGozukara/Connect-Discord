[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$expectedInstallRoot = [IO.Path]::GetFullPath(
    (Join-Path $env:LOCALAPPDATA 'Programs\DiscordBypass')
)
$scriptInstallRoot = [IO.Path]::GetFullPath($PSScriptRoot)
if ($scriptInstallRoot -cne $expectedInstallRoot) {
    throw "Refusing to remove unexpected path: $scriptInstallRoot"
}

$desktopShortcut = Join-Path ([Environment]::GetFolderPath('Desktop')) `
    'DiscordBypass.lnk'
if (Test-Path -LiteralPath $desktopShortcut) {
    Remove-Item -LiteralPath $desktopShortcut -Force
}

$startMenuDirectory = [IO.Path]::GetFullPath(
    (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\DiscordBypass')
)
if (Test-Path -LiteralPath $startMenuDirectory) {
    Remove-Item -LiteralPath $startMenuDirectory -Recurse -Force
}

if (Test-Path -LiteralPath $expectedInstallRoot) {
    Remove-Item -LiteralPath $expectedInstallRoot -Recurse -Force
}

$runtimeRoot = [IO.Path]::GetFullPath(
    (Join-Path $env:LOCALAPPDATA 'DiscordBypass')
)
$expectedRuntimeRoot = [IO.Path]::GetFullPath(
    (Join-Path $env:LOCALAPPDATA 'DiscordBypass')
)
if ($runtimeRoot -cne $expectedRuntimeRoot) {
    throw "Refusing to remove unexpected runtime path: $runtimeRoot"
}
if (Test-Path -LiteralPath $runtimeRoot) {
    Remove-Item -LiteralPath $runtimeRoot -Recurse -Force
}

Write-Host 'DiscordBypass, its private runtime cache, and shortcuts were removed.'
Write-Host 'No system proxy, driver, service, firewall rule, or DNS setting needs reverting.'
