[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# CPython's official Windows embeddable packages. The archive hashes are
# published on https://www.python.org/downloads/release/python-3147/.
$pythonVersion = '3.14.7'
$artifacts = @{
    amd64 = @{
        FileName = 'python-3.14.7-embed-amd64.zip'
        Sha256 = 'd297e5ff019966817ad8502465176139f2d3d840fa4ed84b13bed399a6ab1f15'
    }
    arm64 = @{
        FileName = 'python-3.14.7-embed-arm64.zip'
        Sha256 = 'f6773983c8959d4281e48c4540cb0bdd23e42391e4e951ce17e7ceb52658f21c'
    }
    win32 = @{
        FileName = 'python-3.14.7-embed-win32.zip'
        Sha256 = '2bce2347adb05b4565d0bf50f7a44298f6c0bb08ae4f9d88d051b8512a55fcf7'
    }
}

$reportedArchitecture = $env:PROCESSOR_ARCHITECTURE
if ($env:PROCESSOR_ARCHITEW6432) {
    $reportedArchitecture = $env:PROCESSOR_ARCHITEW6432
}

$artifactKey = switch ($reportedArchitecture.ToUpperInvariant()) {
    'AMD64' { 'amd64' }
    'ARM64' { 'arm64' }
    'X86' { 'win32' }
    default { throw "Unsupported Windows architecture: $reportedArchitecture" }
}
$artifact = $artifacts[$artifactKey]

$projectRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$runtimeRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot '.runtime'))
$targetRoot = [IO.Path]::GetFullPath((Join-Path $runtimeRoot 'python'))
$targetPython = Join-Path $targetRoot 'python.exe'
$runtimePrefix = $runtimeRoot.TrimEnd('\') + '\'

function Remove-GeneratedPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = [IO.Path]::GetFullPath($Path)
    if (-not $fullPath.StartsWith(
        $runtimePrefix,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Refusing to remove a path outside the private runtime: $fullPath"
    }
    if (Test-Path -LiteralPath $fullPath) {
        Remove-Item -LiteralPath $fullPath -Recurse -Force
    }
}

function Test-PrivatePython {
    param([Parameter(Mandatory = $true)][string]$Executable)

    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
        return $false
    }
    & $Executable -c (
        'import asyncio, discord_bypass, sqlite3, ssl, sys; ' +
        'raise SystemExit(sys.version_info[:3] != (3, 14, 7))'
    ) *> $null
    return $LASTEXITCODE -eq 0
}

New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null

# Serialize first-run extraction so two accidental double-clicks cannot leave a
# partial runtime. A second process waits briefly for the first one to finish.
$lockPath = Join-Path $runtimeRoot 'bootstrap.lock'
$lockStream = $null
$lockDeadline = [DateTime]::UtcNow.AddSeconds(60)
while ($null -eq $lockStream) {
    try {
        $lockStream = [IO.File]::Open(
            $lockPath,
            [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )
    } catch [IO.IOException] {
        if ([DateTime]::UtcNow -ge $lockDeadline) {
            throw 'Timed out waiting for another Python bootstrap process.'
        }
        Start-Sleep -Milliseconds 250
    }
}

$temporaryRoot = Join-Path $runtimeRoot (
    '.python.tmp-{0}-{1}' -f $PID, [Guid]::NewGuid().ToString('N')
)
$archivePath = Join-Path $runtimeRoot (
    '.python-download-{0}-{1}.zip' -f $PID, [Guid]::NewGuid().ToString('N')
)

try {
    if (Test-PrivatePython -Executable $targetPython) {
        Write-Host "Using the verified private Python $pythonVersion runtime."
        return
    }

    $downloadUrl = 'https://www.python.org/ftp/python/{0}/{1}' -f `
        $pythonVersion, $artifact.FileName
    Write-Host "Python 3.10+ was not found. Downloading private Python $pythonVersion..."
    Write-Host "Source: $downloadUrl"

    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.ServicePointManager]::SecurityProtocol -bor `
        [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $downloadUrl -OutFile $archivePath -UseBasicParsing

    $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
    if ($actualHash -ine $artifact.Sha256) {
        throw (
            'Downloaded Python archive failed SHA-256 verification. ' +
            "Expected $($artifact.Sha256), received $actualHash."
        )
    }
    Write-Host 'SHA-256 verification passed.'

    New-Item -ItemType Directory -Path $temporaryRoot | Out-Null
    Expand-Archive -LiteralPath $archivePath -DestinationPath $temporaryRoot

    $pathFiles = @(
        Get-ChildItem -LiteralPath $temporaryRoot -File -Filter 'python*._pth'
    )
    if ($pathFiles.Count -ne 1) {
        throw 'The official Python archive has an unexpected path configuration.'
    }
    $pathLines = @(Get-Content -LiteralPath $pathFiles[0].FullName)
    if ($pathLines -notcontains '..\..') {
        Add-Content -LiteralPath $pathFiles[0].FullName -Value '..\..' -Encoding ascii
    }

    $temporaryPython = Join-Path $temporaryRoot 'python.exe'
    if (-not (Test-PrivatePython -Executable $temporaryPython)) {
        throw 'The private Python runtime failed its import and version check.'
    }

    $metadata = [ordered]@{
        version = $pythonVersion
        architecture = $artifactKey
        source = $downloadUrl
        archive_sha256 = $artifact.Sha256
    } | ConvertTo-Json
    Set-Content -LiteralPath (
        Join-Path $temporaryRoot '.discord-bypass-python.json'
    ) -Value $metadata -Encoding UTF8

    if (Test-Path -LiteralPath $targetRoot) {
        Remove-GeneratedPath -Path $targetRoot
    }
    Move-Item -LiteralPath $temporaryRoot -Destination $targetRoot

    if (-not (Test-PrivatePython -Executable $targetPython)) {
        throw 'The installed private Python runtime failed its final check.'
    }
    Write-Host "Private Python is ready at $targetRoot"
} finally {
    if (Test-Path -LiteralPath $archivePath) {
        Remove-Item -LiteralPath $archivePath -Force
    }
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-GeneratedPath -Path $temporaryRoot
    }
    if ($null -ne $lockStream) {
        $lockStream.Dispose()
    }
}
