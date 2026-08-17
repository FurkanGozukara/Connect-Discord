[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$distRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot 'dist'))
$stageRoot = [IO.Path]::GetFullPath((Join-Path $distRoot 'DiscordBypass-source'))
$archivePath = [IO.Path]::GetFullPath(
    (Join-Path $distRoot 'DiscordBypass-source.zip')
)

Push-Location $projectRoot
try {
    & python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) {
        throw 'Tests failed; package was not built.'
    }

    New-Item -ItemType Directory -Path $distRoot -Force | Out-Null
    $distPrefix = $distRoot.TrimEnd('\') + '\'
    if (-not $stageRoot.StartsWith($distPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing to clean a staging path outside dist.'
    }
    if (Test-Path -LiteralPath $stageRoot) {
        Remove-Item -LiteralPath $stageRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Path $stageRoot -Force | Out-Null
    New-Item -ItemType Directory `
        -Path (Join-Path $stageRoot 'discord_bypass') -Force | Out-Null
    New-Item -ItemType Directory `
        -Path (Join-Path $stageRoot 'tests') -Force | Out-Null

    Get-ChildItem -LiteralPath (Join-Path $projectRoot 'discord_bypass') `
        -File -Filter '*.py' | ForEach-Object {
            Copy-Item -LiteralPath $_.FullName `
                -Destination (Join-Path $stageRoot 'discord_bypass')
        }
    Get-ChildItem -LiteralPath (Join-Path $projectRoot 'tests') `
        -File -Filter '*.py' | ForEach-Object {
            Copy-Item -LiteralPath $_.FullName `
                -Destination (Join-Path $stageRoot 'tests')
        }

    $rootFiles = @(
        'domains.txt',
        'bootstrap_python.ps1',
        'run_python.cmd',
        'start_discord.bat',
        'start.cmd',
        'diagnose.cmd',
        'install.ps1',
        'uninstall.ps1',
        'README.md',
        'LICENSE',
        'THIRD_PARTY_NOTICES.md',
        'UPSTREAM_AUDIT.md',
        'UPSTREAMS.lock'
    )
    foreach ($file in $rootFiles) {
        Copy-Item -LiteralPath (Join-Path $projectRoot $file) `
            -Destination (Join-Path $stageRoot $file)
    }

    $manifestLines = Get-ChildItem -LiteralPath $stageRoot -File -Recurse |
        Sort-Object FullName |
        ForEach-Object {
            $filePath = [IO.Path]::GetFullPath($_.FullName)
            $stagePrefix = $stageRoot.TrimEnd('\') + '\'
            if (-not $filePath.StartsWith(
                $stagePrefix,
                [StringComparison]::OrdinalIgnoreCase
            )) {
                throw "Manifest file escaped staging root: $filePath"
            }
            $relative = $filePath.Substring($stagePrefix.Length).Replace('\', '/')
            $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            "$hash  $relative"
        }
    Set-Content -LiteralPath (Join-Path $stageRoot 'MANIFEST.sha256') `
        -Value $manifestLines -Encoding ascii

    if (Test-Path -LiteralPath $archivePath) {
        Remove-Item -LiteralPath $archivePath -Force
    }
    Compress-Archive -Path (Join-Path $stageRoot '*') `
        -DestinationPath $archivePath -CompressionLevel Optimal

    $archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath ($archivePath + '.sha256') `
        -Value "$archiveHash  $([IO.Path]::GetFileName($archivePath))" -Encoding ascii

    Write-Host "Built $archivePath"
    Write-Host "SHA256 $archiveHash"
} finally {
    Pop-Location
}
