$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$SourcePath = Join-Path $ProjectRoot "browser-extension"
$DistPath = Join-Path $ProjectRoot "dist"
$ArchivePath = Join-Path $DistPath "ShieldNet-Browser-Extension.zip"

New-Item -ItemType Directory -Path $DistPath -Force | Out-Null
if (Test-Path $ArchivePath) { Remove-Item $ArchivePath -Force }
Compress-Archive -Path (Join-Path $SourcePath "*") -DestinationPath $ArchivePath -CompressionLevel Optimal
Write-Host "Created $ArchivePath"