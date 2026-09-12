$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$DistPath = Join-Path $ProjectRoot "dist"
$StagePath = Join-Path $DistPath "ShieldNet-Desktop-Preview"
$ArchivePath = Join-Path $DistPath "ShieldNet-Desktop-Preview.zip"

if (Test-Path $StagePath) { Remove-Item $StagePath -Recurse -Force }
if (Test-Path $ArchivePath) { Remove-Item $ArchivePath -Force }
New-Item -ItemType Directory -Path $StagePath -Force | Out-Null

$exclude = @(
    ".git",
    ".shieldnet-venv",
    "__pycache__",
    "dist",
    "node_modules",
    ".pytest_cache"
)

Get-ChildItem $ProjectRoot -Force | Where-Object { $exclude -notcontains $_.Name } | ForEach-Object {
    Copy-Item $_.FullName $StagePath -Recurse -Force
}

Compress-Archive -Path (Join-Path $StagePath "*") -DestinationPath $ArchivePath -CompressionLevel Optimal
Write-Host "Created $ArchivePath"