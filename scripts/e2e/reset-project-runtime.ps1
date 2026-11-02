[CmdletBinding()]
param([switch]$DiscardData)
$ErrorActionPreference = 'Stop'
if (-not $DiscardData) { throw 'RESET_REQUIRES_EXPLICIT_DISCARD_DATA' }
$projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..')).Path
Push-Location -LiteralPath $projectRoot
try {
  & npx.cmd tsx scripts/runtime-compose.ts reset --discard-data
  exit $LASTEXITCODE
} finally { Pop-Location }
