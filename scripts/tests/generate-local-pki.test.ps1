[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$scriptPath = (Resolve-Path (Join-Path $PSScriptRoot '..\generate-local-pki.ps1')).Path
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$pkiRoot = Join-Path $repoRoot '.local\pki'
$previousOpenSslConf = $env:OPENSSL_CONF

try {
  $env:OPENSSL_CONF = 'Z:\codex-diagnostic\missing-openssl.cnf'
  & $scriptPath -Force | Out-Null

  foreach ($expectedPath in @(
    'ca\ca.crt',
    'hospital-a\server.crt',
    'clinic-b\client.crt',
    'auditor\client.crt'
  )) {
    if (-not (Test-Path -LiteralPath (Join-Path $pkiRoot $expectedPath))) {
      throw "EXPECTED_PKI_ARTIFACT_MISSING: $expectedPath"
    }
  }
} finally {
  $env:OPENSSL_CONF = $previousOpenSslConf
}

Write-Output 'PASS: local PKI generation does not depend on the machine OpenSSL configuration path.'
