[CmdletBinding()]
param([switch]$Force)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$pkiRoot = Join-Path $root '.local/pki'
if ((Test-Path $pkiRoot) -and -not $Force) {
  throw 'PKI_ALREADY_EXISTS: use -Force only to replace the local academic PKI'
}
if (Test-Path $pkiRoot) { Remove-Item -LiteralPath $pkiRoot -Recurse -Force }

$openssl = (Get-Command openssl -ErrorAction SilentlyContinue).Source
if (-not $openssl) {
  $gitOpenSsl = 'C:\Program Files\Git\usr\bin\openssl.exe'
  if (Test-Path $gitOpenSsl) { $openssl = $gitOpenSsl }
}
if (-not $openssl) { throw 'OPENSSL_REQUIRED_FOR_LOCAL_PKI' }

function Invoke-OpenSsl {
  param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
  $savedPreference = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $output = & $openssl @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw "OPENSSL_COMMAND_FAILED: $($Arguments[0]) - $($output -join ' ')" }
  } finally {
    $ErrorActionPreference = $savedPreference
  }
}

function New-LeafCertificate {
  param(
    [string]$Institution,
    [string]$Purpose,
    [string]$ExtendedKeyUsage,
    [string]$SubjectAltName
  )
  $directory = Join-Path $pkiRoot $Institution
  New-Item -ItemType Directory -Force -Path $directory | Out-Null
  $keyPath = Join-Path $directory "$Purpose.key"
  $csrPath = Join-Path $directory "$Purpose.csr"
  $certPath = Join-Path $directory "$Purpose.crt"
  $extensionsPath = Join-Path $directory "$Purpose.extensions.cnf"
  $subject = "/CN=$Institution.local-$Purpose/O=Organization\/$Institution"

  Invoke-OpenSsl -Arguments @('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', $keyPath, '-out', $csrPath, '-subj', $subject, '-config', $caExtensions)
  @(
    'basicConstraints=critical,CA:FALSE'
    'keyUsage=critical,digitalSignature,keyEncipherment'
    "extendedKeyUsage=critical,$ExtendedKeyUsage"
    "subjectAltName=$SubjectAltName"
  ) | Set-Content -LiteralPath $extensionsPath -Encoding ascii
  Invoke-OpenSsl -Arguments @('x509', '-req', '-in', $csrPath, '-CA', (Join-Path $pkiRoot 'ca/ca.crt'), '-CAkey', (Join-Path $pkiRoot 'ca/ca.key'), '-CAcreateserial', '-out', $certPath, '-days', '365', '-sha256', '-extfile', $extensionsPath)
  Remove-Item -LiteralPath $csrPath, $extensionsPath
  $fingerprint = (& $openssl x509 -in $certPath -noout -fingerprint -sha256).Trim()
  Write-Output "${Institution}/${Purpose}: $certPath $fingerprint"
}

New-Item -ItemType Directory -Force -Path (Join-Path $pkiRoot 'ca') | Out-Null
Invoke-OpenSsl -Arguments @('genrsa', '-out', (Join-Path $pkiRoot 'ca/ca.key'), '4096')
$caExtensions = Join-Path $pkiRoot 'ca/ca.extensions.cnf'
@(
  '[v3_ca]'
  'basicConstraints=critical,CA:TRUE,pathlen:1'
  'keyUsage=critical,keyCertSign,cRLSign'
  'subjectKeyIdentifier=hash'
) | Set-Content -LiteralPath $caExtensions -Encoding ascii
Invoke-OpenSsl -Arguments @('req', '-x509', '-new', '-nodes', '-key', (Join-Path $pkiRoot 'ca/ca.key'), '-sha256', '-days', '3650', '-out', (Join-Path $pkiRoot 'ca/ca.crt'), '-subj', '/CN=InterFHIR Academic CA/O=InterFHIR Academic CA', '-extensions', 'v3_ca', '-config', $caExtensions)

foreach ($institution in @('hospital-a', 'clinic-b', 'auditor')) {
  $serverSan = "DNS:$institution.local,DNS:$institution-gateway,DNS:localhost"
  $clientSan = "DNS:$institution.local,URI:spiffe://interfhir/Organization/$institution"
  New-LeafCertificate -Institution $institution -Purpose 'server' -ExtendedKeyUsage 'serverAuth' -SubjectAltName $serverSan
  New-LeafCertificate -Institution $institution -Purpose 'client' -ExtendedKeyUsage 'clientAuth' -SubjectAltName $clientSan
}
Remove-Item -LiteralPath $caExtensions

# Compatibility names for the existing local harness. Each alias keeps its
# original purpose: Hospital A serves and Clinic B presents a client cert.
Copy-Item -LiteralPath (Join-Path $pkiRoot 'hospital-a/server.key') -Destination (Join-Path $pkiRoot 'hospital-a/tls.key')
Copy-Item -LiteralPath (Join-Path $pkiRoot 'hospital-a/server.crt') -Destination (Join-Path $pkiRoot 'hospital-a/tls.crt')
Copy-Item -LiteralPath (Join-Path $pkiRoot 'clinic-b/client.key') -Destination (Join-Path $pkiRoot 'clinic-b/tls.key')
Copy-Item -LiteralPath (Join-Path $pkiRoot 'clinic-b/client.crt') -Destination (Join-Path $pkiRoot 'clinic-b/tls.crt')

# The CA private key is needed only while signing this local academic PKI.
$caKeyPath = Join-Path $pkiRoot 'ca/ca.key'
$caSerialPath = Join-Path $pkiRoot 'ca/ca.srl'
if (Test-Path $caKeyPath) { Remove-Item -LiteralPath $caKeyPath -Force -ErrorAction Stop }
if (Test-Path $caKeyPath) { throw 'CA_PRIVATE_KEY_REMAINS' }
if (Test-Path $caSerialPath) { Remove-Item -LiteralPath $caSerialPath -Force -ErrorAction Stop }
if (Test-Path $caSerialPath) { throw 'CA_SERIAL_REMAINS' }
