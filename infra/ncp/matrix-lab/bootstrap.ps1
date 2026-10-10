# Generate configuration and keys only. Never starts a listening server or pulls images.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$lab = $PSScriptRoot
$envFile = Join-Path $lab '.env'
if (-not (Test-Path -LiteralPath $envFile)) { throw 'Create .env after completing the README version-selection gate.' }
$lines = @(Get-Content -LiteralPath $envFile | Where-Object { $_ -match '^SYNAPSE_IMAGE=' })
if ($lines.Count -ne 1) { throw 'Expected exactly one SYNAPSE_IMAGE entry.' }
$image = $lines[0].Substring('SYNAPSE_IMAGE='.Length).Trim()
if ($image -notmatch '^matrixdotorg/synapse:v[0-9]+[.][0-9]+[.][0-9]+@sha256:[a-f0-9]{64}$') {
  throw 'Select an official stable vX.Y.Z tag pinned by a verified SHA256 digest; placeholders/latest/RC rejected.'
}
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Docker is required; nothing generated.' }
& docker image inspect $image *> $null
if ($LASTEXITCODE -ne 0) { throw 'Verified image must already be cached. This script never pulls.' }
$data = Join-Path $lab 'generated'
if (Test-Path -LiteralPath $data) { throw 'generated already exists. Refusing to overwrite keys or data; inspect it manually.' }
New-Item -ItemType Directory -Path $data | Out-Null
# No network, no ports, no Docker logs, suppressed output. Official generate mode exits.
& docker run --rm --pull never --network none --log-driver none --memory 768m --cpus 1 --pids-limit 256 --mount "type=bind,source=$data,target=/data" -e SYNAPSE_SERVER_NAME=matrix.lab -e SYNAPSE_REPORT_STATS=no -e SYNAPSE_CONFIG_DIR=/data -e SYNAPSE_CONFIG_PATH=/data/homeserver.yaml $image generate *> $null
if ($LASTEXITCODE -ne 0) { throw 'Generation failed. Output suppressed for privacy. Inspect ignored generated directory privately before retrying.' }
if (-not (Test-Path -LiteralPath (Join-Path $data 'matrix.lab.signing.key'))) { throw 'Official generator did not create expected signing key; stop and check selected-version behavior.' }
function New-LocalSecret {
  $bytes = New-Object byte[] 32
  $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
  try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
  return [Convert]::ToBase64String($bytes)
}
$template = Get-Content -LiteralPath (Join-Path $lab 'homeserver.yaml.template') -Raw
$template = $template.Replace('__REGISTRATION_SECRET__', (New-LocalSecret)).Replace('__MACAROON_SECRET__', (New-LocalSecret)).Replace('__FORM_SECRET__', (New-LocalSecret))
[System.IO.File]::WriteAllText((Join-Path $data 'homeserver.yaml'), $template, [System.Text.UTF8Encoding]::new($false))
Copy-Item -LiteralPath (Join-Path $lab 'log.config') -Destination (Join-Path $data 'log.config')
Write-Output 'Generated local ignored configuration and signing key only. No server started. Protect generated with local ACLs; do not commit or share it.'
