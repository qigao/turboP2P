# run_mesh_release_mirror_smoke.ps1 - two-tier release distribution over gateways.
#
# A publisher publishes a 3-file release (one nested path) to a backbone
# gateway (A). The C client then mirrors the whole release to a local edge
# gateway (B) with mesh_stream_media_main release mirror (signed GETs from A,
# signed PUTs to B). A local client pulls the release from B and downloads a
# file through B's release-file endpoint, verifying byte-identical content.
# Exits 0 on success.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File mesh/scripts/run_mesh_release_mirror_smoke.ps1

param(
    [int] $BackbonePort = 20141,
    [int] $LocalPort = 20142,
    [string] $BuildDir = "build\Msvc-Release"
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$gatewayBin = Join-Path (Join-Path $repoRoot $BuildDir) 'bin\m3_gateway_main.exe'
$mediaBin   = Join-Path (Join-Path $repoRoot $BuildDir) 'bin\mesh_stream_media_main.exe'

if (-not (Test-Path $gatewayBin) -or -not (Test-Path $mediaBin)) {
    Write-Error "gateway/media binaries not found in $BuildDir\bin"
}

$workDir = Join-Path $env:TEMP ("m3-release-mirror-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

$toolPath = Join-Path $workDir 'tool.bin'
$configPath = Join-Path $workDir 'config.json'
$libPath = Join-Path $workDir 'libfoo.so'
$toolBytes = New-Object byte[] 5000
for ($i = 0; $i -lt $toolBytes.Length; $i++) { $toolBytes[$i] = [byte]($i -band 0xff) }
[System.IO.File]::WriteAllBytes($toolPath, $toolBytes)
$configBytes = New-Object byte[] 300
for ($i = 0; $i -lt $configBytes.Length; $i++) { $configBytes[$i] = [byte]((0x40 + $i) -band 0xff) }
[System.IO.File]::WriteAllBytes($configPath, $configBytes)
$libBytes = New-Object byte[] 1234
for ($i = 0; $i -lt $libBytes.Length; $i++) { $libBytes[$i] = [byte]((0x80 + $i) -band 0xff) }
[System.IO.File]::WriteAllBytes($libPath, $libBytes)
$files = @(
    @{ Path = 'tool.bin'; Key = 'rel/tool'; SrcPath = $toolPath; Src = $toolBytes },
    @{ Path = 'config.json'; Key = 'rel/config.json'; SrcPath = $configPath; Src = $configBytes },
    @{ Path = 'lib/x64/libfoo.so'; Key = 'rel/libfoo'; SrcPath = $libPath; Src = $libBytes }
)

$procs = @()
function Start-Gw([string] $root, [int] $port, [string] $tag) {
    $out = Join-Path $workDir "$tag.out"
    $err = Join-Path $workDir "$tag.err"
    $p = Start-Process -FilePath $gatewayBin -ArgumentList @($root, "$port") `
        -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
    $script:procs += $p
    return $p
}
function Wait-Gateway([int] $port) {
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:$port/bkt/probe" `
                -Method GET -UseBasicParsing -SkipHttpErrorCheck -TimeoutSec 2
            if ($r.StatusCode -eq 403) { return }
        } catch { }
        Start-Sleep -Milliseconds 200
    }
    throw "gateway on port $port not ready"
}

$secretHex = '606162636465666768696a6b6c6d6e6f707172737475767778797a3031323334'
function Sha256Hex([byte[]] $data) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    return ([BitConverter]::ToString($sha.ComputeHash($data)) -replace '-', '').ToLowerInvariant()
}
function HmacSha256([byte[]] $key, [string] $text) {
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $key
    return $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($text))
}
function BytesEqual([byte[]] $a, [byte[]] $b) {
    if ($a.Length -ne $b.Length) { return $false }
    for ($i = 0; $i -lt $a.Length; $i++) {
        if ($a[$i] -ne $b[$i]) { return $false }
    }
    return $true
}
function Sign-Request([string] $hostHeader, [string] $method, [string] $uri, [byte[]] $payload, [string] $amzdate) {
    $payloadHash = Sha256Hex $payload
    $canonical = "$method`n$uri`n`nhost:$hostHeader`nx-amz-content-sha256:$payloadHash`nx-amz-date:$amzdate`nhost;x-amz-content-sha256;x-amz-date`n$payloadHash"
    $date = $amzdate.Substring(0, 8)
    $scope = "$date/us-east-1/s3/aws4_request"
    $stringToSign = "AWS4-HMAC-SHA256`n$amzdate`n$scope`n$(Sha256Hex ([System.Text.Encoding]::UTF8.GetBytes($canonical)))"
    $aws4 = [System.Text.Encoding]::UTF8.GetBytes('AWS4')
    $kBase = New-Object byte[] 36
    [Array]::Copy($aws4, 0, $kBase, 0, 4)
    $secret = New-Object byte[] 32
    for ($i = 0; $i -lt 32; $i++) { $secret[$i] = [Convert]::ToByte($secretHex.Substring($i * 2, 2), 16) }
    [Array]::Copy($secret, 0, $kBase, 4, 32)
    $kDate = HmacSha256 $kBase $date
    $kRegion = HmacSha256 $kDate 'us-east-1'
    $kService = HmacSha256 $kRegion 's3'
    $kSigning = HmacSha256 $kService 'aws4_request'
    $signature = ([BitConverter]::ToString((HmacSha256 $kSigning $stringToSign)) -replace '-', '').ToLowerInvariant()
    return "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/$scope, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=$signature"
}
function Get-Signed([int] $port, [string] $uri, [string] $outPath, [string] $signUri) {
    if (-not $signUri) { $signUri = $uri }
    $hostHeader = "127.0.0.1:$port"
    $amzdate = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $auth = Sign-Request $hostHeader 'GET' $signUri ([byte[]]@()) $amzdate
    $payloadHash = Sha256Hex ([byte[]]@())
    return (& curl.exe -s -o $outPath -w '%{http_code}' `
        -H "Authorization: $auth" -H "x-amz-content-sha256: $payloadHash" `
        -H "x-amz-date: $amzdate" "http://127.0.0.1:$port$uri")
}

try {
    # ---- start both gateways ----
    Write-Host "== backbone gateway :$BackbonePort =="
    $backbone = Start-Gw (Join-Path $workDir 'backbone') $BackbonePort 'backbone'
    Wait-Gateway $BackbonePort
    Write-Host "== local edge gateway :$LocalPort =="
    $local = Start-Gw (Join-Path $workDir 'local') $LocalPort 'local'
    Wait-Gateway $LocalPort

    # ---- publish the release to the backbone ----
    Write-Host '== publish to backbone =='
    $signKeyHex = '606162636465666768696a6b6c6d6e6f707172737475767778797a3031323334'
    $pubArgs = @('release', 'publish', '--paths', 'app-1.0', '1')
    foreach ($f in $files) { $pubArgs += $f.SrcPath; $pubArgs += $f.Path; $pubArgs += $f.Key }
    $pubArgs += '--sign-key'; $pubArgs += $signKeyHex
    $pubArgs += '--gateway'; $pubArgs += "127.0.0.1:$BackbonePort"
    $pub = (& $mediaBin @pubArgs 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "release publish failed: $pub" }
    if ($pub -notmatch 'RELEASE PUBKEY ([0-9a-f]{64})') { throw "release pubkey missing: $pub" }
    $releasePubkey = $Matches[1]
    if ($pub -notmatch 'RELEASE PUBLISH OK files=3 manifest=rel/app-1.0') {
        throw "release publish summary missing: $pub"
    }
    Write-Host 'backbone: release published (3 files + manifest)'

    # ---- mirror the release to the local edge gateway ----
    Write-Host '== C client release mirror =='
    $mir = (& $mediaBin release mirror 'app-1.0' `
        --from "127.0.0.1:$BackbonePort" --to "127.0.0.1:$LocalPort" 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "release mirror failed: $mir" }
    if ($mir -notmatch 'RELEASE MIRROR OK files=3 name=app-1.0') {
        throw "release mirror summary missing: $mir"
    }
    Write-Host 'release mirror OK (backbone -> local edge, 3 files + manifest)'

    # ---- pull the release from the local edge gateway ----
    Write-Host '== pull from local edge =='
    $outDir = Join-Path $workDir 'downloaded'
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    $pull = (& $mediaBin release pull 'app-1.0' $outDir --gateway "127.0.0.1:$LocalPort" --pubkey $releasePubkey 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "release pull from local failed: $pull" }
    if ($pull -notmatch 'RELEASE SIG OK') { throw "release sig verification on local edge missing: $pull" }
    if ($pull -notmatch 'RELEASE PULL OK files=3') { throw "release pull summary missing: $pull" }
    foreach ($f in $files) {
        $down = Join-Path $outDir $f.Path
        if (-not (Test-Path $down)) { throw "local download missing: $down" }
        $got = [System.IO.File]::ReadAllBytes($down)
        if (-not (BytesEqual $got $f.Src)) { throw "local download $($f.Path) mismatch" }
        Write-Host "file $($f.Path) OK ($($got.Length) bytes)"
    }

    # ---- release-file endpoint on the local edge gateway ----
    $rfPath = Join-Path $workDir 'edge-libfoo.so'
    $code = Get-Signed $LocalPort '/rel/app-1.0/lib/x64/libfoo.so' $rfPath '/rel/app-1.0/lib/x64/libfoo.so'
    if ($code -ne '200') { throw "edge release-file GET libfoo.so failed: $code" }
    $rfBytes = [System.IO.File]::ReadAllBytes($rfPath)
    if (-not (BytesEqual $rfBytes $libBytes)) { throw "edge release-file libfoo.so mismatch" }
    Write-Host 'local edge release-file endpoint OK (deep path)'

    Write-Host '== release mirror smoke PASSED =='
    exit 0
} finally {
    foreach ($p in $procs) {
        if ($p -and -not $p.HasExited) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}
