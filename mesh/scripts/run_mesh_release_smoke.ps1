# run_mesh_release_smoke.ps1 - multi-file software release over two-tier mesh.
#
# Publisher packs a 2-file release (mesh_stream_media_main release pack: each
# file becomes an M3 object + a versioned release manifest), publishes the
# files and the release manifest to a backbone gateway, a local mesh node
# pulls and caches them, and a local client downloads the manifest and every
# file from the local node - all byte-identical. Exits 0 on success.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File mesh/scripts/run_mesh_release_smoke.ps1

param(
    [int] $BackbonePort = 20101,
    [int] $LocalPort = 20102,
    [string] $BuildDir = "build\Msvc-Release"
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$gatewayBin = Join-Path (Join-Path $repoRoot $BuildDir) 'bin\m3_gateway_main.exe'
$mediaBin   = Join-Path (Join-Path $repoRoot $BuildDir) 'bin\mesh_stream_media_main.exe'

if (-not (Test-Path $gatewayBin) -or -not (Test-Path $mediaBin)) {
    Write-Error "gateway/media binaries not found in $BuildDir\bin"
}

$workDir = Join-Path $env:TEMP ("m3-release-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

$toolPath = Join-Path $workDir 'tool.bin'
$configPath = Join-Path $workDir 'config.json'
$toolBytes = New-Object byte[] 5000
for ($i = 0; $i -lt $toolBytes.Length; $i++) { $toolBytes[$i] = [byte]($i -band 0xff) }
[System.IO.File]::WriteAllBytes($toolPath, $toolBytes)
$configBytes = New-Object byte[] 300
for ($i = 0; $i -lt $configBytes.Length; $i++) { $configBytes[$i] = [byte]((0x40 + $i) -band 0xff) }
[System.IO.File]::WriteAllBytes($configPath, $configBytes)

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
function HexBytes([string] $hex) {
    $b = New-Object byte[] ($hex.Length / 2)
    for ($i = 0; $i -lt $b.Length; $i++) {
        $b[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16)
    }
    return $b
}
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
    $secret = HexBytes $secretHex
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
    & curl.exe -s -o $outPath -H "Authorization: $auth" `
        -H "x-amz-content-sha256: $payloadHash" -H "x-amz-date: $amzdate" `
        "http://127.0.0.1:$port$uri" | Out-Null
}
function Put-Bytes([int] $port, [string] $uri, [byte[]] $body) {
    $hostHeader = "127.0.0.1:$port"
    $amzdate = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $auth = Sign-Request $hostHeader 'PUT' $uri $body $amzdate
    $payloadHash = Sha256Hex $body
    $bodyPath = Join-Path $workDir ("put-" + [guid]::NewGuid().ToString('N') + ".bin")
    [System.IO.File]::WriteAllBytes($bodyPath, $body)
    $code = & curl.exe -s -o NUL -w '%{http_code}' -X PUT `
        -H "Authorization: $auth" -H "x-amz-content-sha256: $payloadHash" -H "x-amz-date: $amzdate" `
        --data-binary "@$bodyPath" "http://127.0.0.1:$port$uri"
    Remove-Item -LiteralPath $bodyPath -Force -ErrorAction SilentlyContinue
    return $code
}

try {
    # ---- pack the release (client side) ----
    Write-Host '== release pack =='
    $pack = (& $mediaBin release pack 'app-1.0' 1 $toolPath 'rel/tool' $configPath 'rel/config.json' 2>$null | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "release pack failed" }
    if ($pack -notmatch 'RELEASE MANIFEST ([0-9a-f]+)') { throw "release manifest missing: $pack" }
    $releaseHex = $Matches[1]
    $releaseBytes = HexBytes $releaseHex
    $files = @()
    foreach ($m in [regex]::Matches($pack, 'FILE (\S+) key=(\S+) size=(\d+) cid=(\S+)')) {
        $files += @{ Path = $m.Groups[1].Value; Key = $m.Groups[2].Value; Size = [long]$m.Groups[3].Value }
    }
    if ($files.Count -ne 2) { throw "expected 2 files, got $($files.Count)" }
    Write-Host "release app-1.0 files=$($files.Count)"

    # ---- backbone publish ----
    Write-Host "== backbone node (gateway :$BackbonePort) =="
    $bb = Start-Gw (Join-Path $workDir 'backbone') $BackbonePort 'backbone'
    Wait-Gateway $BackbonePort
    foreach ($f in $files) {
        $src = if ($f.Path -eq 'tool.bin') { $toolBytes } else { $configBytes }
        $code = Put-Bytes $BackbonePort ("/" + $f.Key) $src
        if ($code -ne '200') { throw "backbone PUT $($f.Key) failed: $code" }
    }
    $code = Put-Bytes $BackbonePort '/rel/app-1.0' $releaseBytes
    if ($code -ne '200') { throw "backbone PUT release manifest failed: $code" }
    Write-Host 'backbone: release published (2 files + manifest)'

    # ---- local mesh pulls + caches ----
    Write-Host "== local mesh node (gateway :$LocalPort) =="
    $local = Start-Gw (Join-Path $workDir 'local') $LocalPort 'local'
    Wait-Gateway $LocalPort
    foreach ($f in $files) {
        $src = if ($f.Path -eq 'tool.bin') { $toolBytes } else { $configBytes }
        $pulled = Join-Path $workDir ("pull-" + $f.Path)
        Get-Signed $BackbonePort ("/" + $f.Key) $pulled
        $got = [System.IO.File]::ReadAllBytes($pulled)
        if (-not (BytesEqual $got $src)) { throw "pull $($f.Key) mismatch" }
        $code = Put-Bytes $LocalPort ("/" + $f.Key) $got
        if ($code -ne '200') { throw "local cache PUT $($f.Key) failed: $code" }
    }
    $relPull = Join-Path $workDir 'release.bin'
    Get-Signed $BackbonePort '/rel/app-1.0' $relPull
    $relGot = [System.IO.File]::ReadAllBytes($relPull)
    if (-not (BytesEqual $relGot $releaseBytes)) { throw "release manifest pull mismatch" }
    $code = Put-Bytes $LocalPort '/rel/app-1.0' $relGot
    if ($code -ne '200') { throw "local cache PUT release failed: $code" }
    Write-Host 'local mesh: release pulled from backbone and cached'

    # ---- local client downloads ----
    Write-Host '== local client downloads from local mesh =='
    foreach ($f in $files) {
        $src = if ($f.Path -eq 'tool.bin') { $toolBytes } else { $configBytes }
        $down = Join-Path $workDir ("down-" + $f.Path)
        Get-Signed $LocalPort ("/" + $f.Key) $down
        $got = [System.IO.File]::ReadAllBytes($down)
        if (-not (BytesEqual $got $src)) { throw "download $($f.Key) mismatch" }
        Write-Host "file $($f.Key) OK ($($got.Length) bytes)"
    }
    $relDown = Join-Path $workDir 'release-down.bin'
    Get-Signed $LocalPort '/rel/app-1.0' $relDown
    $relDownBytes = [System.IO.File]::ReadAllBytes($relDown)
    if (-not (BytesEqual $relDownBytes $releaseBytes)) { throw "release manifest download mismatch" }
    Write-Host 'release manifest OK (byte-identical)'

    # Gateway-served release listing (server-side decode, thin HTTP client).
    $relTxt = Join-Path $workDir 'release.txt'
    Get-Signed $LocalPort '/rel/app-1.0/release.txt' $relTxt '/rel/app-1.0' | Out-Null
    $relTxtText = [System.IO.File]::ReadAllText($relTxt)
    if ($relTxtText -notmatch 'RELEASE app-1.0 version=1 files=2 digest=') {
        throw "release listing missing header: $relTxtText"
    }
    if ($relTxtText -notmatch 'tool.bin rel/tool 5000 ') { throw "release listing missing tool entry" }
    if ($relTxtText -notmatch 'config.json rel/config.json 300 ') { throw "release listing missing config entry" }
    Write-Host 'release listing OK (gateway release.txt)'

    Write-Host '== release smoke PASSED =='
    exit 0
} finally {
    foreach ($p in $procs) {
        if ($p -and -not $p.HasExited) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}