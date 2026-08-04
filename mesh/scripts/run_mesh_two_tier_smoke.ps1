# run_mesh_two_tier_smoke.ps1 - two-tier distribution: backbone publish, local
# mesh download (files and streams).
#
# Topology:
#   publisher -> backbone node (gateway A, origin)   [publish]
#   local mesh node (gateway B) pulls from A          [cache]
#   local client downloads from B                     [file + stream]
#
# The local tier serves both file downloads (full-object Range GET) and
# streaming (HLS playlist + per-segment Range/206), matching the requirement:
# content is first published to a backbone node, then downloaded through the
# local mesh. Exits 0 on success.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File mesh/scripts/run_mesh_two_tier_smoke.ps1

param(
    [int] $BackbonePort = 20097,
    [int] $LocalPort = 20098,
    [string] $BuildDir = "build\Msvc-Release"
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$gatewayBin = Join-Path (Join-Path $repoRoot $BuildDir) 'bin\m3_gateway_main.exe'
$mediaBin   = Join-Path (Join-Path $repoRoot $BuildDir) 'bin\mesh_stream_media_main.exe'

if (-not (Test-Path $gatewayBin) -or -not (Test-Path $mediaBin)) {
    Write-Error "gateway/media binaries not found in $BuildDir\bin"
}

$workDir = Join-Path $env:TEMP ("m3-two-tier-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null
$dataPath = Join-Path $workDir 'media.bin'
$backboneRoot = Join-Path $workDir 'backbone'
$localRoot = Join-Path $workDir 'local'

$bytes = New-Object byte[] (100 * 1024)
for ($i = 0; $i -lt $bytes.Length; $i++) {
    $bytes[$i] = [byte](($i * 7 + ($i -shr 4) + 1) -band 0xff)
}
[System.IO.File]::WriteAllBytes($dataPath, $bytes)

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
    $ready = $false
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:$port/bkt/probe" `
                -Method GET -UseBasicParsing -SkipHttpErrorCheck -TimeoutSec 2
            if ($r.StatusCode -eq 403) { $ready = $true; break }
        } catch { }
        Start-Sleep -Milliseconds 200
    }
    if (-not $ready) { throw "gateway on port $port not ready" }
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
function Get-Signed([int] $port, [string] $uri, [string] $range, [string] $outPath, [string] $signUri) {
    if (-not $signUri) { $signUri = $uri }
    $hostHeader = "127.0.0.1:$port"
    $amzdate = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $auth = Sign-Request $hostHeader 'GET' $signUri ([byte[]]@()) $amzdate
    $payloadHash = Sha256Hex ([byte[]]@())
    $args = @('-s', '-o', $outPath, '-H', "Authorization: $auth",
               '-H', "x-amz-content-sha256: $payloadHash", '-H', "x-amz-date: $amzdate")
    if ($range) { $args += @('-H', "Range: $range") }
    $args += "http://127.0.0.1:$port$uri"
    & curl.exe @args | Out-Null
    return $outPath
}
function Put-Signed([int] $port, [string] $uri, [byte[]] $body, [string] $path) {
    $hostHeader = "127.0.0.1:$port"
    $amzdate = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $auth = Sign-Request $hostHeader 'PUT' $uri $body $amzdate
    $payloadHash = Sha256Hex $body
    $args = @('-s', '-o', 'NUL', '-w', '%{http_code}', '-X', 'PUT',
               '-H', "Authorization: $auth", '-H', "x-amz-content-sha256: $payloadHash",
               '-H', "x-amz-date: $amzdate")
    if ($path) { $args += @('--data-binary', "@$path") }
    else { $args += @('--data-binary', $body) }
    $args += "http://127.0.0.1:$port$uri"
    return (& curl.exe @args)
}

try {
    # ---- client-side publish (manifest + playlist) ----
    Write-Host '== publish (client manifest + HLS playlist) =='
    $publish = (& $mediaBin publish $dataPath --block 32768 --segment 32768 --dur-ms 2000 2>$null | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "publish failed" }
    if ($publish -notmatch 'PUBLISH OK .*size=102400 chunks=4') { throw "publish marker missing" }
    $ranges = @()
    foreach ($m in [regex]::Matches($publish, '#EXT-X-BYTERANGE:(\d+)@(\d+)')) {
        $ranges += @{ Len = [long]$m.Groups[1].Value; Offset = [long]$m.Groups[2].Value }
    }
    if ($ranges.Count -ne 4) { throw "expected 4 segments, got $($ranges.Count)" }

    # ---- tier 1: backbone node holds the published object ----
    Write-Host "== backbone node (gateway :$BackbonePort) =="
    $bb = Start-Gw $backboneRoot $BackbonePort 'backbone'
    Wait-Gateway $BackbonePort
    $putCode = Put-Signed $BackbonePort '/media/obj' $bytes $dataPath
    if ($putCode -ne '200') { throw "backbone PUT failed: $putCode" }
    Write-Host 'backbone: object published'

    # ---- tier 2: local mesh node pulls from backbone and caches ----
    Write-Host "== local mesh node (gateway :$LocalPort) pulls from backbone =="
    $local = Start-Gw $localRoot $LocalPort 'local'
    Wait-Gateway $LocalPort
    $pullPath = Join-Path $workDir 'pull.bin'
    Get-Signed $BackbonePort '/media/obj' $null $pullPath | Out-Null
    $pulled = [System.IO.File]::ReadAllBytes($pullPath)
    if ($pulled.Length -ne $bytes.Length -or
        -not ([System.Linq.Enumerable]::SequenceEqual($pulled, $bytes))) {
        throw "local mesh pull from backbone mismatch (len $($pulled.Length))"
    }
    $cachePath = Join-Path $workDir 'cache.bin'
    [System.IO.File]::WriteAllBytes($cachePath, $pulled)
    $putCode = Put-Signed $LocalPort '/media/obj' $pulled $cachePath
    if ($putCode -ne '200') { throw "local cache PUT failed: $putCode" }
    Write-Host 'local mesh: object pulled from backbone and cached'

    # ---- local client: stream (playlist + Range/206) from the local node ----
    Write-Host '== local client: stream from local mesh =='
    $plPath = Join-Path $workDir 'local-pl.m3u8'
    Get-Signed $LocalPort '/media/obj/playlist.m3u8' $null $plPath '/media/obj' | Out-Null
    $plText = [System.IO.File]::ReadAllText($plPath)
    if (-not ($plText -match '#EXTM3U')) { throw "local playlist missing #EXTM3U" }
    $gatewayLen = 0L
    foreach ($m in [regex]::Matches($plText, '#EXT-X-BYTERANGE:(\d+)@(\d+)')) {
        $gatewayLen += [long]$m.Groups[1].Value
    }
    if ($gatewayLen -ne 102400) { throw "local playlist byteranges sum $gatewayLen != 102400" }
    for ($s = 0; $s -lt $ranges.Count; $s++) {
        $offset = $ranges[$s].Offset
        $len = $ranges[$s].Len
        $end = $offset + $len - 1
        $segPath = Join-Path $workDir "seg-$s.bin"
        Get-Signed $LocalPort '/media/obj' "bytes=$offset-$end" $segPath | Out-Null
        $seg = [System.IO.File]::ReadAllBytes($segPath)
        $expected = New-Object byte[] $len
        [Array]::Copy($bytes, $offset, $expected, 0, $len)
        if ($seg.Length -ne $expected.Length -or
            -not ([System.Linq.Enumerable]::SequenceEqual($seg, $expected))) {
            throw "local stream segment $s mismatch"
        }
        Write-Host "stream segment ${s}: Range bytes=$offset-$end OK"
    }

    # ---- local client: file download (full object) from the local node ----
    Write-Host '== local client: file download from local mesh =='
    $filePath = Join-Path $workDir 'file.bin'
    Get-Signed $LocalPort '/media/obj' $null $filePath | Out-Null
    $file = [System.IO.File]::ReadAllBytes($filePath)
    if (-not ([System.Linq.Enumerable]::SequenceEqual($file, $bytes))) {
        throw "local file download mismatch"
    }
    Write-Host 'file download OK (102400 bytes, byte-identical)'

    Write-Host '== two-tier distribution smoke PASSED =='
    exit 0
} finally {
    foreach ($p in $procs) {
        if ($p -and -not $p.HasExited) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}