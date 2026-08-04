# run_mesh_media_http_smoke.ps1 - media over HTTP via the M3 gateway.
#
# Drives the real playback path end to end: a media file is published (client
# builds the M3 V2 manifest + HLS media playlist), uploaded to the S3-shaped
# gateway (SigV4 PUT), then each playlist segment is fetched with an HTTP
# Range header (Range/206) and verified byte-for-byte against the source file.
# This is exactly what an HLS player does: read the playlist, fetch segments
# by byte range.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File mesh/scripts/run_mesh_media_http_smoke.ps1

param(
    [int] $GatewayPort = 20093,
    [string] $BuildDir = "build\Msvc-Release"
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$gatewayBin = Join-Path (Join-Path $repoRoot $BuildDir) 'bin\m3_gateway_main.exe'
$mediaBin   = Join-Path (Join-Path $repoRoot $BuildDir) 'bin\mesh_stream_media_main.exe'

if (-not (Test-Path $gatewayBin) -or -not (Test-Path $mediaBin)) {
    Write-Error "gateway/media binaries not found in $BuildDir\bin"
}

$workDir = Join-Path $env:TEMP ("m3-media-http-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null
$dataPath = Join-Path $workDir 'media.bin'
$gwRoot = Join-Path $workDir 'gw'

$bytes = New-Object byte[] (100 * 1024)
for ($i = 0; $i -lt $bytes.Length; $i++) {
    $bytes[$i] = [byte](($i * 7 + ($i -shr 4) + 1) -band 0xff)
}
[System.IO.File]::WriteAllBytes($dataPath, $bytes)

$gatewayProc = $null
try {
    # ---- publish: manifest + playlist (client side) ----
    Write-Host '== publish media (manifest + HLS playlist) =='
    $publish = (& $mediaBin publish $dataPath --block 32768 --segment 32768 --dur-ms 2000 2>$null | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "publish failed (exit $LASTEXITCODE)" }
    if ($publish -notmatch 'PUBLISH OK .*size=102400 chunks=4') { throw "publish marker missing" }

    $ranges = @()
    foreach ($m in [regex]::Matches($publish, '#EXT-X-BYTERANGE:(\d+)@(\d+)')) {
        $ranges += @{ Len = [long]$m.Groups[1].Value; Offset = [long]$m.Groups[2].Value }
    }
    if ($ranges.Count -ne 4) { throw "expected 4 playlist segments, got $($ranges.Count)" }
    Write-Host "playlist segments: $($ranges.Count)"

    # ---- start the gateway (standalone local store) ----
    Write-Host "== starting gateway on port $GatewayPort =="
    $gwOut = Join-Path $workDir 'gw.out'
    $gwErr = Join-Path $workDir 'gw.err'
    $gatewayProc = Start-Process -FilePath $gatewayBin -ArgumentList @($gwRoot, "$GatewayPort") `
        -WindowStyle Hidden -RedirectStandardOutput $gwOut -RedirectStandardError $gwErr -PassThru

    $ready = $false
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-WebRequest -Uri "http://127.0.0.1:$GatewayPort/bkt/probe" `
                -Method GET -UseBasicParsing -SkipHttpErrorCheck -TimeoutSec 2
            if ($r.StatusCode -eq 403) { $ready = $true; break }
        } catch { }
        Start-Sleep -Milliseconds 200
    }
    if (-not $ready) {
        Get-Content -LiteralPath $gwErr -Raw -ErrorAction SilentlyContinue
        throw 'gateway HTTP not ready'
    }

    # ---- SigV4 helpers (same demo credential as the gateway smoke) ----
    $hostHeader = "127.0.0.1:$GatewayPort"
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
    function Sign-Request([string] $method, [string] $uri, [byte[]] $payload, [string] $amzdate) {
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

    # ---- signed PUT of the media object ----
    Write-Host '== signed PUT media/obj =='
    $amzdate = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $auth = Sign-Request 'PUT' '/media/obj' $bytes $amzdate
    $payloadHash = Sha256Hex $bytes
    $putOut = & curl.exe -s -o NUL -w '%{http_code}' -X PUT `
        -H "Authorization: $auth" -H "x-amz-content-sha256: $payloadHash" -H "x-amz-date: $amzdate" `
        --data-binary "@$dataPath" "http://127.0.0.1:$GatewayPort/media/obj"
    if ($putOut -ne '200') { throw "PUT failed: $putOut" }

    # ---- gateway-served playlist (player fetches the object's playlist) ----
    Write-Host '== gateway playlist /media/obj/playlist.m3u8 =='
    $amzdate = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $auth = Sign-Request 'GET' '/media/obj' ([byte[]]@()) $amzdate  # SigV4 signs the canonical resource
    $payloadHash = Sha256Hex ([byte[]]@())
    $plOut = & curl.exe -s `
        -H "Authorization: $auth" -H "x-amz-content-sha256: $payloadHash" -H "x-amz-date: $amzdate" `
        "http://127.0.0.1:$GatewayPort/media/obj/playlist.m3u8"
    $plText = [string]::Join("`n", @($plOut))
    if (-not ($plText -match '#EXTM3U')) { throw "gateway playlist missing #EXTM3U: $plText" }
    # The gateway derives its own segment granularity; verify the served
    # byteranges cover the whole object.
    $gatewayLen = 0L
    foreach ($m in [regex]::Matches($plText, '#EXT-X-BYTERANGE:(\d+)@(\d+)')) {
        $gatewayLen += [long]$m.Groups[1].Value
    }
    if ($gatewayLen -ne 102400) { throw "gateway playlist byteranges sum $gatewayLen != 102400" }
    Write-Host 'gateway playlist OK (byteranges cover the object)'

    # ---- signed Range GETs for every playlist segment (Range/206) ----
    Write-Host '== fetch each playlist segment via Range/206 =='
    for ($s = 0; $s -lt $ranges.Count; $s++) {
        $offset = $ranges[$s].Offset
        $len = $ranges[$s].Len
        $end = $offset + $len - 1
        $amzdate = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
        $auth = Sign-Request 'GET' '/media/obj' ([byte[]]@()) $amzdate
        $payloadHash = Sha256Hex ([byte[]]@())
        $outPath = Join-Path $workDir "seg-$s.bin"
        $headersPath = Join-Path $workDir "seg-$s.hdr"
        & curl.exe -s -o $outPath -D $headersPath `
            -H "Authorization: $auth" -H "x-amz-content-sha256: $payloadHash" -H "x-amz-date: $amzdate" `
            -H "Range: bytes=$offset-$end" "http://127.0.0.1:$GatewayPort/media/obj"
        if ($LASTEXITCODE -ne 0) { throw "Range GET $s failed" }
        $headers = Get-Content -LiteralPath $headersPath -Raw
        if ($headers -notmatch 'HTTP/1.1 206') { throw "segment $s expected 206: $headers" }
        if ($headers -notmatch "Content-Range: bytes $offset-$end/102400") {
            throw "segment $s Content-Range mismatch: $headers"
        }
        $got = [System.IO.File]::ReadAllBytes($outPath)
        $expected = New-Object byte[] $len
        [Array]::Copy($bytes, $offset, $expected, 0, $len)
        if ($got.Length -ne $expected.Length -or -not ([System.Linq.Enumerable]::SequenceEqual($got, $expected))) {
            throw "segment $s bytes mismatch (len $($got.Length) vs $($expected.Length))"
        }
        Write-Host "segment ${s}: 206 bytes=$offset-$end OK"
    }

    Write-Host '== media over HTTP smoke PASSED =='
    exit 0
} finally {
    if ($gatewayProc -and -not $gatewayProc.HasExited) {
        Stop-Process -Id $gatewayProc.Id -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}