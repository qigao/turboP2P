# run_mesh_release_download_smoke.ps1 - C-side release publish/pull over SigV4 HTTP.
#
# The C client publishes a 3-file release (one with a nested release path)
# to a backbone gateway in one command (mesh_stream_media_main release
# publish --paths: pack + signed PUTs for every file and the release
# manifest), then downloads the files back through the gateway with
# release pull and the release-file HTTP endpoint, verifying byte-identical
# content. Exits 0 on success.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File mesh/scripts/run_mesh_release_download_smoke.ps1

param(
    [int] $Port = 20111,
    [string] $BuildDir = "build\Msvc-Release"
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$gatewayBin = Join-Path (Join-Path $repoRoot $BuildDir) 'bin\m3_gateway_main.exe'
$mediaBin   = Join-Path (Join-Path $repoRoot $BuildDir) 'bin\mesh_stream_media_main.exe'

if (-not (Test-Path $gatewayBin) -or -not (Test-Path $mediaBin)) {
    Write-Error "gateway/media binaries not found in $BuildDir\bin"
}

$workDir = Join-Path $env:TEMP ("m3-release-dl-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

$toolPath = Join-Path $workDir 'tool.bin'
$configPath = Join-Path $workDir 'config.json'
$toolBytes = New-Object byte[] 5000
for ($i = 0; $i -lt $toolBytes.Length; $i++) { $toolBytes[$i] = [byte]($i -band 0xff) }
[System.IO.File]::WriteAllBytes($toolPath, $toolBytes)
$configBytes = New-Object byte[] 300
for ($i = 0; $i -lt $configBytes.Length; $i++) { $configBytes[$i] = [byte]((0x40 + $i) -band 0xff) }
[System.IO.File]::WriteAllBytes($configPath, $configBytes)
$libPath = Join-Path $workDir 'libfoo.so'
$libBytes = New-Object byte[] 1234
for ($i = 0; $i -lt $libBytes.Length; $i++) { $libBytes[$i] = [byte]((0x80 + $i) -band 0xff) }
[System.IO.File]::WriteAllBytes($libPath, $libBytes)

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
function Put-Bytes([int] $port, [string] $uri, [byte[]] $body) {
    $hostHeader = "127.0.0.1:$port"
    $amzdate = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $payloadHash = Sha256Hex $body
    $auth = Sign-Request $hostHeader 'PUT' $uri $body $amzdate
    $bodyPath = Join-Path $workDir ("put-" + [guid]::NewGuid().ToString('N') + ".bin")
    [System.IO.File]::WriteAllBytes($bodyPath, $body)
    $code = & curl.exe -s -o NUL -w '%{http_code}' -X PUT `
        -H "Authorization: $auth" -H "x-amz-content-sha256: $payloadHash" -H "x-amz-date: $amzdate" `
        --data-binary "@$bodyPath" "http://127.0.0.1:$port$uri"
    Remove-Item -LiteralPath $bodyPath -Force -ErrorAction SilentlyContinue
    return $code
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
    # ---- pack the release (client side) ----
    $files = @(
        @{ Path = 'tool.bin'; Key = 'rel/tool'; SrcPath = $toolPath; Src = $toolBytes },
        @{ Path = 'config.json'; Key = 'rel/config.json'; SrcPath = $configPath; Src = $configBytes },
        @{ Path = 'lib/x64/libfoo.so'; Key = 'rel/libfoo'; SrcPath = $libPath; Src = $libBytes }
    )

    # ---- start the backbone gateway ----
    Write-Host "== backbone gateway :$Port =="
    $gw = Start-Gw (Join-Path $workDir 'backbone') $Port 'backbone'
    Wait-Gateway $Port

    # ---- C-side publish: pack + upload files + release manifest ----
    Write-Host '== C client release publish =='
    $signKeyHex = '606162636465666768696a6b6c6d6e6f707172737475767778797a3031323334'
    $pubArgs = @('release', 'publish', '--paths', 'app-1.0', '1')
    foreach ($f in $files) { $pubArgs += $f.SrcPath; $pubArgs += $f.Path; $pubArgs += $f.Key }
    $pubArgs += '--sign-key'; $pubArgs += $signKeyHex
    $pubArgs += '--gateway'; $pubArgs += "127.0.0.1:$Port"
    $pub = (& $mediaBin @pubArgs 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "release publish failed: $pub" }
    if ($pub -notmatch 'RELEASE MANIFEST ([0-9a-f]+)') { throw "release manifest missing: $pub" }
    $releaseHex = $Matches[1]
    if ($pub -notmatch 'RELEASE PUBKEY ([0-9a-f]{64})') { throw "release pubkey missing: $pub" }
    $releasePubkey = $Matches[1]
    if ($pub -notmatch 'RELEASE SIG [0-9a-f]+') { throw "release sig missing: $pub" }
    if ($pub -notmatch 'RELEASE PUBLISH OK files=3 manifest=rel/app-1.0') {
        throw "release publish summary missing: $pub"
    }
    Write-Host 'release publish OK (C client, 3 files + manifest + signature via SigV4 PUT)'

    # ---- C-side pull through the gateway ----
    Write-Host '== C client release pull =='
    $outDir = Join-Path $workDir 'downloaded'
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    $pull = (& $mediaBin release pull $releaseHex $outDir --gateway "127.0.0.1:$Port" 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "release pull failed: $pull" }
    if ($pull -notmatch 'RELEASE PULL OK files=3') { throw "release pull summary missing: $pull" }
    Write-Host 'release pull OK (C client, 3 files via SigV4 GET)'

    # ---- byte-compare every downloaded file ----
    foreach ($f in $files) {
        $src = $f.Src
        $down = Join-Path $outDir $f.Path
        if (-not (Test-Path $down)) { throw "downloaded file missing: $down" }
        $got = [System.IO.File]::ReadAllBytes($down)
        if (-not (BytesEqual $got $src)) { throw "downloaded $($f.Path) mismatch" }
        Write-Host "file $($f.Path) OK ($($got.Length) bytes)"
    }

    # ---- C-side pull by release name (manifest fetched from gateway) ----
    $outDir2 = Join-Path $workDir 'downloaded-by-name'
    New-Item -ItemType Directory -Force -Path $outDir2 | Out-Null
    $pull2 = (& $mediaBin release pull 'app-1.0' $outDir2 --gateway "127.0.0.1:$Port" --pubkey $releasePubkey 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "release pull by name failed: $pull2" }
    if ($pull2 -notmatch 'RELEASE SIG OK') { throw "release sig verification missing: $pull2" }
    if ($pull2 -notmatch 'RELEASE PULL OK files=3') { throw "release pull by name summary missing: $pull2" }
    foreach ($f in $files) {
        $down = Join-Path $outDir2 $f.Path
        if (-not (Test-Path $down)) { throw "by-name download missing: $down" }
        $got = [System.IO.File]::ReadAllBytes($down)
        if (-not (BytesEqual $got $f.Src)) { throw "by-name download $($f.Path) mismatch" }
    }
    Write-Host 'release pull by name OK (C client, manifest from gateway)'

    # ---- release-file HTTP download endpoint (GET /rel/app-1.0/<path>) ----
    $rfPath = Join-Path $workDir 'release-file-tool.bin'
    $code = Get-Signed $Port '/rel/app-1.0/tool.bin' $rfPath '/rel/app-1.0/tool.bin'
    if ($code -ne '200') { throw "release-file GET tool.bin failed: $code" }
    $rfBytes = [System.IO.File]::ReadAllBytes($rfPath)
    if (-not (BytesEqual $rfBytes $toolBytes)) { throw "release-file tool.bin mismatch" }
    $code = Get-Signed $Port '/rel/app-1.0/config.json' $rfPath '/rel/app-1.0/config.json'
    if ($code -ne '200') { throw "release-file GET config.json failed: $code" }
    $rfBytes = [System.IO.File]::ReadAllBytes($rfPath)
    if (-not (BytesEqual $rfBytes $configBytes)) { throw "release-file config.json mismatch" }
    $code = Get-Signed $Port '/rel/app-1.0/lib/x64/libfoo.so' $rfPath '/rel/app-1.0/lib/x64/libfoo.so'
    if ($code -ne '200') { throw "release-file GET libfoo.so failed: $code" }
    $rfBytes = [System.IO.File]::ReadAllBytes($rfPath)
    if (-not (BytesEqual $rfBytes $libBytes)) { throw "release-file libfoo.so mismatch" }
    Write-Host 'release-file endpoint OK (3 files via GET /rel/app-1.0/<path>)'

    # ---- release entry point: ?listing=1 direct listing + ?redirect ----
    $listingPath = Join-Path $workDir 'release-listing.txt'
    $code = Get-Signed $Port '/rel/app-1.0?listing=1' $listingPath '/rel/app-1.0'
    if ($code -ne '200') { throw "release ?listing failed: $code" }
    $listingText = [System.IO.File]::ReadAllText($listingPath)
    if ($listingText -notmatch 'RELEASE app-1.0 version=1 files=3 digest=') { throw "listing header missing: $listingText" }
    if ($listingText -notmatch 'lib/x64/libfoo.so rel/libfoo 1234 ') { throw "listing deep path missing: $listingText" }
    Write-Host 'release ?listing=1 OK (direct listing download)'

    $hostHeader = "127.0.0.1:$Port"
    $amzdate = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $auth = Sign-Request $hostHeader 'GET' '/rel/app-1.0' ([byte[]]@()) $amzdate
    $payloadHash = Sha256Hex ([byte[]]@())
    $hdrOut = Join-Path $workDir 'redirect-headers.txt'
    $code = & curl.exe -s -o NUL -D $hdrOut -w '%{http_code}' `
        -H "Authorization: $auth" -H "x-amz-content-sha256: $payloadHash" -H "x-amz-date: $amzdate" `
        "http://127.0.0.1:$Port/rel/app-1.0?redirect=release.txt"
    if ($code -ne '302') { throw "release ?redirect status $code" }
    $hdrText = [System.IO.File]::ReadAllText($hdrOut)
    if ($hdrText -notmatch 'Location: /rel/app-1.0/release.txt') { throw "redirect Location missing: $hdrText" }
    Write-Host 'release ?redirect OK (302 -> /rel/app-1.0/release.txt)'

    # ---- integrity: pull must reject a corrupted gateway object ----
    $corrupt = New-Object byte[] 5000
    for ($i = 0; $i -lt $corrupt.Length; $i++) { $corrupt[$i] = [byte]((0xff - ($i -band 0xff)) -band 0xff) }
    $code = Put-Bytes $Port '/rel/tool' $corrupt
    if ($code -ne '200') { throw "corrupt PUT failed: $code" }
    $outDir3 = Join-Path $workDir 'downloaded-corrupt'
    New-Item -ItemType Directory -Force -Path $outDir3 | Out-Null
    $pull3 = (& $mediaBin release pull 'app-1.0' $outDir3 --gateway "127.0.0.1:$Port" 2>&1 | Out-String)
    if ($LASTEXITCODE -eq 0) { throw "corrupted release pull unexpectedly succeeded: $pull3" }
    if ($pull3 -notmatch 'integrity mismatch') { throw "integrity failure not reported: $pull3" }
    Write-Host 'release integrity check OK (corrupted object rejected)'

    # ---- publisher signature: tampered sidecar must fail verification ----
    $sigPath = Join-Path $workDir 'release.sig'
    $code = Get-Signed $Port '/rel/app-1.0.sig' $sigPath '/rel/app-1.0.sig'
    if ($code -ne '200') { throw "sig GET failed: $code" }
    $sigBytes = [System.IO.File]::ReadAllBytes($sigPath)
    $sigBytes[40] = $sigBytes[40] -bxor 0xff
    $code = Put-Bytes $Port '/rel/app-1.0.sig' $sigBytes
    if ($code -ne '200') { throw "tampered sig PUT failed: $code" }
    $outDir4 = Join-Path $workDir 'downloaded-tampered-sig'
    New-Item -ItemType Directory -Force -Path $outDir4 | Out-Null
    $pull4 = (& $mediaBin release pull 'app-1.0' $outDir4 --gateway "127.0.0.1:$Port" --pubkey $releasePubkey 2>&1 | Out-String)
    if ($LASTEXITCODE -eq 0) { throw "tampered signature pull unexpectedly succeeded: $pull4" }
    if ($pull4 -notmatch 'release signature verification failed') { throw "sig failure not reported: $pull4" }
    Write-Host 'release signature check OK (tampered sidecar rejected)'

    Write-Host '== release download smoke PASSED =='
    exit 0
} finally {
    foreach ($p in $procs) {
        if ($p -and -not $p.HasExited) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}
