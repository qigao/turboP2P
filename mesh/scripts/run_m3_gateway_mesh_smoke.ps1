# run_m3_gateway_mesh_smoke.ps1 - M3 cross-process mesh data-plane smoke.
#
# Starts two store nodes serving chunk PUT/GET over p2p (authenticated,
# capability-signed), one gateway (local metadata) that dials both stores over
# mesh, then drives a signed S3 PUT + GET through the gateway HTTP endpoint and
# verifies the object round-trips via the replicated mesh stores.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File mesh/scripts/run_m3_gateway_mesh_smoke.ps1

param(
    [int] $GatewayPort = 20091,
    [int] $MeshBasePort = 20421,
    [string] $BuildDir = "build\Msvc-Release"
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$gatewayBin = Join-Path (Join-Path $repoRoot $BuildDir) 'bin\m3_gateway_main.exe'
$storeBin   = Join-Path (Join-Path $repoRoot $BuildDir) 'bin\m3_store_node_main.exe'

if (-not (Test-Path $gatewayBin) -or -not (Test-Path $storeBin)) {
    Write-Error "gateway/store binaries not found in $BuildDir\bin"
}

# Gateway identity: the same 32-byte key drives the p2p X25519 channel identity
# and the Ed25519 capability signer. The stores allowlist its Ed25519 public key.
$gwKeyHex = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
$store1KeyHex = '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb'
$store2KeyHex = '6b0e1e5a2c7f9d4e8b3f5a1c7d9e2b4f6a8c0e2d4f6a8b0c1d3e5f7a9b0c1d3e'
$store1IdHex = '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f'
$store2IdHex = '303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f'
$store1Root = Join-Path $env:TEMP ("m3-mesh-store1-" + [guid]::NewGuid().ToString('N'))
$store2Root = Join-Path $env:TEMP ("m3-mesh-store2-" + [guid]::NewGuid().ToString('N'))
$gwRoot     = Join-Path $env:TEMP ("m3-mesh-gw-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $store1Root, $store2Root, $gwRoot | Out-Null

$store1Port = $MeshBasePort
$store2Port = $MeshBasePort + 1
$gwMeshPort = $MeshBasePort + 2

$procs = @()
$outFiles = @()

function Start-Proc([string] $file, [string[]] $argList, [string] $tag) {
    $tagId = [guid]::NewGuid().ToString('N')
    $out = Join-Path $env:TEMP ("m3-mesh-" + $tag + "-" + $tagId + ".out")
    $err = Join-Path $env:TEMP ("m3-mesh-" + $tag + "-" + $tagId + ".err")
    $p = Start-Process -FilePath $file -ArgumentList $argList -WindowStyle Hidden `
        -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
    $script:procs += $p
    $script:outFiles += @($out, $err)
    return $p
}

function Stop-All {
    foreach ($p in $script:procs) {
        if ($p -and -not $p.HasExited) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }
    foreach ($f in $script:outFiles) {
        Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
    }
}

try {
    Write-Host '== starting store 1 (mesh) =='
    $p1 = Start-Proc $storeBin @(
        '--root', $store1Root, '--node-id', $store1IdHex, '--key', $store1KeyHex,
        '--mesh-serve', '--mesh-listen', "$store1Port",
        '--trusted-gateway', $gwKeyHex) 'store1'
    Write-Host '== starting store 2 (mesh) =='
    $p2 = Start-Proc $storeBin @(
        '--root', $store2Root, '--node-id', $store2IdHex, '--key', $store2KeyHex,
        '--mesh-serve', '--mesh-listen', "$store2Port",
        '--trusted-gateway', $gwKeyHex) 'store2'

    # Wait for the stores to print their serving line with the pubkey.
    $store1Pub = $null
    $store2Pub = $null
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        if (-not $store1Pub) {
            $line = Get-Content -LiteralPath $outFiles[0] -Raw -ErrorAction SilentlyContinue
            if ($line -match 'pubkey=([0-9a-f]{64})') { $store1Pub = $Matches[1] }
        }
        if (-not $store2Pub) {
            $line = Get-Content -LiteralPath $outFiles[2] -Raw -ErrorAction SilentlyContinue
            if ($line -match 'pubkey=([0-9a-f]{64})') { $store2Pub = $Matches[1] }
        }
        if ($store1Pub -and $store2Pub) { break }
        Start-Sleep -Milliseconds 200
    }
    if (-not $store1Pub -or -not $store2Pub) {
        Write-Host '--- store1 out ---'
        Get-Content -LiteralPath $outFiles[0] -Raw -ErrorAction SilentlyContinue
        Write-Host '--- store1 err ---'
        Get-Content -LiteralPath $outFiles[1] -Raw -ErrorAction SilentlyContinue
        Write-Host '--- store2 out ---'
        Get-Content -LiteralPath $outFiles[2] -Raw -ErrorAction SilentlyContinue
        Write-Host '--- store2 err ---'
        Get-Content -LiteralPath $outFiles[3] -Raw -ErrorAction SilentlyContinue
        throw "stores did not report pubkeys: $store1Pub / $store2Pub"
    }
    Write-Host "store1 pubkey=$store1Pub"
    Write-Host "store2 pubkey=$store2Pub"

    Write-Host '== starting gateway (mesh) =='
    $pgw = Start-Proc $gatewayBin @(
        $gwRoot, "$GatewayPort",
        '--max-chunk', '32768',
        '--mesh-listen', "$gwMeshPort", '--mesh-key', $gwKeyHex,
        '--store-peer', "$store1IdHex`:$store1Pub@127.0.0.1:$store1Port",
        '--store-peer', "$store2IdHex`:$store2Pub@127.0.0.1:$store2Port") 'gw'

    # Wait for the gateway HTTP endpoint to answer (403 on an unsigned request
    # proves the server and auth path are live).
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
    if (-not $ready) { throw 'gateway HTTP not ready' }

    # Signed S3 PUT + GET (SigV4) through the gateway.
    $hostHeader = "127.0.0.1:$GatewayPort"
    $secretHex = '606162636465666768696a6b6c6d6e6f707172737475767778797a3031323334'
    $body = 'mesh-data-plane-roundtrip'

    function HexBytes([string] $hex) {
        $bytes = New-Object byte[] ($hex.Length / 2)
        for ($i = 0; $i -lt $bytes.Length; $i++) {
            $bytes[$i] = [Convert]::ToByte($hex.Substring($i * 2, 2), 16)
        }
        return $bytes
    }
    function Sha256Hex([byte[]] $data) {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $h = $sha.ComputeHash($data)
        return ([BitConverter]::ToString($h) -replace '-', '').ToLowerInvariant()
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

    $amzdate = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $auth = Sign-Request 'PUT' '/bkt/obj' ([System.Text.Encoding]::UTF8.GetBytes($body)) $amzdate
    $payloadHash = Sha256Hex ([System.Text.Encoding]::UTF8.GetBytes($body))
    $putOut = & curl.exe -s -o NUL -w '%{http_code}' -X PUT `
        -H "Authorization: $auth" -H "x-amz-content-sha256: $payloadHash" -H "x-amz-date: $amzdate" `
        --data-binary $body "http://127.0.0.1:$GatewayPort/bkt/obj"
    if ($putOut -ne '200') { throw "PUT failed: $putOut" }

    $amzdate = (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
    $auth = Sign-Request 'GET' '/bkt/obj' ([byte[]]@()) $amzdate
    $payloadHash = Sha256Hex ([byte[]]@())
    $getOut = & curl.exe -s -X GET `
        -H "Authorization: $auth" -H "x-amz-content-sha256: $payloadHash" -H "x-amz-date: $amzdate" `
        "http://127.0.0.1:$GatewayPort/bkt/obj"
    if ($getOut -ne $body) { throw "GET round-trip mismatch: '$getOut'" }

    Write-Host "mesh S3 PUT/GET round-trip OK ($($body.Length) bytes via 2 mesh stores)"
}
finally {
    Stop-All
    Remove-Item -LiteralPath $store1Root, $store2Root, $gwRoot -Recurse -Force -ErrorAction SilentlyContinue
}
