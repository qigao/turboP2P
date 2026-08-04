# run_m3_store_node_smoke.ps1 - M3 store-node cross-process durability smoke.
#
# Publishes "hello" with store process A, reads it back with store process B
# (same store root, sequential exclusive locks), and checks the health
# snapshot. Exits 0 on success.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File mesh/scripts/run_m3_store_node_smoke.ps1

param(
    [string] $BuildDir = "build\Msvc-Release"
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$bin = Join-Path (Join-Path $repoRoot $BuildDir) 'bin\m3_store_node_main.exe'

if (-not (Test-Path $bin)) {
    Write-Error "store node binary not found: $bin"
}

# Fixed RFC 8032 test identity so both processes share the same node key.
$nodeIdHex = '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f'
$keyHex    = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'

$workDir = Join-Path $env:TEMP ("m3-store-node-smoke-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null
$root = Join-Path $workDir 'store'
New-Item -ItemType Directory -Force -Path $root | Out-Null

try {
    $common = @('--root', $root, '--node-id', $nodeIdHex, '--key', $keyHex)

    Write-Host '== process A: publish hello =='
    $putOut = (& $bin @common 'put' 'hello' 2>$null | Out-String)
    Write-Host $putOut
    if ($LASTEXITCODE -ne 0) { throw "put failed (exit $LASTEXITCODE)" }
    if ($putOut -notmatch 'PUT OK cid=([0-9a-f]{64})') {
        throw "put did not report a cid: $putOut"
    }
    $cid = $Matches[1]

    Write-Host '== process B: read back hello =='
    $getOut = (& $bin @common 'get' $cid '5' 2>$null | Out-String)
    Write-Host $getOut
    if ($LASTEXITCODE -ne 0) { throw "get failed (exit $LASTEXITCODE)" }
    if ($getOut -notmatch 'GET OK size=5 data=68656c6c6f') {
        throw "read-back mismatch: $getOut"
    }

    # Quota accounting is in-memory per process in V1, so only the structure
    # is asserted here; per-tenant quota semantics are covered by
    # test_m3_store_node in the same process.
    Write-Host '== process B: health =='
    $healthB = (& $bin @common 'health' 2>$null | Out-String)
    Write-Host $healthB
    if ($LASTEXITCODE -ne 0) { throw "health B failed (exit $LASTEXITCODE)" }
    if ($healthB -notmatch 'HEALTH domain=dc-a') {
        throw "health B mismatch: $healthB"
    }

    Write-Host 'store-node cross-process smoke OK'
}
finally {
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}
