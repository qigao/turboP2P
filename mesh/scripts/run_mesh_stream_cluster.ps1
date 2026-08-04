# run_mesh_stream_cluster.ps1 - real multi-process mesh-stream cluster smoke.
#
# Runs three separate mesh_stream_node_main processes: node A announces a
# mesh-stream/<id> service, node B announces mesh-sync/<object>, and node C
# decodes both canonical service records, discovers the services, applies QoS
# (the 10.99.0.0/16 subnet is denied) and accounts stream bandwidth. Asserts
# the CLUSTER OK marker. Exits 0 on success.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File mesh/scripts/run_mesh_stream_cluster.ps1

param(
    [string] $BuildDir = "build\Msvc-Release"
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$bin = Join-Path (Join-Path $repoRoot $BuildDir) 'bin\mesh_stream_node_main.exe'

if (-not (Test-Path $bin)) {
    Write-Error "mesh stream node binary not found: $bin"
}

$nodeA = '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f'
$nodeB = '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
$streamId = 'aabbccddeeff00112233445566778899'
$objectId = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'

Write-Host '== node A: announce mesh-stream service =='
$outA = (& $bin --node $nodeA announce stream $streamId --vip 10.0.0.1 --port 9001 --epoch 1 --ttl-ms 60000 2>$null | Out-String)
Write-Host $outA
if ($LASTEXITCODE -ne 0) { throw "announce A failed (exit $LASTEXITCODE)" }
if ($outA -notmatch 'ANNOUNCE OK dns=mesh-stream-') { throw "announce A marker missing: $outA" }
if ($outA -notmatch 'RECORD ([0-9a-f]+)') { throw "announce A record missing: $outA" }
$recordA = $Matches[1]

Write-Host '== node B: announce mesh-sync service =='
$outB = (& $bin --node $nodeB announce sync $objectId --vip 10.0.0.2 --port 9002 --epoch 1 --ttl-ms 60000 2>$null | Out-String)
Write-Host $outB
if ($LASTEXITCODE -ne 0) { throw "announce B failed (exit $LASTEXITCODE)" }
if ($outB -notmatch 'ANNOUNCE OK dns=mesh-sync-') { throw "announce B marker missing: $outB" }
if ($outB -notmatch 'RECORD ([0-9a-f]+)') { throw "announce B record missing: $outB" }
$recordB = $Matches[1]

Write-Host '== node C: discover stream + sync, QoS, bandwidth =='
$outC = (& $bin --node $nodeA discover stream $streamId --record $recordA --record $recordB 2>$null | Out-String)
Write-Host $outC
if ($LASTEXITCODE -ne 0) { throw "discover failed (exit $LASTEXITCODE)" }
if ($outC -notmatch 'DISCOVER OK count=1') { throw "discover count mismatch: $outC" }
if ($outC -notmatch 'FOUND node=101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f port=9001 vip=10.0.0.1') {
    throw "discover did not find node A: $outC"
}
if ($outC -notmatch 'CLUSTER OK nodes=2 streams=1 sync=1 denied=1 chunks=5 bytes=5120') {
    throw "CLUSTER OK marker missing or unexpected: $outC"
}

$outSync = (& $bin --node $nodeB discover sync $objectId --record $recordA --record $recordB 2>$null | Out-String)
Write-Host $outSync
if ($LASTEXITCODE -ne 0) { throw "discover sync failed (exit $LASTEXITCODE)" }
if ($outSync -notmatch 'FOUND node=202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f port=9002 vip=10.0.0.2') {
    throw "discover did not find node B: $outSync"
}

Write-Host '== node C: QoS gates =='
$qosOk = (& $bin qos $nodeA --vip 10.0.0.1 --direction in 2>$null | Out-String)
Write-Host $qosOk
if ($qosOk -notmatch 'QOS OK') { throw "expected QOS OK: $qosOk" }
$qosDenied = (& $bin qos $nodeA --vip 10.99.0.1 --direction in 2>$null | Out-String)
Write-Host $qosDenied
if ($qosDenied -notmatch 'QOS DENIED') { throw "expected QOS DENIED: $qosDenied" }

Write-Host '== mesh-stream cluster smoke PASSED =='
exit 0