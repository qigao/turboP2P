# run_mesh_stream_media_smoke.ps1 - media pipeline smoke (publish + range pull).
#
# Creates a deterministic media file, publishes it (chunked M3 V2 manifest +
# HLS-style playlists), then pulls a mid-file byte range and verifies the
# window bytes match the original slice. Exits 0 on success.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File mesh/scripts/run_mesh_stream_media_smoke.ps1

param(
    [string] $BuildDir = "build\Msvc-Release"
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$bin = Join-Path (Join-Path $repoRoot $BuildDir) 'bin\mesh_stream_media_main.exe'

if (-not (Test-Path $bin)) {
    Write-Error "media binary not found: $bin"
}

# Deterministic 100 KiB media file (chunked at the 64 KiB default block).
$workDir = Join-Path $env:TEMP ("mesh-media-smoke-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null
$dataPath = Join-Path $workDir 'media.bin'
$bytes = New-Object byte[] (100 * 1024)
for ($i = 0; $i -lt $bytes.Length; $i++) {
    $bytes[$i] = [byte](($i * 7 + ($i -shr 4) + 1) -band 0xff)
}
[System.IO.File]::WriteAllBytes($dataPath, $bytes)

try {
    Write-Host '== publish: manifest + playlists =='
    $publish = (& $bin publish $dataPath 2>$null | Out-String)
    Write-Host $publish
    if ($LASTEXITCODE -ne 0) { throw "publish failed (exit $LASTEXITCODE)" }
    if ($publish -notmatch 'PUBLISH OK .*size=102400 chunks=2') {
        throw "publish marker missing: $publish"
    }
    if ($publish -notmatch 'MANIFEST ([0-9a-f]+)') { throw "manifest missing: $publish" }
    $manifest = $Matches[1]
    if ($publish -notmatch '#EXT-X-BYTERANGE:102400@0') { throw "playlist byterange missing: $publish" }
    if ($publish -notmatch '#EXT-X-STREAM-INF:BANDWIDTH=') { throw "master playlist missing: $publish" }

    Write-Host '== pull: mid-file range =='
    $start = 50000
    $len = 3000
    $pull = (& $bin pull $dataPath $manifest $start $len 2>$null | Out-String)
    Write-Host $pull
    if ($LASTEXITCODE -ne 0) { throw "pull failed (exit $LASTEXITCODE)" }
    if ($pull -notmatch 'PULL OK start=50000 len=3000 window=3000') {
        throw "pull marker missing: $pull"
    }
    if ($pull -notmatch 'WINDOW ([0-9a-f]+)') { throw "window missing: $pull" }
    $windowHex = $Matches[1]

    # Expected slice hex.
    $slice = New-Object byte[] $len
    [Array]::Copy($bytes, $start, $slice, 0, $len)
    $expectedHex = [System.BitConverter]::ToString($slice).Replace('-', '').ToLowerInvariant()
    if ($windowHex -ne $expectedHex) {
        throw "window mismatch: got $windowHex expected $expectedHex"
    }

    Write-Host '== mesh-stream media smoke PASSED =='
    exit 0
} finally {
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}