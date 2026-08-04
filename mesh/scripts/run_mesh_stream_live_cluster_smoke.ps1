# run_mesh_stream_live_cluster_smoke.ps1 - multi-node live distribution.
#
# source (KCP client, produces live blocks) -> relay (KCP server feeds the
# sliding-window HLS live playlist) -> HTTP client (polls /live.m3u8 and
# fetches segments). Proves live blocks travel over KCP between two processes
# and are served as HLS over HTTP. Exits 0 on success.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File mesh/scripts/run_mesh_stream_live_cluster_smoke.ps1

param(
    [int] $HttpPort = 20107,
    [int] $KcpPort = 20108,
    [string] $BuildDir = "build\Msvc-Release"
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$bin = Join-Path (Join-Path $repoRoot $BuildDir) 'bin'
$relayBin = Join-Path $bin 'mesh_stream_live_hls_main.exe'
$sourceBin = Join-Path $bin 'mesh_stream_live_source_main.exe'

if (-not (Test-Path $relayBin) -or -not (Test-Path $sourceBin)) {
    Write-Error "live relay/source binaries not found in $BuildDir\bin"
}

$workDir = Join-Path $env:TEMP ("m3-live-cluster-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

$relayProc = Start-Process -FilePath $relayBin `
    -ArgumentList @("--port", "$HttpPort", "--kcp-port", "$KcpPort", "--window", "4") `
    -WindowStyle Hidden -RedirectStandardOutput (Join-Path $workDir 'relay.out') `
    -RedirectStandardError (Join-Path $workDir 'relay.err') -PassThru
Start-Sleep -Milliseconds 500
$sourceProc = Start-Process -FilePath $sourceBin `
    -ArgumentList @("--port", "$KcpPort", "--segments", "6", "--block", "256") `
    -WindowStyle Hidden -RedirectStandardOutput (Join-Path $workDir 'source.out') `
    -RedirectStandardError (Join-Path $workDir 'source.err') -PassThru

function Get-Playlist {
    return (& curl.exe -s "http://127.0.0.1:$HttpPort/live.m3u8")
}

try {
    # Wait for the relay to serve a playlist that lists live segments (the
    # source's blocks must have traveled over KCP into the HLS window).
    $pl = ""
    $seg = $null
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {
        try {
            $pl = [string]::Join("`n", @(Get-Playlist))
            if ($pl -match '#EXTM3U' -and $pl -match 'seg-(\d+)') {
                $seg = $Matches[1]
                break
            }
        } catch { }
        Start-Sleep -Milliseconds 200
    }
    if ($null -eq $seg) {
        Get-Content -LiteralPath (Join-Path $workDir 'relay.err') -Raw -ErrorAction SilentlyContinue
        throw "relay never served a live segment"
    }
    if ($pl -notmatch '#EXT-X-MEDIA-SEQUENCE:(\d+)') { throw "playlist missing media sequence" }
    $seq = $Matches[1]
    Write-Host "relay playlist: media-sequence=$seq (live segments arrived via KCP)"

    $segPath = Join-Path $workDir 'seg.bin'
    $code = (& curl.exe -s -o $segPath -w '%{http_code}' "http://127.0.0.1:$HttpPort/live/seg-$seg")
    if ($code -ne '200') { throw "segment $seg not served: $code" }
    $bytes = [System.IO.File]::ReadAllBytes($segPath)
    if ($bytes.Length -ne 256) { throw "segment length $($bytes.Length) != 256" }
    Write-Host "segment ${seg}: 200 OK (256 bytes over KCP + HTTP)"

    Write-Host '== multi-node live distribution smoke PASSED =='
    exit 0
} finally {
    foreach ($p in @($sourceProc, $relayProc)) {
        if ($p -and -not $p.HasExited) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}