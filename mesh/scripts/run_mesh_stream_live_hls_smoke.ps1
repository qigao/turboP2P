# run_mesh_stream_live_hls_smoke.ps1 - live-over-HTTP smoke.
#
# Starts the live HLS demo server (producer feeds the sliding-window playlist;
# HTTP serves /live.m3u8 + /live/seg-N), then acts as a live client: polls the
# playlist and watches EXT-X-MEDIA-SEQUENCE advance (liveness), fetches a
# current segment, and confirms an evicted segment 404s (LIVE_SKIP). Exits 0
# on success.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File mesh/scripts/run_mesh_stream_live_hls_smoke.ps1

param(
    [int] $Port = 20105,
    [string] $BuildDir = "build\Msvc-Release"
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$bin = Join-Path (Join-Path $repoRoot $BuildDir) 'bin\mesh_stream_live_hls_main.exe'

if (-not (Test-Path $bin)) {
    Write-Error "live hls binary not found: $bin"
}

$workDir = Join-Path $env:TEMP ("m3-live-hls-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null
$out = Join-Path $workDir 'live.out'
$err = Join-Path $workDir 'live.err'

$proc = Start-Process -FilePath $bin `
    -ArgumentList @("--port", "$Port", "--segments", "6", "--interval-ms", "300", "--window", "3") `
    -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err -PassThru

function Get-Playlist {
    return (& curl.exe -s "http://127.0.0.1:$Port/live.m3u8")
}
function Get-SegmentStatus([string] $seg, [string] $outPath) {
    return (& curl.exe -s -o $outPath -w '%{http_code}' "http://127.0.0.1:$Port/live/$seg")
}

try {
    # Wait for the server and the first segment to be live.
    $seq1 = $null
    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline) {
        try {
            $pl = [string]::Join("`n", @(Get-Playlist))
            if ($pl -match '#EXT-X-MEDIA-SEQUENCE:(\d+)') { $seq1 = [long]$Matches[1]; break }
        } catch { }
        Start-Sleep -Milliseconds 200
    }
    if ($null -eq $seq1) { throw "live playlist never appeared" }
    Write-Host "playlist 1: media-sequence=$seq1"
    if ($pl -notmatch '#EXTM3U') { throw "missing #EXTM3U" }
    if ($pl -match '#EXT-X-ENDLIST') { throw "live playlist must not end" }

    # Wait for the live edge to advance (liveness).
    Start-Sleep -Milliseconds 700
    $pl2 = [string]::Join("`n", @(Get-Playlist))
    if ($pl2 -notmatch '#EXT-X-MEDIA-SEQUENCE:(\d+)') { throw "playlist 2 missing sequence" }
    $seq2 = [long]$Matches[1]
    Write-Host "playlist 2: media-sequence=$seq2"
    if ($seq2 -le $seq1) { throw "media sequence did not advance ($seq1 -> $seq2)" }

    # Fetch the latest listed segment (200, 256 bytes).
    $seg = $null
    foreach ($m in [regex]::Matches($pl2, 'seg-(\d+)')) { $seg = $m.Groups[1].Value }
    if (-not $seg) { throw "no segment in playlist" }
    $segPath = Join-Path $workDir 'seg.bin'
    $code = Get-SegmentStatus "seg-$seg" $segPath
    if ($code -ne '200') { throw "segment $seg not served with 200: $code" }
    $segBytes = [System.IO.File]::ReadAllBytes($segPath)
    if ($segBytes.Length -ne 256) { throw "segment $seg length $($segBytes.Length) != 256" }
    Write-Host "segment ${seg}: 200 OK (256 bytes)"

    # An evicted segment (index < first in window) 404s -> LIVE_SKIP.
    $first = [long]0
    if ($pl2 -match '#EXT-X-MEDIA-SEQUENCE:(\d+)') { $first = [long]$Matches[1] }
    if ($first -gt 0) {
        $evicted = $first - 1
        $evPath = Join-Path $workDir 'evicted.bin'
        $code = Get-SegmentStatus "seg-$evicted" $evPath
        if ($code -ne '404') { throw "evicted segment $evicted did not 404: $code" }
        Write-Host "evicted segment ${evicted}: 404 OK (LIVE_SKIP)"
    }

    Write-Host '== live-over-HTTP smoke PASSED =='
    exit 0
} finally {
    if ($proc -and -not $proc.HasExited) {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}