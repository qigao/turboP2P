# run_mesh_stream_live_failover_smoke.ps1 - live HLS cross-gateway failover.
#
# Two live HLS gateways (mesh_stream_live_hls_main) produce the same
# deterministic live session. The failover client watches the primary; when
# the primary is killed, it switches to the backup and serves the same segment
# index. The smoke verifies (1) both gateways serve byte-identical segments,
# and (2) after the primary dies, the client fails over to the backup.
# Exits 0 on success.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File mesh/scripts/run_mesh_stream_live_failover_smoke.ps1

param(
    [int] $PrimaryPort = 20151,
    [int] $BackupPort = 20152,
    [string] $BuildDir = "build\Msvc-Release"
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$serverBin = Join-Path (Join-Path $repoRoot $BuildDir) 'bin\mesh_stream_live_hls_main.exe'
$clientBin = Join-Path (Join-Path $repoRoot $BuildDir) 'bin\mesh_stream_live_client_main.exe'

if (-not (Test-Path $serverBin) -or -not (Test-Path $clientBin)) {
    Write-Error "live server/client binaries not found in $BuildDir\bin"
}

$workDir = Join-Path $env:TEMP ("m3-live-failover-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null

$procs = @()
function Start-Live([int] $port, [string] $tag) {
    $out = Join-Path $workDir "$tag.out"
    $err = Join-Path $workDir "$tag.err"
    $p = Start-Process -FilePath $serverBin `
        -ArgumentList @("--port", "$port", "--segments", "8", "--interval-ms", "150", "--window", "3") `
        -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
    $script:procs += $p
    return $p
}
function Get-Playlist([int] $port) {
    return (& curl.exe -s "http://127.0.0.1:$port/live.m3u8")
}
function Wait-LiveEdge([int] $port, [long] $minSeq) {
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {
        try {
            $pl = [string]::Join("`n", @(Get-Playlist $port))
            if ($pl -match '#EXT-X-MEDIA-SEQUENCE:(\d+)') {
                if ([long]$Matches[1] -ge $minSeq) { return }
            }
        } catch { }
        Start-Sleep -Milliseconds 200
    }
    throw "live gateway on port $port never reached media-sequence $minSeq"
}

try {
    Write-Host "== live gateways (primary :$PrimaryPort, backup :$BackupPort) =="
    $primary = Start-Live $PrimaryPort 'primary'
    $backup = Start-Live $BackupPort 'backup'
    # 8 segments at 150ms fill the window (last 3 = seg 5..7); wait for them.
    Wait-LiveEdge $PrimaryPort 5
    Wait-LiveEdge $BackupPort 5
    Write-Host 'both gateways live (media-sequence >= 5)'

    # ---- phase 1: both gateways serve byte-identical segments ----
    Write-Host '== phase 1: identical content on primary and backup =='
    $r1 = (& $clientBin --primary "127.0.0.1:$PrimaryPort" --backup "127.0.0.1:$BackupPort" --segment 5 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "failover verify failed: $r1" }
    if ($r1 -notmatch 'PRIMARY seg-5 OK') { throw "primary seg-5 not served: $r1" }
    if ($r1 -notmatch 'LIVE FAILOVER VERIFY OK seg=5 bytes=256') { throw "identical-content check missing: $r1" }
    if ($r1 -notmatch 'LIVE BACKUP PLAYLIST OK') { throw "backup playlist check missing: $r1" }
    Write-Host 'phase 1 OK (identical 256-byte segment on both gateways)'

    # ---- phase 2: primary dies; client switches to backup ----
    Write-Host '== phase 2: failover after primary death =='
    Stop-Process -Id $primary.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300
    $r2 = (& $clientBin --primary "127.0.0.1:$PrimaryPort" --backup "127.0.0.1:$BackupPort" --segment 6 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "failover failed: $r2" }
    if ($r2 -notmatch 'PRIMARY seg-6 unreachable') { throw "primary should be unreachable: $r2" }
    if ($r2 -notmatch 'LIVE FAILOVER OK seg=6 served-by=backup bytes=256') { throw "backup failover missing: $r2" }
    Write-Host 'phase 2 OK (client switched to backup after primary death)'

    Write-Host '== live failover smoke PASSED =='
    exit 0
} finally {
    foreach ($p in $procs) {
        if ($p -and -not $p.HasExited) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}
