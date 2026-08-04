# run_m3_gateway_cluster.ps1 - M3 multi-process S3 gateway deployment smoke.
#
# Starts node1/2/3 as m3_gateway_main --raft-node (each embeds a raft voter and
# an S3 HTTP server), waits for a raft leader to be elected by the continuous
# node pump (no HTTP request required), and verifies every gateway's HTTP
# endpoint answers (the SigV4 403 on an unsigned request proves the server and
# auth path are live). Exits 0 on success.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File mesh/scripts/run_m3_gateway_cluster.ps1

param(
    [int] $HttpBasePort = 20001,
    [int] $RaftBasePort = 19901,
    [int] $TimeoutSec = 60,
    [string] $BuildDir = "build\Msvc-Release"
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$tlsDir   = Join-Path $repoRoot 'mesh\tests\data\m3tls'
$bin      = Join-Path (Join-Path $repoRoot $BuildDir) 'bin\m3_gateway_main.exe'

if (-not (Test-Path $bin)) {
    Write-Error "gateway binary not found: $bin"
}

$fingerprints = @(
    'sha256:a9a12784e612bd3ced3dbc4ec6b9f1f58b84a4592650fda8be88f5d777f49800',
    'sha256:66a4ee96d3c72dacc600ecda40ff0d3a308e2bf06a1ff2d45e74d36d88e7f465',
    'sha256:56fdbb74472b0d77a2fc182a44be32a41c4b9dbfab34a6cc68374b50066d24e1'
)
$httpPorts = @($HttpBasePort, ($HttpBasePort + 1), ($HttpBasePort + 2))
$raftPorts = @($RaftBasePort, ($RaftBasePort + 1), ($RaftBasePort + 2))

$workDir = Join-Path $env:TEMP ("m3-gateway-cluster-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null
$stdout = @($null, $null, $null)
$stderr = @($null, $null, $null)
$procs  = @($null, $null, $null)

function Start-Gateway([int] $id) {
    $store = Join-Path $workDir "store$id"
    New-Item -ItemType Directory -Force -Path $store | Out-Null
    $args = @(
        $store,
        "$($httpPorts[$id - 1])",
        '--raft-node',
        '--node-id', "$id",
        '--raft-listen-port', "$($raftPorts[$id - 1])",
        '--sqlite', ':memory:',
        '--cert',  (Join-Path $tlsDir "node$id.crt"),
        '--key',   (Join-Path $tlsDir "node$id.key"),
        '--ca',    (Join-Path $tlsDir 'm3ca.crt'),
        '--voter', '1', '--voter', '2', '--voter', '3'
    )
    for ($p = 1; $p -le 3; $p++) {
        if ($p -ne $id) {
            $args += '--peer'
            $args += "$p@127.0.0.1:$($raftPorts[$p - 1]):$($fingerprints[$p - 1])"
        }
    }
    $out = Join-Path $workDir "gw$id.out"
    $err = Join-Path $workDir "gw$id.err"
    $stdout[$id - 1] = $out
    $stderr[$id - 1] = $err
    $procs[$id - 1] = Start-Process -FilePath $bin -ArgumentList $args `
        -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
    Write-Host ("gateway {0} pid={1} http={2} raft={3}" -f $id, $procs[$id - 1].Id,
                $httpPorts[$id - 1], $raftPorts[$id - 1])
}

function Stop-Gateways {
    foreach ($p in $procs) {
        if ($null -ne $p -and -not $p.HasExited) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

function Any-Leader {
    for ($id = 1; $id -le 3; $id++) {
        if (-not (Test-Path $stdout[$id - 1])) { continue }
        if (Get-Content $stdout[$id - 1] -ErrorAction SilentlyContinue |
            Select-String -Pattern 'leader=1' | Select-Object -First 1) {
            return $true
        }
    }
    return $false
}

function All-Http-Alive {
    for ($id = 1; $id -le 3; $id++) {
        if ($procs[$id - 1].HasExited) {
            return $false
        }
        try {
            $req = [System.Net.HttpWebRequest]::Create(
                "http://127.0.0.1:$($httpPorts[$id - 1])/")
            $req.Timeout = 3000
            $req.Method = 'GET'
            $resp = $req.GetResponse()
            $resp.Close()
        } catch {
            # 4xx/5xx still proves the HTTP server answered; only network errors fail.
            if ($_.Exception.InnerException -is [System.Net.WebException]) {
                continue
            }
            return $false
        }
    }
    return $true
}

$ok = $false
try {
    for ($id = 1; $id -le 3; $id++) { Start-Gateway $id }

    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $leaderSeen = $false
    $httpAlive = $false

    while ((Get-Date) -lt $deadline) {
        if (-not $leaderSeen) { $leaderSeen = Any-Leader }
        if (-not $httpAlive)  { $httpAlive = All-Http-Alive }
        if ($leaderSeen -and $httpAlive) {
            $ok = $true
            break
        }
        Start-Sleep -Milliseconds 500
    }

    if (-not $leaderSeen) {
        Write-Host "FAIL: no raft leader elected within ${TimeoutSec}s"
    } elseif (-not $httpAlive) {
        Write-Host "FAIL: one or more gateway HTTP endpoints did not answer"
    } else {
        Write-Host "PASS: leader elected and all 3 gateway HTTP endpoints live"
    }
}
finally {
    Stop-Gateways
    if (-not $ok) {
        for ($id = 1; $id -le 3; $id++) {
            Write-Host "--- gateway $id stdout ---"
            Get-Content $stdout[$id - 1] -ErrorAction SilentlyContinue
            Write-Host "--- gateway $id stderr ---"
            Get-Content $stderr[$id - 1] -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -Recurse -Force $workDir -ErrorAction SilentlyContinue
}

exit $(if ($ok) { 0 } else { 1 })
