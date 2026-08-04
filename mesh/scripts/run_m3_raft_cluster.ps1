# run_m3_raft_cluster.ps1 - Phase 2b-ii step 3: three-process CoroNet TLS raft cluster e2e.
#
# Starts node1/2/3 (m3_raft_node_main) on 127.0.0.1, waits for leader election,
# for the probe PUT to commit (PROBE-COMMITTED), and for all three applied
# indices to converge to at least the committed index. Exits 0 on success.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File mesh/scripts/run_m3_raft_cluster.ps1

param(
    [int] $BasePort = 19501,
    [int] $TimeoutSec = 60,
    [string] $BuildDir = "build\Msvc-Release"
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$tlsDir   = Join-Path $repoRoot 'mesh\tests\data\m3tls'
$bin      = Join-Path (Join-Path $repoRoot $BuildDir) 'bin\m3_raft_node_main.exe'

if (-not (Test-Path $bin)) {
    Write-Error "node binary not found: $bin (build first: cmake --build --preset win-release-user --target m3_raft_node_main)"
}

# sha256 fingerprints of mesh/tests/data/m3tls/node{1,2,3}.crt
$fingerprints = @(
    'sha256:a9a12784e612bd3ced3dbc4ec6b9f1f58b84a4592650fda8be88f5d777f49800',
    'sha256:66a4ee96d3c72dacc600ecda40ff0d3a308e2bf06a1ff2d45e74d36d88e7f465',
    'sha256:56fdbb74472b0d77a2fc182a44be32a41c4b9dbfab34a6cc68374b50066d24e1'
)
$ports = @($BasePort, ($BasePort + 1), ($BasePort + 2))

$workDir = Join-Path $env:TEMP ("m3-raft-cluster-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $workDir | Out-Null
$stdout = @($null, $null, $null)
$stderr = @($null, $null, $null)
$procs  = @($null, $null, $null)

function Start-Node([int] $id) {
    $args = @(
        '--node-id', "$id",
        '--listen-host', '127.0.0.1',
        '--listen-port', "$($ports[$id - 1])",
        '--sqlite', ':memory:',
        '--cert',  (Join-Path $tlsDir "node$id.crt"),
        '--key',   (Join-Path $tlsDir "node$id.key"),
        '--ca',    (Join-Path $tlsDir 'm3ca.crt'),
        '--voter', '1', '--voter', '2', '--voter', '3',
        '--probe-put'
    )
    for ($p = 1; $p -le 3; $p++) {
        if ($p -ne $id) {
            $args += '--peer'
            $args += "$p@127.0.0.1:$($ports[$p - 1]):$($fingerprints[$p - 1])"
        }
    }
    $out = Join-Path $workDir "node$id.out"
    $err = Join-Path $workDir "node$id.err"
    $stdout[$id - 1] = $out
    $stderr[$id - 1] = $err
    $procs[$id - 1] = Start-Process -FilePath $bin -ArgumentList $args `
        -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err -PassThru
    Write-Host ("node {0} pid={1} port={2}" -f $id, $procs[$id - 1].Id, ($ports[$id - 1]))
}

function Stop-Nodes {
    foreach ($p in $procs) {
        if ($null -ne $p -and -not $p.HasExited) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-LastApplied([int] $id) {
    if (-not (Test-Path $stdout[$id - 1])) { return $null }
    $line = Get-Content $stdout[$id - 1] -ErrorAction SilentlyContinue |
        Select-String -Pattern 'node \d+ leader=\d applied=(\d+)' |
        Select-Object -Last 1
    if ($null -eq $line -or $line.Matches.Count -eq 0) { return $null }
    return [uint64]$line.Matches[0].Groups[1].Value
}

function Get-ProbeCommittedIndex {
    for ($id = 1; $id -le 3; $id++) {
        if (-not (Test-Path $stdout[$id - 1])) { continue }
        $line = Get-Content $stdout[$id - 1] -ErrorAction SilentlyContinue |
            Select-String -Pattern 'PROBE-COMMITTED node=(\d+) index=(\d+)' |
            Select-Object -Last 1
        if ($null -ne $line -and $line.Matches.Count -gt 0) {
            return [uint64]$line.Matches[0].Groups[2].Value
        }
    }
    return $null
}

function Any-Leader {
    for ($id = 1; $id -le 3; $id++) {
        if (-not (Test-Path $stdout[$id - 1])) { continue }
        $line = Get-Content $stdout[$id - 1] -ErrorAction SilentlyContinue |
            Select-String -Pattern 'leader=1' | Select-Object -Last 1
        if ($null -ne $line) { return $true }
    }
    return $false
}

$ok = $false
try {
    for ($id = 1; $id -le 3; $id++) { Start-Node $id }

    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $committed = $null
    $leaderSeen = $false

    while ((Get-Date) -lt $deadline) {
        if ($null -eq $committed) {
            $committed = Get-ProbeCommittedIndex
        }
        if (-not $leaderSeen) {
            $leaderSeen = Any-Leader
        }
        if ($null -ne $committed) {
            $all = $true
            for ($id = 1; $id -le 3; $id++) {
                if ($procs[$id - 1].HasExited) {
                    Write-Host ("FAIL: node {0} exited early (see {1})" -f $id, $stderr[$id - 1])
                    $all = $false
                    break
                }
                $applied = Get-LastApplied $id
                if ($null -eq $applied -or $applied -lt $committed) {
                    $all = $false
                }
            }
            if ($all) {
                $ok = $leaderSeen
                break
            }
        }
        Start-Sleep -Milliseconds 500
    }

    if ($null -eq $committed) {
        Write-Host "FAIL: no PROBE-COMMITTED within ${TimeoutSec}s"
    } elseif (-not $leaderSeen) {
        Write-Host "FAIL: no leader elected"
    } elseif (-not $ok) {
        Write-Host "FAIL: applied indices did not converge to $committed within ${TimeoutSec}s"
    } else {
        Write-Host "PASS: probe committed at index $committed and all 3 nodes converged"
    }
}
finally {
    Stop-Nodes
    if (-not $ok) {
        Write-Host '--- node1.out ---'
        Get-Content $stdout[0] -ErrorAction SilentlyContinue
        Write-Host '--- node2.out ---'
        Get-Content $stdout[1] -ErrorAction SilentlyContinue
        Write-Host '--- node3.out ---'
        Get-Content $stdout[2] -ErrorAction SilentlyContinue
        foreach ($e in $stderr) {
            if ((Test-Path $e) -and (Get-Item $e).Length -gt 0) {
                Write-Host "--- $e ---"
                Get-Content $e
            }
        }
    }
    Remove-Item -Recurse -Force $workDir -ErrorAction SilentlyContinue
}

exit $(if ($ok) { 0 } else { 1 })
