[CmdletBinding()]
param(
    [ValidateSet('Local', 'Remote')]
    [string]$Target = 'Remote',

    [ValidateSet('Run', 'Start', 'Status', 'Logs', 'Verify', 'Stop')]
    [string]$Action = 'Run',

    [string]$RemoteHost = 'root@eu',
    [string]$RemoteRepoDir = '/root/code/turbo-p2p',
    [string]$RemoteRunner = '',
    [string]$RemoteMeshdBin = '/root/code/turbo-p2p/build/linux-gcc-release/bin/meshd',
    [string]$RemoteConfig = '/root/code/turbo-p2p/mesh/examples/mesh.eu.yaml',
    [string]$RemoteStatusFile = '/tmp/meshd-status.json',
    [string]$RemoteSessionPrefix = '',
    [string]$RemoteLdLibraryPath = '/root/code/turbo-p2p/build/linux-gcc-release/bin:/root/code/turbonet/build/linux-gcc-release/bin:/opt/turbonet/lib',
    [string]$StatusIntervalMs = '200',
    [string]$StartWaitSecs = '3',
    [string]$StatusLines = '80',
    [string]$DoctorBeforeStart = '1'
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RemoteRunner)) {
    $RemoteRunner = "$RemoteRepoDir/run_meshd_remote_status_check.sh"
}

function Invoke-SshCommand {
    param([string[]]$RemoteArgs)

    $output = & ssh $RemoteHost @RemoteArgs 2>&1
    $exitCode = $LASTEXITCODE

    foreach ($line in $output) {
        Write-Output $line
    }
    return $exitCode
}

function Get-RemoteRunnerArgs {
    param([string]$RemoteAction)

    return @(
        'env',
        "LD_LIBRARY_PATH_VALUE=$RemoteLdLibraryPath",
        'bash',
        $RemoteRunner,
        '--action',
        $RemoteAction.ToLowerInvariant(),
        '--repo-dir',
        $RemoteRepoDir,
        '--meshd-bin',
        $RemoteMeshdBin,
        '--config',
        $RemoteConfig,
        '--status-file',
        $RemoteStatusFile,
        '--status-interval-ms',
        $StatusIntervalMs,
        '--start-wait-secs',
        $StartWaitSecs,
        '--status-lines',
        $StatusLines,
        '--doctor-before-start',
        $DoctorBeforeStart,
        $(if (-not [string]::IsNullOrWhiteSpace($RemoteSessionPrefix)) {
            @('--session-prefix', $RemoteSessionPrefix)
        } else {
            @()
        })
    )
}

function Invoke-LocalTarget {
    throw "Local target is not implemented for meshd TUN status checks. Use -Target Remote."
}

function Invoke-RemoteTarget {
    $remoteArgs = Get-RemoteRunnerArgs -RemoteAction $Action
    $exitCode = Invoke-SshCommand -RemoteArgs $remoteArgs
    exit $exitCode
}

if ($Target -eq 'Local') {
    Invoke-LocalTarget
} else {
    Invoke-RemoteTarget
}
