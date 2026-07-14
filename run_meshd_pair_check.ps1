[CmdletBinding()]
param(
    [ValidateSet('Run', 'Status', 'Logs', 'Stop')]
    [string]$Action = 'Run',

    [string]$RemoteHost = 'root@eu',
    [string]$RemoteRepoDir = '/root/code/turbo-p2p',
    [string]$RemoteRunner = '',
    [string]$RemoteMeshdBin = '/root/code/turbo-p2p/build/linux-gcc-release/bin/meshd',
    [string]$RemoteBootstrapConfig = '/root/code/turbo-p2p/mesh/examples/mesh.eu.yaml',
    [string]$RemoteJoinerConfig = '/root/code/turbo-p2p/mesh/examples/mesh.local.yaml',
    [string]$RemoteLdLibraryPath = '/root/code/turbo-p2p/build/linux-gcc-release/bin:/root/code/turbonet/build/linux-gcc-release/bin:/opt/turbonet/lib',
    [string]$ConnectWaitSecs = '20',
    [string]$ConnectPollSecs = '2'
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RemoteRunner)) {
    $RemoteRunner = "$RemoteRepoDir/run_meshd_remote_pair_check.sh"
}

function ConvertTo-BashLiteral {
    param([string]$Value)

    if ($null -eq $Value -or $Value.Length -eq 0) {
        return "''"
    }

    return "'" + ($Value -replace "'", "'""'""'") + "'"
}

function Invoke-SshCommand {
    param([string]$RemoteCommand)

    & ssh $RemoteHost $RemoteCommand
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "remote pair check failed with exit code $exitCode"
    }
}

$parts = @(
    'env',
    "LD_LIBRARY_PATH_VALUE=$RemoteLdLibraryPath",
    'bash',
    $RemoteRunner,
    '--action',
    $Action.ToLowerInvariant(),
    '--repo-dir',
    $RemoteRepoDir,
    '--meshd-bin',
    $RemoteMeshdBin,
    '--bootstrap-config',
    $RemoteBootstrapConfig,
    '--joiner-config',
    $RemoteJoinerConfig,
    '--connect-wait-secs',
    $ConnectWaitSecs,
    '--connect-poll-secs',
    $ConnectPollSecs
)

$remoteCommand = ($parts | ForEach-Object { ConvertTo-BashLiteral $_ }) -join ' '
Invoke-SshCommand -RemoteCommand $remoteCommand
