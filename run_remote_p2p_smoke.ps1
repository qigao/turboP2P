[CmdletBinding()]
param(
    [ValidateSet('Run', 'Status', 'Logs', 'Stop')]
    [string]$Action = 'Run',

    [ValidateSet('', 'Core', 'Pair', 'Stun', 'StunThreeNode', 'StunMatrix', 'FullSmoke', 'FullThreeNode', 'FullMatrix')]
    [string]$Profile = '',

    [switch]$WithMeshdPair,
    [switch]$WithPublicStun,

    [string]$RemoteHost = 'root@eu',
    [string]$RemoteRepoDir = '/root/code/turbo-p2p',
    [string]$RemoteSessionPrefix = '',
    [string]$RemotePraktorRunner = '',
    [string]$RemotePraktorBin = '/root/code/praktor/build/linux-gcc-release/bin/praktor',
    [string]$RemotePraktorLogDir = '',
    [string]$RemotePraktorSessionPrefix = '',
    [int]$PraktorWaitTimeoutSecs = 900,
    [int]$PraktorWaitPollSecs = 3,

    [string]$RemoteMeshdRunner = '',
    [string]$RemoteMeshdBin = '/root/code/turbo-p2p/build/linux-gcc-release/bin/meshd',
    [string]$RemoteMeshdConfig = '/root/code/turbo-p2p/mesh/examples/mesh.eu.yaml',
    [string]$RemoteMeshdStatusFile = '/tmp/meshd-status.json',
    [string]$RemoteMeshdSessionPrefix = '',
    [string]$RemoteLdLibraryPath = '/root/code/turbo-p2p/build/linux-gcc-release/bin:/root/code/turbonet/build/linux-gcc-release/bin:/opt/turbonet/lib',

    [string]$RemoteMeshdPairRunner = '',
    [string]$RemoteMeshdPairBootstrapConfig = '/root/code/turbo-p2p/mesh/examples/mesh.eu.yaml',
    [string]$RemoteMeshdPairJoinerConfig = '/root/code/turbo-p2p/mesh/examples/mesh.local.yaml',
    [string]$RemoteMeshdPairBootstrapStatusFile = '/tmp/meshd-bootstrap-status.json',
    [string]$RemoteMeshdPairJoinerStatusFile = '/tmp/meshd-joiner-status.json',
    [string]$RemoteMeshdPairBootstrapSessionPrefix = '',
    [string]$RemoteMeshdPairJoinerSessionPrefix = '',
    [string]$RemoteMeshdPairConnectWaitSecs = '20',
    [string]$RemoteMeshdPairConnectPollSecs = '2',

    [string]$RemotePublicStunRunner = '',
    [string]$RemotePublicStunTmuxRunner = '',
    [string]$RemotePublicStunBinDir = '/root/code/turbo-p2p/build/linux-gcc-release/bin',
    [string]$RemotePublicStunSessionPrefix = '',
    [string]$RemotePublicStunLogDir = '',
    [ValidateSet('two-node', 'three-node', 'matrix')]
    [string]$RemotePublicStunScenario = 'two-node',
    [string]$RemotePublicStunUrl = '',
    [string]$RemotePublicStunAdvertiseIp = '',
    [string]$RemotePublicStunWorkdirRoot = '/tmp/mesh-public-stun-suite'
)

$ErrorActionPreference = 'Stop'

$ResolvedPublicStunWorkdirRoot = if ($RemotePublicStunWorkdirRoot -eq '/tmp/mesh-public-stun-suite') {
    '/tmp/mesh-public-stun-suite-' + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
} else {
    $RemotePublicStunWorkdirRoot
}

switch ($Profile) {
    'Core' {
    }
    'Pair' {
        $WithMeshdPair = $true
    }
    'Stun' {
        $WithPublicStun = $true
        if ($PSBoundParameters.ContainsKey('RemotePublicStunScenario') -and $RemotePublicStunScenario -ne 'two-node') {
            throw 'Profile Stun requires -RemotePublicStunScenario two-node'
        }
        $RemotePublicStunScenario = 'two-node'
    }
    'StunThreeNode' {
        $WithPublicStun = $true
        if ($PSBoundParameters.ContainsKey('RemotePublicStunScenario') -and $RemotePublicStunScenario -ne 'three-node') {
            throw 'Profile StunThreeNode requires -RemotePublicStunScenario three-node'
        }
        $RemotePublicStunScenario = 'three-node'
    }
    'StunMatrix' {
        $WithPublicStun = $true
        if ($PSBoundParameters.ContainsKey('RemotePublicStunScenario') -and $RemotePublicStunScenario -ne 'matrix') {
            throw 'Profile StunMatrix requires -RemotePublicStunScenario matrix'
        }
        $RemotePublicStunScenario = 'matrix'
    }
    'FullSmoke' {
        $WithMeshdPair = $true
        $WithPublicStun = $true
        if ($PSBoundParameters.ContainsKey('RemotePublicStunScenario') -and $RemotePublicStunScenario -ne 'two-node') {
            throw 'Profile FullSmoke requires -RemotePublicStunScenario two-node'
        }
        $RemotePublicStunScenario = 'two-node'
    }
    'FullThreeNode' {
        $WithMeshdPair = $true
        $WithPublicStun = $true
        if ($PSBoundParameters.ContainsKey('RemotePublicStunScenario') -and $RemotePublicStunScenario -ne 'three-node') {
            throw 'Profile FullThreeNode requires -RemotePublicStunScenario three-node'
        }
        $RemotePublicStunScenario = 'three-node'
    }
    'FullMatrix' {
        $WithMeshdPair = $true
        $WithPublicStun = $true
        if ($PSBoundParameters.ContainsKey('RemotePublicStunScenario') -and $RemotePublicStunScenario -ne 'matrix') {
            throw 'Profile FullMatrix requires -RemotePublicStunScenario matrix'
        }
        $RemotePublicStunScenario = 'matrix'
    }
}

if (-not [string]::IsNullOrWhiteSpace($RemoteSessionPrefix)) {
    if ([string]::IsNullOrWhiteSpace($RemotePraktorSessionPrefix)) {
        $RemotePraktorSessionPrefix = "$RemoteSessionPrefix-praktor"
    }

    if ([string]::IsNullOrWhiteSpace($RemoteMeshdSessionPrefix)) {
        $RemoteMeshdSessionPrefix = "$RemoteSessionPrefix-meshd"
    }

    if ($RemoteMeshdStatusFile -eq '/tmp/meshd-status.json') {
        $RemoteMeshdStatusFile = "/tmp/$RemoteSessionPrefix-meshd-status.json"
    }

    if ([string]::IsNullOrWhiteSpace($RemoteMeshdPairBootstrapSessionPrefix)) {
        $RemoteMeshdPairBootstrapSessionPrefix = "$RemoteSessionPrefix-meshd-bootstrap"
    }

    if ([string]::IsNullOrWhiteSpace($RemoteMeshdPairJoinerSessionPrefix)) {
        $RemoteMeshdPairJoinerSessionPrefix = "$RemoteSessionPrefix-meshd-joiner"
    }

    if ($RemoteMeshdPairBootstrapStatusFile -eq '/tmp/meshd-bootstrap-status.json') {
        $RemoteMeshdPairBootstrapStatusFile = "/tmp/$RemoteSessionPrefix-meshd-bootstrap-status.json"
    }

    if ($RemoteMeshdPairJoinerStatusFile -eq '/tmp/meshd-joiner-status.json') {
        $RemoteMeshdPairJoinerStatusFile = "/tmp/$RemoteSessionPrefix-meshd-joiner-status.json"
    }

    if ([string]::IsNullOrWhiteSpace($RemotePublicStunSessionPrefix)) {
        $RemotePublicStunSessionPrefix = "$RemoteSessionPrefix-public-stun"
    }
}

if ([string]::IsNullOrWhiteSpace($RemotePraktorRunner)) {
    $RemotePraktorRunner = "$RemoteRepoDir/run_praktor_p2p_tmux.sh"
}

if ([string]::IsNullOrWhiteSpace($RemoteMeshdRunner)) {
    $RemoteMeshdRunner = "$RemoteRepoDir/run_meshd_remote_status_check.sh"
}

if ([string]::IsNullOrWhiteSpace($RemoteMeshdPairRunner)) {
    $RemoteMeshdPairRunner = "$RemoteRepoDir/run_meshd_remote_pair_check.sh"
}

if ([string]::IsNullOrWhiteSpace($RemotePublicStunRunner)) {
    $RemotePublicStunRunner = "$RemoteRepoDir/mesh/tests/run_public_stun_suite.sh"
}

if ([string]::IsNullOrWhiteSpace($RemotePublicStunTmuxRunner)) {
    $RemotePublicStunTmuxRunner = "$RemoteRepoDir/run_public_stun_tmux.sh"
}

function ConvertTo-BashLiteral {
    param([string]$Value)

    if ($null -eq $Value -or $Value.Length -eq 0) {
        return "''"
    }

    return "'" + ($Value -replace "'", "'""'""'") + "'"
}

function Invoke-SshCommand {
    param(
        [string]$Label,
        [string]$RemoteCommand
    )

    Write-Host "== $Label =="
    & ssh $RemoteHost $RemoteCommand
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "$Label failed with exit code $exitCode"
    }
}

function Invoke-SshCapture {
    param([string]$RemoteCommand)

    $output = & ssh $RemoteHost $RemoteCommand 2>&1
    return @{
        ExitCode = $LASTEXITCODE
        Output = $output
    }
}

function Get-PraktorCommand {
    param([string]$PraktorAction)

    $parts = @(
        'bash',
        $RemotePraktorRunner,
        '--action',
        $PraktorAction.ToLowerInvariant(),
        '--mode',
        'smoke',
        '--repo-dir',
        $RemoteRepoDir,
        '--praktor-bin',
        $RemotePraktorBin
    )

    if (-not [string]::IsNullOrWhiteSpace($RemotePraktorLogDir)) {
        $parts += @('--log-dir', $RemotePraktorLogDir)
    }

    if (-not [string]::IsNullOrWhiteSpace($RemotePraktorSessionPrefix)) {
        $parts += @('--session-prefix', $RemotePraktorSessionPrefix)
    }

    return ($parts | ForEach-Object { ConvertTo-BashLiteral $_ }) -join ' '
}

function Get-PraktorSessionName {
    $prefix = if ([string]::IsNullOrWhiteSpace($RemotePraktorSessionPrefix)) {
        'turbop2p-praktor'
    } else {
        $RemotePraktorSessionPrefix
    }

    return "$prefix-smoke"
}

function Get-PraktorLogPath {
    $prefix = if ([string]::IsNullOrWhiteSpace($RemotePraktorSessionPrefix)) {
        'turbop2p-praktor'
    } else {
        $RemotePraktorSessionPrefix
    }

    $logDir = if ([string]::IsNullOrWhiteSpace($RemotePraktorLogDir)) {
        '/tmp'
    } else {
        $RemotePraktorLogDir
    }

    return "$logDir/$prefix-smoke.log"
}

function Get-MeshdCommand {
    param([string]$MeshdAction)

    $parts = @(
        'env',
        "LD_LIBRARY_PATH_VALUE=$RemoteLdLibraryPath",
        'bash',
        $RemoteMeshdRunner,
        '--action',
        $MeshdAction.ToLowerInvariant(),
        '--repo-dir',
        $RemoteRepoDir,
        '--meshd-bin',
        $RemoteMeshdBin,
        '--config',
        $RemoteMeshdConfig,
        '--status-file',
        $RemoteMeshdStatusFile
    )

    if (-not [string]::IsNullOrWhiteSpace($RemoteMeshdSessionPrefix)) {
        $parts += @('--session-prefix', $RemoteMeshdSessionPrefix)
    }

    return ($parts | ForEach-Object { ConvertTo-BashLiteral $_ }) -join ' '
}

function Get-MeshdPairCommand {
    param([string]$PairAction)

    $parts = @(
        'env',
        "LD_LIBRARY_PATH_VALUE=$RemoteLdLibraryPath",
        "BOOTSTRAP_STATUS_FILE=$RemoteMeshdPairBootstrapStatusFile",
        "JOINER_STATUS_FILE=$RemoteMeshdPairJoinerStatusFile",
        "BOOTSTRAP_SESSION_PREFIX=$RemoteMeshdPairBootstrapSessionPrefix",
        "JOINER_SESSION_PREFIX=$RemoteMeshdPairJoinerSessionPrefix",
        'bash',
        $RemoteMeshdPairRunner,
        '--action',
        $PairAction.ToLowerInvariant(),
        '--repo-dir',
        $RemoteRepoDir,
        '--meshd-bin',
        $RemoteMeshdBin,
        '--bootstrap-config',
        $RemoteMeshdPairBootstrapConfig,
        '--joiner-config',
        $RemoteMeshdPairJoinerConfig,
        '--connect-wait-secs',
        $RemoteMeshdPairConnectWaitSecs,
        '--connect-poll-secs',
        $RemoteMeshdPairConnectPollSecs
    )

    return ($parts | ForEach-Object { ConvertTo-BashLiteral $_ }) -join ' '
}

function Get-PublicStunCommand {
    param([string]$PublicStunAction)

    $parts = @(
        'bash',
        $RemotePublicStunTmuxRunner,
        '--action',
        $PublicStunAction.ToLowerInvariant(),
        '--runner',
        $RemotePublicStunRunner,
        '--repo-dir',
        $RemoteRepoDir,
        '--bin-dir',
        $RemotePublicStunBinDir,
        '--scenario',
        $RemotePublicStunScenario,
        '--workdir-root',
        $ResolvedPublicStunWorkdirRoot,
        '--session-prefix',
        $RemotePublicStunSessionPrefix
    )

    if (-not [string]::IsNullOrWhiteSpace($RemotePublicStunLogDir)) {
        $parts += @('--log-dir', $RemotePublicStunLogDir)
    }

    if (-not [string]::IsNullOrWhiteSpace($RemotePublicStunUrl)) {
        $parts += @('--stun-url', $RemotePublicStunUrl)
    }

    if (-not [string]::IsNullOrWhiteSpace($RemotePublicStunAdvertiseIp)) {
        $parts += @('--advertise-ip', $RemotePublicStunAdvertiseIp)
    }

    return ($parts | ForEach-Object { ConvertTo-BashLiteral $_ }) -join ' '
}

function Get-PublicStunSessionName {
    $prefix = if ([string]::IsNullOrWhiteSpace($RemotePublicStunSessionPrefix)) {
        'turbop2p-public-stun'
    } else {
        $RemotePublicStunSessionPrefix
    }

    return "$prefix-$RemotePublicStunScenario"
}

function Get-PublicStunLogPath {
    $prefix = if ([string]::IsNullOrWhiteSpace($RemotePublicStunSessionPrefix)) {
        'turbop2p-public-stun'
    } else {
        $RemotePublicStunSessionPrefix
    }

    $logDir = if ([string]::IsNullOrWhiteSpace($RemotePublicStunLogDir)) {
        '/tmp'
    } else {
        $RemotePublicStunLogDir
    }

    return "$logDir/$prefix-$RemotePublicStunScenario.log"
}

function Wait-PraktorSmoke {
    $session = Get-PraktorSessionName
    $logPath = Get-PraktorLogPath
    $deadline = (Get-Date).AddSeconds($PraktorWaitTimeoutSecs)

    Write-Host "== Praktor Smoke Wait =="

    while ((Get-Date) -lt $deadline) {
        $remoteCommand = @(
            'if',
            '[', '-f', (ConvertTo-BashLiteral $logPath), ']',
            '&&', 'grep', '-Fq', (ConvertTo-BashLiteral '[workflow] SUCCESS'), (ConvertTo-BashLiteral $logPath),
            ';', 'then', 'echo', 'success',
            ';', 'elif',
            '[', '-f', (ConvertTo-BashLiteral $logPath), ']',
            '&&', 'grep', '-Fq', (ConvertTo-BashLiteral '[workflow] FAILED'), (ConvertTo-BashLiteral $logPath),
            ';', 'then', 'echo', 'failed',
            ';', 'elif',
            'tmux', 'has-session', '-t', (ConvertTo-BashLiteral $session), '2>/dev/null',
            ';', 'then', 'echo', 'running',
            ';', 'else', 'echo', 'unknown',
            ';', 'fi'
        ) -join ' '

        $result = Invoke-SshCapture -RemoteCommand $remoteCommand
        $state = ($result.Output | Select-Object -Last 1).ToString().Trim()

        if ($state -eq 'success') {
            Invoke-SshCommand -Label 'Praktor Smoke Log Tail' -RemoteCommand ("tail -n 40 " + (ConvertTo-BashLiteral $logPath))
            return
        }

        if ($state -eq 'failed') {
            Invoke-SshCommand -Label 'Praktor Smoke Log Tail' -RemoteCommand ("tail -n 80 " + (ConvertTo-BashLiteral $logPath))
            throw 'Praktor smoke reported failure'
        }

        Start-Sleep -Seconds $PraktorWaitPollSecs
    }

    Invoke-SshCommand -Label 'Praktor Smoke Log Tail' -RemoteCommand ("tail -n 80 " + (ConvertTo-BashLiteral (Get-PraktorLogPath)))
    throw "Praktor smoke wait timed out after $PraktorWaitTimeoutSecs seconds"
}

function Wait-PublicStunSuite {
    $session = Get-PublicStunSessionName
    $logPath = Get-PublicStunLogPath
    $deadline = (Get-Date).AddSeconds($PraktorWaitTimeoutSecs)
    $successMarker = "[PASS] public STUN suite passed ($RemotePublicStunScenario)"

    Write-Host '== Public STUN Suite Wait =='

    while ((Get-Date) -lt $deadline) {
        $remoteCommand = @(
            'if',
            '[', '-f', (ConvertTo-BashLiteral $logPath), ']',
            '&&', 'grep', '-Fq', (ConvertTo-BashLiteral $successMarker), (ConvertTo-BashLiteral $logPath),
            ';', 'then', 'echo', 'success',
            ';', 'elif',
            '[', '-f', (ConvertTo-BashLiteral $logPath), ']',
            '&&', 'grep', '-Fq', (ConvertTo-BashLiteral '[FAIL]'), (ConvertTo-BashLiteral $logPath),
            ';', 'then', 'echo', 'failed',
            ';', 'elif',
            'tmux', 'has-session', '-t', (ConvertTo-BashLiteral $session), '2>/dev/null',
            ';', 'then', 'echo', 'running',
            ';', 'else', 'echo', 'unknown',
            ';', 'fi'
        ) -join ' '

        $result = Invoke-SshCapture -RemoteCommand $remoteCommand
        $state = ($result.Output | Select-Object -Last 1).ToString().Trim()

        if ($state -eq 'success') {
            Invoke-SshCommand -Label 'Public STUN Suite Log Tail' -RemoteCommand ("tail -n 80 " + (ConvertTo-BashLiteral $logPath))
            return
        }

        if ($state -eq 'failed') {
            Invoke-SshCommand -Label 'Public STUN Suite Log Tail' -RemoteCommand ("tail -n 120 " + (ConvertTo-BashLiteral $logPath))
            throw 'Public STUN suite reported failure'
        }

        Start-Sleep -Seconds $PraktorWaitPollSecs
    }

    Invoke-SshCommand -Label 'Public STUN Suite Log Tail' -RemoteCommand ("tail -n 120 " + (ConvertTo-BashLiteral (Get-PublicStunLogPath)))
    throw "Public STUN suite wait timed out after $PraktorWaitTimeoutSecs seconds"
}

switch ($Action) {
    'Run' {
        Invoke-SshCommand -Label 'Praktor Smoke Start' -RemoteCommand (Get-PraktorCommand -PraktorAction 'Start')
        Wait-PraktorSmoke
        Invoke-SshCommand -Label 'Meshd Status' -RemoteCommand (Get-MeshdCommand -MeshdAction 'Run')
        if ($WithMeshdPair) {
            Invoke-SshCommand -Label 'Meshd Pair' -RemoteCommand (Get-MeshdPairCommand -PairAction 'Run')
        }
        if ($WithPublicStun) {
            Invoke-SshCommand -Label 'Public STUN Suite Start' -RemoteCommand (Get-PublicStunCommand -PublicStunAction 'Start')
            Wait-PublicStunSuite
        }
        break
    }
    'Status' {
        Invoke-SshCommand -Label 'Praktor Smoke Status' -RemoteCommand (Get-PraktorCommand -PraktorAction 'Status')
        Invoke-SshCommand -Label 'Meshd Status' -RemoteCommand (Get-MeshdCommand -MeshdAction 'Status')
        if ($WithMeshdPair) {
            Invoke-SshCommand -Label 'Meshd Pair Status' -RemoteCommand (Get-MeshdPairCommand -PairAction 'Status')
        }
        if ($WithPublicStun) {
            Invoke-SshCommand -Label 'Public STUN Suite Status' -RemoteCommand (Get-PublicStunCommand -PublicStunAction 'Status')
        }
        break
    }
    'Logs' {
        Invoke-SshCommand -Label 'Praktor Smoke Logs' -RemoteCommand (Get-PraktorCommand -PraktorAction 'Logs')
        Invoke-SshCommand -Label 'Meshd Logs' -RemoteCommand (Get-MeshdCommand -MeshdAction 'Logs')
        if ($WithMeshdPair) {
            Invoke-SshCommand -Label 'Meshd Pair Logs' -RemoteCommand (Get-MeshdPairCommand -PairAction 'Logs')
        }
        if ($WithPublicStun) {
            Invoke-SshCommand -Label 'Public STUN Suite Logs' -RemoteCommand (Get-PublicStunCommand -PublicStunAction 'Logs')
        }
        break
    }
    'Stop' {
        if ($WithMeshdPair) {
            Invoke-SshCommand -Label 'Meshd Pair Stop' -RemoteCommand (Get-MeshdPairCommand -PairAction 'Stop')
        }
        Invoke-SshCommand -Label 'Meshd Stop' -RemoteCommand (Get-MeshdCommand -MeshdAction 'Stop')
        if ($WithPublicStun) {
            Invoke-SshCommand -Label 'Public STUN Suite Stop' -RemoteCommand (Get-PublicStunCommand -PublicStunAction 'Stop')
        }
        Invoke-SshCommand -Label 'Praktor Smoke Stop' -RemoteCommand (Get-PraktorCommand -PraktorAction 'Stop')
        break
    }
}
