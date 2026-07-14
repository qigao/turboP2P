[CmdletBinding()]
param(
    [ValidateSet('Local', 'Remote')]
    [string]$Target = 'Local',

    [ValidateSet('Validate', 'Run', 'Start', 'Status', 'Logs', 'Wait', 'Stop')]
    [string]$Action = 'Run',

    [ValidateSet('Full', 'Smoke')]
    [string]$Mode = 'Smoke',

    [string]$VsDevCmd = $env:VSDEVCMD,
    [string]$PraktorExe = '',
    [string]$CMakePreset = 'win-dev-user',
    [string]$TestPreset = 'win-dev-user',
    [string]$VcpkgTriplet = 'x64-windows',
    [string]$VcpkgInstallRoot = 'vcpkg_installed',
    [string]$VcpkgCommand = 'vcpkg',
    [string]$BuildArgs = '',
    [string]$CtestArgs = '',
    [string]$BuildTarget = '',

    [string]$RemoteHost = 'root@eu',
    [string]$RemoteRepoDir = '/root/code/turbo-p2p',
    [string]$RemotePraktorBin = '/root/code/praktor/build/linux-gcc-release/bin/praktor',
    [string]$RemoteRunner = '',
    [string]$RemoteLdLibraryPath = '/opt/turbonet/lib',
    [string]$RemoteLogDir = '',
    [string]$RemoteSessionPrefix = '',

    [string[]]$Var = @()
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSCommandPath
$localRunner = Join-Path $repoRoot 'run_praktor_p2p_local.ps1'

if ([string]::IsNullOrWhiteSpace($RemoteRunner)) {
    $RemoteRunner = "$RemoteRepoDir/run_praktor_p2p_tmux.sh"
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
    return $LASTEXITCODE
}

function Get-RemoteWorkflowPath {
    if ($Mode -eq 'Full') {
        return "$RemoteRepoDir/praktor_p2p_ci.yml"
    }

    return "$RemoteRepoDir/praktor_p2p_smoke_ci.yml"
}

function Get-RemoteRunnerCommand {
    param([string]$RemoteAction)

    $parts = @(
        'bash',
        $RemoteRunner,
        '--action',
        $RemoteAction.ToLowerInvariant(),
        '--mode',
        $Mode.ToLowerInvariant(),
        '--repo-dir',
        $RemoteRepoDir,
        '--praktor-bin',
        $RemotePraktorBin
    )

    if (-not [string]::IsNullOrWhiteSpace($RemoteLogDir)) {
        $parts += @('--log-dir', $RemoteLogDir)
    }

    if (-not [string]::IsNullOrWhiteSpace($RemoteSessionPrefix)) {
        $parts += @('--session-prefix', $RemoteSessionPrefix)
    }

    if (-not [string]::IsNullOrWhiteSpace($BuildTarget)) {
        $parts += @('--var', "BUILD_TARGET=$BuildTarget")
    }

    if (-not [string]::IsNullOrWhiteSpace($BuildArgs)) {
        $parts += @('--var', "BUILD_ARGS=$BuildArgs")
    }

    if (-not [string]::IsNullOrWhiteSpace($CtestArgs)) {
        $parts += @('--var', "CTEST_ARGS=$CtestArgs")
    }

    foreach ($override in $Var) {
        if ([string]::IsNullOrWhiteSpace($override)) {
            continue
        }
        $parts += @('--var', $override)
    }

    return ($parts | ForEach-Object { ConvertTo-BashLiteral $_ }) -join ' '
}

function Invoke-LocalTarget {
    if ($Action -in @('Start', 'Status', 'Logs', 'Wait', 'Stop')) {
        throw "Local target does not support action '$Action'. Use Validate or Run."
    }

    $localAction = if ($Action -eq 'Validate') { 'Validate' } else { 'Run' }
    $localRunnerArgs = @{
        Action = $localAction
        Mode = $Mode
        CMakePreset = $CMakePreset
        TestPreset = $TestPreset
        VcpkgTriplet = $VcpkgTriplet
        VcpkgInstallRoot = $VcpkgInstallRoot
        VcpkgCommand = $VcpkgCommand
    }

    if (-not [string]::IsNullOrWhiteSpace($PraktorExe)) {
        $localRunnerArgs.PraktorExe = $PraktorExe
    }

    if (-not [string]::IsNullOrWhiteSpace($VsDevCmd)) {
        $localRunnerArgs.VsDevCmd = $VsDevCmd
    }

    if (-not [string]::IsNullOrWhiteSpace($BuildArgs)) {
        $localRunnerArgs.BuildArgs = $BuildArgs
    }

    if (-not [string]::IsNullOrWhiteSpace($CtestArgs)) {
        $localRunnerArgs.CtestArgs = $CtestArgs
    }

    if (-not [string]::IsNullOrWhiteSpace($BuildTarget)) {
        $localRunnerArgs.BuildTarget = $BuildTarget
    }

    $forwardVars = @()
    foreach ($override in $Var) {
        if ([string]::IsNullOrWhiteSpace($override)) {
            continue
        }
        $forwardVars += $override
    }
    if ($forwardVars.Count -gt 0) {
        $localRunnerArgs.Var = $forwardVars
    }

    & $localRunner @localRunnerArgs
    exit $LASTEXITCODE
}

function Invoke-RemoteTarget {
    $workflowPath = Get-RemoteWorkflowPath

    if ($Action -eq 'Validate') {
        $remoteCommand = @(
            'cd', (ConvertTo-BashLiteral $RemoteRepoDir),
            '&&',
            'env', (ConvertTo-BashLiteral "LD_LIBRARY_PATH=$RemoteLdLibraryPath"),
            (ConvertTo-BashLiteral $RemotePraktorBin),
            'validate',
            '-f',
            (ConvertTo-BashLiteral $workflowPath)
        ) -join ' '

        $exitCode = Invoke-SshCommand -RemoteCommand $remoteCommand
        exit $exitCode
    }

    if ($Action -eq 'Run') {
        $startCommand = Get-RemoteRunnerCommand -RemoteAction 'start'
        $waitCommand = Get-RemoteRunnerCommand -RemoteAction 'wait'

        $exitCode = Invoke-SshCommand -RemoteCommand $startCommand
        if ($exitCode -ne 0) {
            exit $exitCode
        }

        $exitCode = Invoke-SshCommand -RemoteCommand $waitCommand
        exit $exitCode
    }

    $exitCode = Invoke-SshCommand -RemoteCommand (Get-RemoteRunnerCommand -RemoteAction $Action)
    exit $exitCode
}

if ($Target -eq 'Local') {
    Invoke-LocalTarget
} else {
    Invoke-RemoteTarget
}
