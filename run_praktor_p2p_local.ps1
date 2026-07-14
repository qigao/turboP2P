[CmdletBinding()]
param(
    [ValidateSet('Validate', 'Run')]
    [string]$Action = 'Validate',

    [ValidateSet('Full', 'Smoke')]
    [string]$Mode = 'Smoke',

    [string]$PraktorExe = '',
    [string]$VsDevCmd = $env:VSDEVCMD,
    [string]$CMakePreset = 'win-dev-user',
    [string]$TestPreset = 'win-dev-user',
    [string]$VcpkgTriplet = 'x64-windows',
    [string]$VcpkgInstallRoot = 'vcpkg_installed',
    [string]$VcpkgCommand = 'vcpkg',
    [string]$BuildArgs = '',
    [string]$CtestArgs = '',
    [string]$BuildTarget = '',
    [string[]]$Var = @()
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSCommandPath
$repoParent = Split-Path -Parent $repoRoot
$workspaceRoot = Split-Path -Parent $repoParent

if ([string]::IsNullOrWhiteSpace($PraktorExe)) {
    $candidates = @(
        (Join-Path $workspaceRoot 'Praktor\build\Msvc\bin\praktor.exe'),
        (Join-Path $repoParent 'Praktor\build\Msvc\bin\praktor.exe')
    )

    $PraktorExe = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}

if ([string]::IsNullOrWhiteSpace($PraktorExe) -or -not (Test-Path $PraktorExe)) {
    throw "Praktor executable not found: $PraktorExe"
}

$workflowName = if ($Mode -eq 'Full') { 'praktor_p2p_ci.yml' } else { 'praktor_p2p_smoke_ci.yml' }
$workflowPath = Join-Path $repoRoot $workflowName

if (-not (Test-Path $workflowPath)) {
    throw "Workflow not found: $workflowPath"
}

if ($Action -eq 'Validate') {
    Write-Host "Validating $workflowName with $PraktorExe"
    & $PraktorExe 'validate' '-f' $workflowPath
    exit $LASTEXITCODE
}

if ([string]::IsNullOrWhiteSpace($VsDevCmd)) {
    throw 'VSDEVCMD is not set. Export VSDEVCMD to a valid VsDevCmd.bat path before running local Praktor CI.'
}

if (-not (Test-Path $VsDevCmd)) {
    throw "VSDEVCMD does not exist: $VsDevCmd"
}

$env:VSDEVCMD = $VsDevCmd
$cmdPrefix = 'call "%VSDEVCMD%" -arch=x64 -host_arch=x64 >nul &&'

if ($Mode -eq 'Smoke' -and [string]::IsNullOrWhiteSpace($CtestArgs)) {
    $CtestArgs = '-R ^(test_p2p^|test_mesh_paths)$'
}

$args = @(
    '-f', $workflowPath,
    '--color', 'never',
    '-i', "CMAKE_PRESET=$CMakePreset",
    '-i', "TEST_PRESET=$TestPreset",
    '-i', "VCPKG_TRIPLET=$VcpkgTriplet",
    '-i', "VCPKG_INSTALL_ROOT=$VcpkgInstallRoot",
    '-i', "VCPKG_COMMAND=$VcpkgCommand",
    '-i', "VCPKG_COMMAND_PREFIX=$cmdPrefix",
    '-i', "COMMAND_PREFIX=$cmdPrefix",
    '-i', "TEST_COMMAND_PREFIX=$cmdPrefix"
)

if (-not [string]::IsNullOrWhiteSpace($BuildTarget)) {
    $args += @('-i', "BUILD_TARGET=$BuildTarget")
}

if (-not [string]::IsNullOrWhiteSpace($BuildArgs)) {
    $args += @('-i', "BUILD_ARGS=$BuildArgs")
}

if (-not [string]::IsNullOrWhiteSpace($CtestArgs)) {
    $args += @('-i', "CTEST_ARGS=$CtestArgs")
}

foreach ($override in $Var) {
    if ([string]::IsNullOrWhiteSpace($override)) {
        continue
    }
    $args += @('-i', $override)
}

Write-Host "Running $workflowName with $PraktorExe"
Write-Host "VSDEVCMD=$VsDevCmd"

& $PraktorExe @args
exit $LASTEXITCODE
