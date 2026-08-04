# A6400_UPDATER_LAB_PROBE_V1
$ErrorActionPreference = 'Stop'

$result = [ordered]@{
    schema_version = 1
    sandbox_dll_loaded = $false
    file_write_succeeded = $false
    registry_write_succeeded = $false
    network_connected = $false
    device_read_succeeded = $false
    child_effect_observed = $false
    token_is_admin = $false
}

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$target = Join-Path $repositoryRoot '.artifacts\sandbox\a6400-updater\host-target\probe.txt'
$childTarget = Join-Path $repositoryRoot '.artifacts\sandbox\a6400-updater\host-target\child.txt'
$output = Join-Path $repositoryRoot '.artifacts\sandbox\a6400-updater\trace\probe-raw.json'

try {
    foreach ($module in [System.Diagnostics.Process]::GetCurrentProcess().Modules) {
        if ($module.ModuleName -ieq 'SbieDll.dll') {
            $result.sandbox_dll_loaded = $true
            break
        }
    }
} catch {
    $result.sandbox_dll_loaded = $false
}

try {
    $suffix = '\.artifacts\sandbox\a6400-updater\host-target\probe.txt'
    if (-not $target.EndsWith($suffix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'invalid probe target'
    }
    [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($target)) | Out-Null
    [System.IO.File]::WriteAllText($target, 'a6400-updater-lab-probe')
    $result.file_write_succeeded = $true
} catch {
    $result.file_write_succeeded = $false
}

try {
    $registryPath = 'HKCU:\Software\OpenAI\A6400UpdaterLabProbe'
    New-Item -Path $registryPath -Force | Out-Null
    New-ItemProperty -Path $registryPath -Name Marker -Value 1 -PropertyType DWord -Force | Out-Null
    $result.registry_write_succeeded = $true
} catch {
    $result.registry_write_succeeded = $false
}

try {
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $connected = $client.ConnectAsync('127.0.0.1', 18765).Wait(1500)
        $result.network_connected = $connected -and $client.Connected
    } finally {
        $client.Dispose()
    }
} catch {
    $result.network_connected = $false
}

try {
    $device = [System.IO.FileStream]::new(
        '\\.\PhysicalDrive0',
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite
    )
    try {
        $result.device_read_succeeded = $device.ReadByte() -ge 0
    } finally {
        $device.Dispose()
    }
} catch {
    $result.device_read_succeeded = $false
}

try {
    if ([System.IO.File]::Exists($childTarget)) {
        throw 'child marker already exists'
    }
    $child = Start-Process `
        -FilePath (Join-Path $env:SystemRoot 'System32\cmd.exe') `
        -ArgumentList @('/d', '/c', ('type nul > "' + $childTarget + '"')) `
        -WindowStyle Hidden `
        -Wait `
        -PassThru
    $result.child_effect_observed = [System.IO.File]::Exists($childTarget)
} catch {
    $result.child_effect_observed = $false
}

try {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    $result.token_is_admin = $principal.IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator
    )
} catch {
    $result.token_is_admin = $true
}

$json = $result | ConvertTo-Json -Compress
try {
    [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($output)) | Out-Null
    [System.IO.File]::WriteAllText($output, $json)
} catch {
    # Standard output remains the fallback for non-Sandboxie control runs.
}
$json
