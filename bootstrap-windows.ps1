#requires -version 5.1
# The .cmd entry starts this script in a new PowerShell process; all settings are process-local.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

function Receive-Installer([string[]]$Uris, $File, $Publisher, $Digest) {
    foreach ($uri in $Uris) {
        try {
            Write-Host "下载 $uri"
            Invoke-WebRequest -UseBasicParsing -Uri $uri -OutFile $File -TimeoutSec 120
            if ($Digest -and (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash -ne $Digest) {
                throw "文件校验失败。$uri"
            }
            $sig = Get-AuthenticodeSignature -LiteralPath $File
            if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.GetNameInfo('SimpleName', $false) -ne $Publisher) {
                throw "无法验证 $Publisher 的数字签名。请检查 Windows 的时间、网络和根证书。"
            }
            return
        } catch {
            if ($uri -eq $Uris[-1]) { throw }
            Write-Warning "$uri 下载或校验失败，正在切换下载源。$($_.Exception.Message)"
        }
    }
}

function Test-Python($Exe, $Code) {
    if (-not $Exe -or -not (Test-Path -LiteralPath $Exe -PathType Leaf)) { return $false }
    $ErrorActionPreference = 'Continue'
    try {
        & $Exe -I -c $Code *> $null
        return ($LASTEXITCODE -eq 0)
    } catch { return $false }
}

function Get-BasePython($Root, $Arch, $Work) {
    $privateDir = Join-Path $Root "Python31317-$Arch"
    $privateExe = Join-Path $privateDir 'python.exe'
    $candidates = @($privateExe, (Join-Path $PSScriptRoot '.venv-win\Scripts\python.exe'))
    # PEP 514 locations include installs made without PATH or the py launcher.
    foreach ($hive in 'HKCU:', 'HKLM:') {
        $dirs = Get-ChildItem "$hive\Software\Python\PythonCore" -ErrorAction SilentlyContinue
        foreach ($dir in $dirs) {
            $key = Get-Item -LiteralPath ($dir.PSPath + '\InstallPath') -ErrorAction SilentlyContinue
            if ($key -and $key.GetValue('')) { $candidates += Join-Path $key.GetValue('') 'python.exe' }
        }
    }
    $candidates += Get-Command python.exe -All -CommandType Application -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -notmatch '\\Microsoft\\WindowsApps\\python\.exe$' } | ForEach-Object { $_.Path }
    $check = "import sys, sysconfig; raise SystemExit(not ((3, 10) <= sys.version_info[:2] <= (3, 14) and sysconfig.get_platform() == 'win-$Arch' and not sysconfig.get_config_var('Py_GIL_DISABLED')))"
    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        if (Test-Python $candidate $check) { return $candidate }
    }

    $hashes = @{
        amd64 = '5da012101ba2e17113a9a1cd901e9ce1441086f2b7ecb5de06ec94163899a190'
        arm64 = '3089a1977c32b26f5078e5a7d0285b7a861b8c96250c5dac3b6af59fbe9e9a75'
    }
    $installer = Join-Path $Work 'python-installer.exe'
    $filename = "python-3.13.17-$Arch.exe"
    $sources = @(
        "https://mirrors.tuna.tsinghua.edu.cn/python/3.13.17/$filename"
        "https://mirrors.aliyun.com/python-release/windows/$filename"
        "https://www.python.org/ftp/python/3.13.17/$filename"
    )
    Receive-Installer $sources $installer 'Python Software Foundation' $hashes[$Arch]
    Write-Host '正在为当前用户安装 Python 3.13。'
    $options = @('/passive', '/norestart', 'InstallAllUsers=0', 'Include_launcher=0', 'InstallLauncherAllUsers=0',
                 'Shortcuts=0', 'PrependPath=0', 'Include_test=0', 'Include_tcltk=0', 'Include_doc=0',
                 ('TargetDir="' + $privateDir + '"'))
    $result = Start-Process -FilePath $installer -WorkingDirectory $Work -ArgumentList $options -PassThru -Wait
    if ($result.ExitCode -notin 0, 3010 -or -not (Test-Python $privateExe $check)) {
        throw "Python 安装未完成（退出码 $($result.ExitCode)）。请重启启动器。"
    }
    return $privateExe
}

function Get-AppPython($Root, $Arch, $Work) {
    $requirements = Join-Path $PSScriptRoot 'requirements.txt'
    $digest = (Get-FileHash -LiteralPath $requirements -Algorithm SHA256).Hash.Substring(0, 16)
    $venv = Join-Path $Root "env-$Arch-$digest"
    $exe = Join-Path $venv 'Scripts\python.exe'
    $ready = Join-Path $venv 'ready'
    $qt = 'from PySide6.QtWidgets import QApplication; app = QApplication([])'
    if ((Test-Path -LiteralPath $ready) -and (Test-Python $exe $qt)) { return $exe }
    $previous = Join-Path $PSScriptRoot '.venv-win\Scripts\python.exe'
    if (Test-Python $previous $qt) {
        # An older source checkout may already have these exact wheels, even when offline.
        $oldPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            & $previous -I -m pip --isolated --disable-pip-version-check install --dry-run --no-index -r $requirements *> $null
            if ($LASTEXITCODE -eq 0) { return $previous }
        } finally { $ErrorActionPreference = $oldPreference }
    }
    $base = Get-BasePython $Root $Arch $Work
    Write-Host '正在配置 Apacket 的 Python 环境。'
    & $base -I -m venv $venv | Out-Host
    if ($LASTEXITCODE -ne 0) { throw '创建 Python 环境失败，请检查磁盘空间后再打开启动器。' }
    $indexes = @(
        'https://pypi.tuna.tsinghua.edu.cn/simple'
        'https://mirrors.aliyun.com/pypi/simple'
        'https://pypi.org/simple'
    )
    foreach ($index in $indexes) {
        Write-Host "正在从 $index 安装界面组件。"
        & $exe -I -m pip --isolated --disable-pip-version-check install --index-url $index --timeout 15 --retries 1 --only-binary=:all: -r $requirements | Out-Host
        if ($LASTEXITCODE -eq 0) { break }
    }
    if ($LASTEXITCODE -ne 0) { throw '界面组件安装失败。请检查网络后再次打开启动器。' }
    if (-not (Test-Python $exe $qt)) {
        Write-Host 'Qt 尚未能加载，正在打开 Microsoft Visual C++ 运行库安装向导。'
        $vcArch = if ($Arch -eq 'amd64') { 'x64' } else { 'arm64' }
        $installer = Join-Path $Work 'vc-redist.exe'
        Receive-Installer "https://aka.ms/vc14/vc_redist.$vcArch.exe" $installer 'Microsoft Corporation' $null
        $result = Start-Process -FilePath $installer -WorkingDirectory $Work -ArgumentList '/install', '/norestart' -PassThru -Wait
        if (-not (Test-Python $exe $qt)) { throw "Qt 仍无法启动。请完成 Microsoft 运行库安装后再试（退出码 $($result.ExitCode)）。" }
    }
    [IO.File]::WriteAllText($ready, $digest)
    return $exe
}

function Test-Npcap {
    return ((Test-Path -LiteralPath "$env:SystemRoot\System32\Npcap\wpcap.dll") -and
            (Test-Path -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\npcap'))
}

function Initialize-Capture($Work) {
    if (Test-Npcap) { return }
    Add-Type -AssemblyName System.Windows.Forms
    $answer = [Windows.Forms.MessageBox]::Show(
        '实时抓包需要 Npcap。“是”将下载并打开官方安装向导，可能需要 Windows 管理员确认。“否”直接打开离线分析。',
        'Apacket', 'YesNo', 'Question')
    if ($answer -ne 'Yes') { return }
    try {
        $installer = Join-Path $Work 'npcap-1.90.exe'
        Receive-Installer 'https://npcap.com/dist/npcap-1.90.exe' $installer 'Nmap Software LLC' '682b57e1c05ef375931975c9d6ded40888f4bfdf9f4b11571e654f962f1199b6'
        # Only the vendor's interactive driver installer requests elevation and presents its license.
        $result = Start-Process -FilePath $installer -WorkingDirectory $Work -Verb RunAs -PassThru -Wait
        if ($result.ExitCode -eq 3010) {
            Write-Warning 'Npcap 安装完成，Windows 重启后可以实时抓包。'
        } elseif (-not (Test-Npcap)) {
            Write-Warning "Npcap 安装未完成（退出码 $($result.ExitCode)），先打开离线分析。"
        }
    } catch {
        Write-Warning "Npcap 安装未完成，先打开离线分析。$($_.Exception.Message)"
    }
}

$work = $lock = $null
try {
    Set-Location -LiteralPath $PSScriptRoot
    $arch = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITEW6432')
    if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
    if ($arch -notin 'AMD64', 'ARM64') { throw '此版本需要 x64 或 ARM64 的 Windows 电脑。' }
    $arch = $arch.ToLowerInvariant()
    $build = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
    if ([int]$build -lt 17763) { throw '此版本需要 Windows 10 1809 或更新版本。' }
    $checkOnly = $args.Count -eq 1 -and $args[0] -eq '--check'
    $root = Join-Path $env:LOCALAPPDATA 'Apacket'
    [IO.Directory]::CreateDirectory($root) | Out-Null
    $work = Join-Path ([IO.Path]::GetTempPath()) ('Apacket-' + [guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($work) | Out-Null
    # FileShare.None releases automatically if setup is interrupted.
    $timer = [Diagnostics.Stopwatch]::StartNew()
    do {
        try { $lock = [IO.File]::Open((Join-Path $root 'setup.lock'), 'OpenOrCreate', 'ReadWrite', 'None') }
        catch [IO.IOException] {
            if ($timer.Elapsed.TotalSeconds -ge 180) { throw '另一窗口正在配置环境。完成后请重新打开本窗口。' }
            Start-Sleep -Milliseconds 400
        }
    } until ($null -ne $lock)
    $python = Get-AppPython $root $arch $work
    if (-not $checkOnly) { Initialize-Capture $work }
    $lock.Dispose()
    $lock = $null
    if ($checkOnly) {
        $capture = if (Test-Npcap) { '已安装' } else { '未安装，可使用离线分析' }
        Write-Host "Python 和 Qt 已就绪。Npcap $capture。"
        Write-Host "Python: $python"
        $result = 0
    } else {
        & $python -E -s -m apacket @args
        $result = $LASTEXITCODE
    }
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    $result = 1
} finally {
    if ($lock) { $lock.Dispose() }
    if ($work -and [IO.Directory]::Exists($work)) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}
exit $result
