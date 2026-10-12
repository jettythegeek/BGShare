<#
  Build BGShare.exe and BGShare-Setup.exe on Windows.
  Usage (PowerShell, from this folder):
      powershell -ExecutionPolicy Bypass -File .\build.ps1            # one-folder build (fast start, recommended)
      powershell -ExecutionPolicy Bypass -File .\build.ps1 -OneFile   # single BGShare.exe
      .\build.ps1 -NoInstaller                                         # skip Inno Setup
  Needs: Python 3.11-3.14 (py launcher or python on PATH). Optional: Inno Setup 6 for the installer
  (winget install JRSoftware.InnoSetup). Everything it needs is in this folder (bgshare_peer.py is the P2P core).
#>
param([switch]$OneFile, [switch]$NoInstaller, [string]$Version = "2.1.0")
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

function Step($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }

Step "Finding Python"
$pyExe = $null; $pyPre = @()
if (Get-Command py -ErrorAction SilentlyContinue) { $pyExe = "py"; $pyPre = @("-3") }
elseif (Get-Command python -ErrorAction SilentlyContinue) { $pyExe = "python" }
else { throw "Python 3 not found. Install it from python.org (tick 'Add Python to PATH')." }
& $pyExe @pyPre --version

Step "Creating virtual environment (.venv)"
if (-not (Test-Path ".venv\Scripts\python.exe")) { & $pyExe @pyPre -m venv .venv }
$vpy = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
& $vpy -m pip install --upgrade pip wheel
& $vpy -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "pip install failed (see messages above)." }

Step "Checking the Python sources"
& $vpy -m py_compile bgshare_desktop.py bgshare_peer.py make_icon.py
if ($LASTEXITCODE -ne 0) { throw "Syntax check failed." }

Step "Building the icon from the Blue Giraffe logo"
& $vpy make_icon.py
if ($LASTEXITCODE -ne 0) { throw "Icon build failed." }

Step "Running PyInstaller"
Remove-Item -Recurse -Force build, dist -ErrorAction SilentlyContinue
$mode = if ($OneFile) { "--onefile" } else { "--onedir" }
$piArgs = @("--noconfirm", "--clean", "--windowed", $mode, "--name", "BGShare",
    "--icon", "bgshare.ico",
    "--add-data", "bgshare.ico;.", "--add-data", "bgshare.png;.",
    "--hidden-import", "bgshare_peer",
    "--hidden-import", "pystray._win32",
    "--collect-submodules", "webview", "--collect-data", "webview",
    "--version-file", "version_info.txt",
    "bgshare_desktop.py")
# simple Windows version resource
@"
VSVersionInfo(ffi=FixedFileInfo(filevers=($($Version.Replace('.',',')),0), prodvers=($($Version.Replace('.',',')),0)),
 kids=[StringFileInfo([StringTable('040904B0',[StringStruct('CompanyName','Blue Giraffe Development Ltd'),
 StringStruct('FileDescription','BGShare'),StringStruct('ProductName','BGShare'),StringStruct('FileVersion','$Version'),
 StringStruct('ProductVersion','$Version'),StringStruct('OriginalFilename','BGShare.exe')])]),VarFileInfo([VarStruct('Translation',[1033,1200])])])
"@ | ForEach-Object { [IO.File]::WriteAllText((Join-Path $PSScriptRoot "version_info.txt"), $_, (New-Object Text.UTF8Encoding $false)) }
& $vpy -m PyInstaller @piArgs
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed." }
$exe = if ($OneFile) { "dist\BGShare.exe" } else { "dist\BGShare\BGShare.exe" }
if (-not (Test-Path $exe)) { throw "Expected $exe was not produced." }
Write-Host "Built $exe" -ForegroundColor Green

if ($NoInstaller) { return }
Step "Building the installer with Inno Setup"
$iscc = (Get-Command ISCC.exe -ErrorAction SilentlyContinue).Source
foreach ($c in @("${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
                 "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe")) { if (-not $iscc -and (Test-Path $c)) { $iscc = $c } }
if (-not $iscc) {
    Write-Warning "Inno Setup 6 not found - skipped BGShare-Setup.exe. Install it from https://jrsoftware.org/isdl.php (or 'winget install JRSoftware.InnoSetup') and run build.ps1 again."
    return
}
$src = if ($OneFile) { "dist" } else { "dist\BGShare" }
& $iscc "/DMyAppVersion=$Version" "/DSourceDir=$src" "/DOneFile=$([int][bool]$OneFile)" installer.iss
if ($LASTEXITCODE -ne 0) { throw "ISCC failed." }
Write-Host "Installer: $(Resolve-Path Output\BGShare-Setup.exe)" -ForegroundColor Green
