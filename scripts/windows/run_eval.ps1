# Runs tool-injection-eval against Gemini and writes the results next to this script.
#
# Double-click run_eval.bat (or run this file). It finds Python 3.11+, makes a private
# virtual environment in .venv, installs the eval from GitHub, then runs
# `python -m tool_injection_eval.run`, which writes results\RESULTS.md, logs\ and a
# one-line-per-step STATUS.txt here. Running it again resumes where it stopped.
#
# Your Gemini API key is read from GEMINI_API_KEY or GOOGLE_API_KEY, or asked for once.
# It stays in this process's memory and is never written to disk.
#
# Optional environment variables (CI uses these):
#   TIE_PACKAGE  what to pip install instead of the GitHub branch (e.g. a local checkout)
#   TIE_REF      branch, tag or commit to install from GitHub (default: main)
#   TIE_MODEL    an Inspect model to run instead of Gemini (e.g. mockllm/model)
#   TIE_ROUNDS   number of rounds (default 3)

# Native programs print warnings to stderr. Windows PowerShell 5.1 turns those into
# terminating errors under "Stop", so check exit codes explicitly instead.
$ErrorActionPreference = "Continue"
$here = $PSScriptRoot
Set-Location $here
$statusFile = Join-Path $here "STATUS.txt"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
Start-Transcript -Path (Join-Path $here "run_log.txt") -Append | Out-Null

function Status([string]$msg) {
  $line = "$(Get-Date -Format s)  $msg"
  Write-Host $line -ForegroundColor Cyan
  Add-Content -Path $statusFile -Value $line -Encoding ASCII
}

function Fail([string]$msg) {
  Status "FAILED: $msg"
  Stop-Transcript | Out-Null
  exit 1
}

# Returns e.g. 312 for Python 3.12, or 0 if the command is missing or broken.
function Get-PyVersion([string[]]$cmd) {
  if (-not (Get-Command $cmd[0] -ErrorAction SilentlyContinue)) { return 0 }
  $rest = @($cmd | Select-Object -Skip 1)
  $out = & $cmd[0] @rest -c "import sys; print(sys.version_info[0] * 100 + sys.version_info[1])" 2>$null
  if ($LASTEXITCODE -ne 0) { return 0 }
  $n = 0
  if ([int]::TryParse(("$out").Trim(), [ref]$n)) { return $n }
  return 0
}

Status "Starting in $here"

# 1. Python 3.11 or newer (Inspect needs it)
$candidates = @(
  @("py", "-3.12"), @("py", "-3.13"), @("py", "-3.11"), @("py", "-3.14"),
  @("python"), @("python3"),
  @("$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"),
  @("$env:LOCALAPPDATA\Programs\Python\Python313\python.exe"),
  @("$env:LOCALAPPDATA\Programs\Python\Python311\python.exe"),
  @("$env:USERPROFILE\anaconda3\python.exe"),
  @("$env:USERPROFILE\miniconda3\python.exe"),
  @("$env:ProgramData\anaconda3\python.exe")
)
$py = $null
foreach ($c in $candidates) {
  if ((Get-PyVersion $c) -ge 311) { $py = [string[]]$c; break }
}
if (-not $py) {
  $conda = @(
    "$env:USERPROFILE\anaconda3\Scripts\conda.exe",
    "$env:USERPROFILE\miniconda3\Scripts\conda.exe",
    "$env:ProgramData\anaconda3\Scripts\conda.exe"
  ) | Where-Object { Test-Path $_ } | Select-Object -First 1
  if ($conda) {
    $prefix = Join-Path $here ".condapy"
    if (-not (Test-Path "$prefix\python.exe")) {
      Status "No Python 3.11+ found; creating one with conda (a few minutes)"
      & $conda create -y -q -p $prefix python=3.12
    }
    if ((Get-PyVersion @("$prefix\python.exe")) -ge 311) { $py = [string[]]@("$prefix\python.exe") }
  }
}
if (-not $py) {
  Fail "No Python 3.11 or newer found. Install Python 3.12 from https://www.python.org/downloads/ (tick 'Add python.exe to PATH'), then run this again."
}
Status "Using Python: $($py -join ' ')"

# 2. A private virtual environment with the eval and the Gemini SDK
$venv = Join-Path $here ".venv"
$vpy = Join-Path $venv "Scripts\python.exe"
if (-not (Test-Path $vpy)) {
  Status "Creating a virtual environment in .venv"
  $rest = @($py | Select-Object -Skip 1)
  & $py[0] @rest -m venv $venv
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path $vpy)) { Fail "could not create the virtual environment" }
}
$ref = if ($env:TIE_REF) { $env:TIE_REF } else { "main" }
$pkg = if ($env:TIE_PACKAGE) { $env:TIE_PACKAGE } else { "https://github.com/Herons-0/tool-injection-eval/archive/$ref.zip" }
Status "Installing tool-injection-eval from $pkg (the first run takes a few minutes)"
& $vpy -m pip install --disable-pip-version-check --quiet $pkg google-genai
if ($LASTEXITCODE -ne 0) { Fail "pip install failed; see the messages above" }
# Same version number, newer code: make sure this exact source is the one installed.
& $vpy -m pip install --disable-pip-version-check --quiet --force-reinstall --no-deps $pkg
if ($LASTEXITCODE -ne 0) { Fail "pip install failed; see the messages above" }

# 3. The API key (only for Gemini)
if (-not $env:TIE_MODEL -or $env:TIE_MODEL.StartsWith("google/")) {
  if ($env:GEMINI_API_KEY) { $env:GOOGLE_API_KEY = $env:GEMINI_API_KEY }
  if (-not $env:GOOGLE_API_KEY) {
    Write-Host ""
    Write-Host "Paste your Gemini API key and press Enter. It is used for this run only and never saved." -ForegroundColor Yellow
    $secure = Read-Host "Gemini API key" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $env:GOOGLE_API_KEY = ([Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)).Trim()
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
  }
  if (-not $env:GOOGLE_API_KEY) { Fail "no API key given" }
}

# 4. Run. The runner writes its own progress lines, then DONE, PAUSED or FAILED.
$runArgs = @("-m", "tool_injection_eval.run", "--out", $here)
if ($env:TIE_MODEL) { $runArgs += @("--model", $env:TIE_MODEL) }
if ($env:TIE_ROUNDS) { $runArgs += @("--rounds", $env:TIE_ROUNDS) }
Status "Running the eval. Progress appears below and in STATUS.txt."
& $vpy @runArgs
$code = $LASTEXITCODE
$last = Get-Content $statusFile -Tail 1
if ($last -notmatch "  (DONE|PAUSED|FAILED)") { Status "STOPPED: the eval exited with code $code before finishing" }
Stop-Transcript | Out-Null
exit $code
