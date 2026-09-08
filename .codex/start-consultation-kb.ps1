[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Diagnostic {
    param([Parameter(Mandatory = $true)][string]$Code)

    [Console]::Error.WriteLine("consultation-kb MCP startup: $Code")
}

function Get-NormalizedPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    return [IO.Path]::GetFullPath($Path).TrimEnd([char[]]"\/")
}

function Test-PathWithin {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $candidate = Get-NormalizedPath $Path
    $boundary = Get-NormalizedPath $Root
    if ($candidate.Equals($boundary, [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    return $candidate.StartsWith(
        $boundary + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase
    )
}

function Test-ReparsePoint {
    param([Parameter(Mandatory = $true)][string]$Path)

    $item = Get-Item -LiteralPath $Path -Force
    return [bool]($item.Attributes -band [IO.FileAttributes]::ReparsePoint)
}

function Assert-PlainDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Code
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw $Code
    }
    if (Test-ReparsePoint $Path) {
        throw $Code
    }
}

function Assert-PlainFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Code
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw $Code
    }
    if (Test-ReparsePoint $Path) {
        throw $Code
    }
}

function Assert-RepositoryMarker {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (
        -not (Test-Path -LiteralPath $Path -PathType Container) -and
        -not (Test-Path -LiteralPath $Path -PathType Leaf)
    ) {
        throw "REPOSITORY_INVALID"
    }
    if (Test-ReparsePoint $Path) {
        throw "REPOSITORY_INVALID"
    }
}

function Read-PyVenvConfig {
    param([Parameter(Mandatory = $true)][string]$Path)

    $values = @{}
    foreach ($rawLine in [IO.File]::ReadAllLines($Path, [Text.Encoding]::UTF8)) {
        $line = $rawLine.Trim()
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("#")) {
            continue
        }
        $separator = $line.IndexOf("=")
        if ($separator -le 0) {
            throw "VENV_CONFIG_INVALID"
        }
        $key = $line.Substring(0, $separator).Trim().ToLowerInvariant()
        $value = $line.Substring($separator + 1).Trim()
        if ([string]::IsNullOrWhiteSpace($value) -or $values.ContainsKey($key)) {
            throw "VENV_CONFIG_INVALID"
        }
        $values[$key] = $value
    }
    if (-not $values.ContainsKey("home") -or -not $values.ContainsKey("version")) {
        throw "VENV_CONFIG_INVALID"
    }
    return $values
}

function Invoke-RuntimeProbe {
    param([Parameter(Mandatory = $true)][string]$PythonExe)

    $probeCode = @'
import json
import platform
import sqlite3
import struct
import sys

try:
    import ssl
    ssl_available = True
except Exception:
    ssl_available = False

try:
    import venv
    venv_available = True
except Exception:
    venv_available = False

fts5_available = False
connection = sqlite3.connect(":memory:")
try:
    connection.execute("CREATE VIRTUAL TABLE consultation_probe USING fts5(body)")
    connection.execute("INSERT INTO consultation_probe(body) VALUES ('probe')")
    row = connection.execute(
        "SELECT count(*) FROM consultation_probe WHERE consultation_probe MATCH 'probe'"
    ).fetchone()
    fts5_available = bool(row and row[0] == 1)
except sqlite3.DatabaseError:
    fts5_available = False
finally:
    connection.close()

print(json.dumps({
    "implementation": platform.python_implementation(),
    "version": list(sys.version_info[:3]),
    "bits": struct.calcsize("P") * 8,
    "prefix": sys.prefix,
    "base_prefix": sys.base_prefix,
    "executable": sys.executable,
    "venv_available": venv_available,
    "ssl_available": ssl_available,
    "fts5_available": fts5_available,
}, separators=(",", ":")))
'@

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $PythonExe
    $startInfo.Arguments = '-I -X utf8 -c "import os;exec(os.environ[''CONSULTATION_RUNTIME_PROBE''])"'
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.EnvironmentVariables["CONSULTATION_RUNTIME_PROBE"] = $probeCode

    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        throw "RUNTIME_PROBE_FAILED"
    }
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($stderr)) {
        throw "RUNTIME_PROBE_FAILED"
    }
    try {
        return $stdout | ConvertFrom-Json
    }
    catch {
        throw "RUNTIME_PROBE_INVALID"
    }
}

try {
    $CodexRoot = Get-NormalizedPath $PSScriptRoot
    $RepoRoot = Get-NormalizedPath (Join-Path $PSScriptRoot "..")
    $WorkspaceRoot = Get-NormalizedPath (Split-Path -Parent $RepoRoot)
    $VaultRoot = Get-NormalizedPath (Join-Path $WorkspaceRoot "knowledge-vault")
    $VenvRoot = Get-NormalizedPath (Join-Path $RepoRoot ".venv")
    $PythonExe = Get-NormalizedPath (Join-Path $RepoRoot ".venv\Scripts\python.exe")
    $VenvConfigPath = Get-NormalizedPath (Join-Path $VenvRoot "pyvenv.cfg")

    Assert-PlainDirectory $CodexRoot "CODEX_DIRECTORY_INVALID"
    Assert-PlainDirectory $RepoRoot "REPOSITORY_INVALID"
    Assert-RepositoryMarker (Join-Path $RepoRoot ".git")
    Assert-PlainDirectory $VaultRoot "VAULT_DIRECTORY_INVALID"
    Assert-PlainDirectory $VenvRoot "VENV_DIRECTORY_INVALID"
    Assert-PlainFile $PythonExe "VENV_PYTHON_MISSING"
    Assert-PlainFile $VenvConfigPath "VENV_CONFIG_MISSING"

    if ((Split-Path -Parent $VaultRoot) -ine $WorkspaceRoot) {
        throw "VAULT_BOUNDARY_INVALID"
    }
    if ((Split-Path -Leaf $VaultRoot) -cne "knowledge-vault") {
        throw "VAULT_BOUNDARY_INVALID"
    }
    if ((Test-PathWithin $VaultRoot $RepoRoot) -or (Test-PathWithin $RepoRoot $VaultRoot)) {
        throw "VAULT_BOUNDARY_INVALID"
    }

    $venvConfig = Read-PyVenvConfig $VenvConfigPath
    $venvHome = Get-NormalizedPath ([string]$venvConfig["home"])
    if (-not [IO.Path]::IsPathRooted($venvHome)) {
        throw "VENV_CONFIG_INVALID"
    }
    $portableHome = $venvHome.Replace("\", "/").ToLowerInvariant()
    if (
        $portableHome.Contains(".cache/codex-runtimes") -or
        (Test-PathWithin $venvHome $RepoRoot) -or
        (Test-PathWithin $venvHome $VaultRoot)
    ) {
        throw "VENV_BASE_FORBIDDEN"
    }

    $probe = Invoke-RuntimeProbe $PythonExe
    $version = @($probe.version)
    if (
        [string]$probe.implementation -cne "CPython" -or
        $version.Count -ne 3 -or
        [int]$version[0] -ne 3 -or
        [int]$version[1] -ne 12 -or
        [int]$version[2] -lt 10 -or
        [int]$probe.bits -ne 64 -or
        $probe.venv_available -ne $true -or
        $probe.ssl_available -ne $true -or
        $probe.fts5_available -ne $true
    ) {
        throw "RUNTIME_CONTRACT_MISMATCH"
    }
    if ((Get-NormalizedPath ([string]$probe.prefix)) -ine $VenvRoot) {
        throw "RUNTIME_NOT_FIXED_VENV"
    }
    if ((Get-NormalizedPath ([string]$probe.executable)) -ine $PythonExe) {
        throw "RUNTIME_NOT_FIXED_VENV"
    }
    $basePrefix = Get-NormalizedPath ([string]$probe.base_prefix)
    $portableBase = $basePrefix.Replace("\", "/").ToLowerInvariant()
    if (
        $portableBase.Contains(".cache/codex-runtimes") -or
        (Test-PathWithin $basePrefix $RepoRoot) -or
        (Test-PathWithin $basePrefix $VaultRoot)
    ) {
        throw "RUNTIME_BASE_FORBIDDEN"
    }
}
catch {
    Write-Diagnostic "STARTUP_VALIDATION_FAILED"
    exit 42
}

$env:CONSULTATION_VAULT_ROOT = $VaultRoot
$env:PYTHONUTF8 = "1"
$env:PYTHONUNBUFFERED = "1"
$env:HF_HUB_OFFLINE = "1"
$env:TRANSFORMERS_OFFLINE = "1"
$env:HF_DATASETS_OFFLINE = "1"
Remove-Item Env:PYTHONHOME -ErrorAction SilentlyContinue
Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue

try {
    Set-Location -LiteralPath $RepoRoot
    & $PythonExe -I -X utf8 -m consultation_kb.mcp.server
    exit $LASTEXITCODE
}
catch {
    Write-Diagnostic "SERVER_LAUNCH_FAILED"
    exit 42
}
