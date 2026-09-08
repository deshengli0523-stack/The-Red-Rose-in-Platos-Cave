[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SpecPath,

    [string]$CandidateRunnerScript
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Diagnostic {
    param([Parameter(Mandatory = $true)][string]$Message)
    [Console]::Error.WriteLine($Message)
}

function Read-SimpleToml {
    param([Parameter(Mandatory = $true)][string]$Path)

    $document = @{}
    $section = $null
    foreach ($rawLine in [IO.File]::ReadAllLines($Path, [Text.Encoding]::UTF8)) {
        $line = ($rawLine -replace "#.*$", "").Trim()
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        if ($line -match "^\[([A-Za-z0-9_.-]+)\]$") {
            $section = $Matches[1]
            if (-not $document.ContainsKey($section)) {
                $document[$section] = @{}
            }
            continue
        }
        if ($null -eq $section -or $line -notmatch "^([A-Za-z0-9_.-]+)\s*=\s*(.+)$") {
            throw "Unsupported consultation Python TOML line: $rawLine"
        }
        $key = $Matches[1]
        $rawValue = $Matches[2]
        try {
            $document[$section][$key] = $rawValue | ConvertFrom-Json
        }
        catch {
            throw "Unsupported consultation Python TOML value for $section.$key"
        }
    }
    return $document
}

function Get-NormalizedPath {
    param([AllowNull()][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return $null
    }
    try {
        $expanded = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
        $full = [IO.Path]::GetFullPath($expanded)
        return $full.TrimEnd([char[]]"\/")
    }
    catch {
        return $null
    }
}

function Test-PathWithin {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $normalizedPath = Get-NormalizedPath $Path
    $normalizedRoot = Get-NormalizedPath $Root
    if ($null -eq $normalizedPath -or $null -eq $normalizedRoot) {
        return $false
    }
    if ($normalizedPath.Equals($normalizedRoot, [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    $prefix = $normalizedRoot + [IO.Path]::DirectorySeparatorChar
    return $normalizedPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Invoke-InjectedOperation {
    param(
        [Parameter(Mandatory = $true)][string]$Operation,
        [AllowEmptyString()][string]$Value
    )

    $arguments = @(
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        $script:CandidateRunnerScript,
        "-Operation",
        $Operation
    )
    if (-not [string]::IsNullOrEmpty($Value)) {
        $arguments += @("-Value", $Value)
    }
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $output = @(& powershell.exe @arguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
    return [pscustomobject]@{
        ExitCode = $exitCode
        Lines = @($output | ForEach-Object { [string]$_ })
    }
}

$ProbeCode = @'
import json
import platform
import sqlite3
import struct
import sys

try:
    import venv
    venv_available = True
except Exception:
    venv_available = False

try:
    import ssl
    ssl_available = True
except Exception:
    ssl_available = False

fts5_available = False
connection = sqlite3.connect(':memory:')
try:
    connection.execute('CREATE VIRTUAL TABLE consultation_probe USING fts5(body)')
    connection.execute('INSERT INTO consultation_probe(body) VALUES (?)', ('probe',))
    row = connection.execute(
        'SELECT count(*) FROM consultation_probe WHERE consultation_probe MATCH ?',
        ('probe',),
    ).fetchone()
    fts5_available = bool(row and row[0] == 1)
except sqlite3.DatabaseError:
    fts5_available = False
finally:
    connection.close()

base_executable = getattr(sys, '_base_executable', None) or sys.executable
print(json.dumps({
    'implementation': platform.python_implementation(),
    'version': list(sys.version_info[:3]),
    'bits': struct.calcsize('P') * 8,
    'venv_available': venv_available,
    'ssl_available': ssl_available,
    'sqlite_version': sqlite3.sqlite_version,
    'fts5_available': fts5_available,
    'executable': sys.executable,
    'base_executable': base_executable,
}, separators=(',', ':')))
'@

function Get-RegistryCandidates {
    $roots = @(
        "HKCU:\Software\Python",
        "HKLM:\Software\Python",
        "HKLM:\Software\WOW6432Node\Python"
    )
    $candidates = @()
    foreach ($root in $roots) {
        foreach ($company in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            foreach ($tagKey in @(Get-ChildItem -LiteralPath $company.PSPath -ErrorAction SilentlyContinue)) {
                if ($tagKey.PSChildName -notmatch "^3\.12(?:[.-]|$)") {
                    continue
                }
                $installKeyPath = Join-Path $tagKey.PSPath "InstallPath"
                $installKey = Get-Item -LiteralPath $installKeyPath -ErrorAction SilentlyContinue
                if ($null -eq $installKey) {
                    continue
                }
                $properties = Get-ItemProperty -LiteralPath $installKeyPath -ErrorAction SilentlyContinue
                $executable = $null
                if ($null -ne $properties -and $properties.PSObject.Properties.Name -contains "ExecutablePath") {
                    $executable = [string]$properties.ExecutablePath
                }
                if ([string]::IsNullOrWhiteSpace($executable)) {
                    $prefix = [string]$installKey.GetValue("")
                    if (-not [string]::IsNullOrWhiteSpace($prefix)) {
                        $executable = Join-Path $prefix "python.exe"
                    }
                }
                if (-not [string]::IsNullOrWhiteSpace($executable)) {
                    $candidates += $executable
                }
            }
        }
    }
    return $candidates
}

function Invoke-RealOperation {
    param(
        [Parameter(Mandatory = $true)][string]$Operation,
        [AllowEmptyString()][string]$Value
    )

    switch ($Operation) {
        "HasPymanager" {
            $present = $null -ne (Get-Command pymanager -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1)
            return [pscustomobject]@{ ExitCode = 0; Lines = @($present.ToString().ToLowerInvariant()) }
        }
        "HasLegacyLauncher" {
            $present = $null -ne (Get-Command py -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1)
            return [pscustomobject]@{ ExitCode = 0; Lines = @($present.ToString().ToLowerInvariant()) }
        }
        "DiscoverPymanager" {
            $command = Get-Command pymanager -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($null -eq $command) {
                return [pscustomobject]@{ ExitCode = 1; Lines = @() }
            }
            $previousPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = "Continue"
                $output = @(& $command.Source list --only-managed --format=exe 3.12 2>&1)
                $exitCode = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $previousPreference
            }
            return [pscustomobject]@{
                ExitCode = $exitCode
                Lines = @($output | ForEach-Object { [string]$_ })
            }
        }
        "DiscoverLegacy" {
            $command = Get-Command py -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($null -eq $command) {
                return [pscustomobject]@{ ExitCode = 1; Lines = @() }
            }
            $previousPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = "Continue"
                $rawLines = @(& $command.Source -0p 2>&1)
                $exitCode = $LASTEXITCODE
            }
            finally {
                $ErrorActionPreference = $previousPreference
            }
            $paths = @()
            foreach ($rawLine in $rawLines) {
                $line = [string]$rawLine
                if ($line -match "^\s*-\S+\s+(?:\*\s+)?(.+?\.exe)\s*$") {
                    $paths += $Matches[1]
                }
            }
            return [pscustomobject]@{ ExitCode = $exitCode; Lines = @($paths) }
        }
        "DiscoverRegistry" {
            return [pscustomobject]@{ ExitCode = 0; Lines = @(Get-RegistryCandidates) }
        }
        "ProbeCandidate" {
            $previousPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = "Continue"
                $output = @(& $Value -I -X utf8 -c $script:ProbeCode 2>&1)
                $exitCode = $LASTEXITCODE
            }
            catch {
                $output = @("candidate process could not be launched")
                $exitCode = 1
            }
            finally {
                $ErrorActionPreference = $previousPreference
            }
            return [pscustomobject]@{
                ExitCode = $exitCode
                Lines = @($output | ForEach-Object { [string]$_ })
            }
        }
        default {
            return [pscustomobject]@{ ExitCode = 1; Lines = @("Unknown resolver operation") }
        }
    }
}

function Invoke-ResolverOperation {
    param(
        [Parameter(Mandatory = $true)][string]$Operation,
        [AllowEmptyString()][string]$Value = ""
    )

    if (-not [string]::IsNullOrWhiteSpace($script:CandidateRunnerScript)) {
        return Invoke-InjectedOperation -Operation $Operation -Value $Value
    }
    return Invoke-RealOperation -Operation $Operation -Value $Value
}

function Get-OperationBoolean {
    param([Parameter(Mandatory = $true)][string]$Operation)

    $result = Invoke-ResolverOperation -Operation $Operation
    if ($result.ExitCode -ne 0) {
        return $false
    }
    return (($result.Lines -join "`n").Trim() -ieq "true")
}

function Resolve-CandidatePath {
    param([AllowNull()][string]$Candidate)

    if ([string]::IsNullOrWhiteSpace($Candidate)) {
        return $null
    }
    $trimmed = $Candidate.Trim().Trim('"')
    if (-not [IO.Path]::IsPathRooted($trimmed)) {
        return $null
    }
    $normalized = Get-NormalizedPath $trimmed
    if ($null -eq $normalized -or -not (Test-Path -LiteralPath $normalized -PathType Leaf)) {
        return $null
    }
    return (Resolve-Path -LiteralPath $normalized).Path
}

try {
    $SpecPath = (Resolve-Path -LiteralPath $SpecPath -ErrorAction Stop).Path
    $Spec = Read-SimpleToml -Path $SpecPath
    $RequiredImplementation = [string]$Spec["python"]["implementation"]
    $RequiredSeries = [string]$Spec["python"]["series"]
    $MinimumPatch = [int]$Spec["python"]["min_patch"]
    $RequiredBits = [int]$Spec["python"]["bits"]
    $RequireVenv = [bool]$Spec["python"]["venv"]
    $ForbiddenFragments = @($Spec["paths"]["forbidden_fragments"])
    $NotFoundExitCode = [int]$Spec["resolver"]["not_found_exit_code"]
    $seriesParts = @($RequiredSeries.Split('.'))
    if ($seriesParts.Count -ne 2) {
        throw "Python series must have major.minor form"
    }
    $RequiredMajor = [int]$seriesParts[0]
    $RequiredMinor = [int]$seriesParts[1]
}
catch {
    Write-Diagnostic "Invalid consultation Python specification: $($_.Exception.Message)"
    exit 42
}

if ($NotFoundExitCode -le 0 -or $NotFoundExitCode -gt 255) {
    Write-Diagnostic "Invalid consultation Python specification: dedicated exit code must be 1..255"
    exit 42
}

if (-not [string]::IsNullOrWhiteSpace($CandidateRunnerScript)) {
    try {
        $CandidateRunnerScript = (Resolve-Path -LiteralPath $CandidateRunnerScript -ErrorAction Stop).Path
    }
    catch {
        Write-Diagnostic "Candidate runner script is unavailable"
        exit $NotFoundExitCode
    }
}

$RepoRoot = Get-NormalizedPath (Join-Path $PSScriptRoot "..")
$VaultRoot = Get-NormalizedPath $env:CONSULTATION_VAULT_ROOT
$TempRoots = @()
foreach ($tempCandidate in @($env:TEMP, $env:TMP, [IO.Path]::GetTempPath())) {
    $normalizedTemp = Get-NormalizedPath $tempCandidate
    if ($null -ne $normalizedTemp -and $TempRoots -notcontains $normalizedTemp) {
        $TempRoots += $normalizedTemp
    }
}

function Get-ForbiddenBaseReason {
    param([AllowNull()][string]$BaseExecutable)

    $normalizedBase = Get-NormalizedPath $BaseExecutable
    if ($null -eq $normalizedBase) {
        return "base executable path is invalid"
    }
    $portableBase = $normalizedBase.Replace('\', '/').ToLowerInvariant()
    foreach ($fragment in $script:ForbiddenFragments) {
        $portableFragment = ([string]$fragment).Replace('\', '/').ToLowerInvariant()
        if (-not [string]::IsNullOrWhiteSpace($portableFragment) -and $portableBase.Contains($portableFragment)) {
            return "base executable is in a forbidden Codex runtime cache"
        }
    }
    if (Test-PathWithin -Path $normalizedBase -Root $script:RepoRoot) {
        return "base executable is in the forbidden repository tree"
    }
    if ($null -ne $script:VaultRoot -and (Test-PathWithin -Path $normalizedBase -Root $script:VaultRoot)) {
        return "base executable is in the forbidden vault tree"
    }
    foreach ($tempRoot in $script:TempRoots) {
        if (Test-PathWithin -Path $normalizedBase -Root $tempRoot) {
            return "base executable is in a forbidden temporary directory"
        }
    }
    return $null
}

function Test-PythonCandidate {
    param([AllowNull()][string]$Candidate)

    $resolvedCandidate = Resolve-CandidatePath $Candidate
    if ($null -eq $resolvedCandidate) {
        return [pscustomobject]@{ Valid = $false; Reason = "candidate must be an existing absolute executable path" }
    }
    $probeResult = Invoke-ResolverOperation -Operation "ProbeCandidate" -Value $resolvedCandidate
    if ($probeResult.ExitCode -ne 0) {
        $probeDetail = ($probeResult.Lines -join " ").Trim()
        if ([string]::IsNullOrWhiteSpace($probeDetail)) {
            $probeDetail = "no diagnostic output"
        }
        return [pscustomobject]@{ Valid = $false; Reason = "candidate probe failed: $probeDetail" }
    }
    try {
        $probe = ($probeResult.Lines -join "`n") | ConvertFrom-Json
        $version = @($probe.version)
        if ($version.Count -ne 3) {
            throw "invalid version tuple"
        }
        $major = [int]$version[0]
        $minor = [int]$version[1]
        $patch = [int]$version[2]
    }
    catch {
        return [pscustomobject]@{ Valid = $false; Reason = "candidate probe returned invalid JSON" }
    }
    if ([string]$probe.implementation -cne $script:RequiredImplementation) {
        return [pscustomobject]@{ Valid = $false; Reason = "implementation must be $script:RequiredImplementation" }
    }
    if ($major -ne $script:RequiredMajor -or $minor -ne $script:RequiredMinor) {
        return [pscustomobject]@{ Valid = $false; Reason = "Python series must be $script:RequiredSeries" }
    }
    if ($patch -lt $script:MinimumPatch) {
        return [pscustomobject]@{ Valid = $false; Reason = "minimum patch is $script:MinimumPatch" }
    }
    if ([int]$probe.bits -ne $script:RequiredBits) {
        return [pscustomobject]@{ Valid = $false; Reason = "$script:RequiredBits-bit Python is required" }
    }
    if ($script:RequireVenv -and $probe.venv_available -ne $true) {
        return [pscustomobject]@{ Valid = $false; Reason = "venv module is required" }
    }
    if ($probe.ssl_available -ne $true) {
        return [pscustomobject]@{ Valid = $false; Reason = "SSL module is required" }
    }
    if ($probe.fts5_available -ne $true) {
        return [pscustomobject]@{ Valid = $false; Reason = "SQLite FTS5 is required" }
    }
    $forbiddenReason = Get-ForbiddenBaseReason ([string]$probe.base_executable)
    if ($null -ne $forbiddenReason) {
        return [pscustomobject]@{ Valid = $false; Reason = $forbiddenReason }
    }

    $baseHash = "unavailable"
    $basePath = Get-NormalizedPath ([string]$probe.base_executable)
    if ($null -ne $basePath -and (Test-Path -LiteralPath $basePath -PathType Leaf)) {
        try {
            $baseHash = (Get-FileHash -LiteralPath $basePath -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        catch {
            $baseHash = "unavailable"
        }
    }
    return [pscustomobject]@{
        Valid = $true
        Reason = ""
        Candidate = $resolvedCandidate
        Major = $major
        Minor = $minor
        Patch = $patch
        Implementation = [string]$probe.implementation
        Bits = [int]$probe.bits
        BaseHash = $baseHash
    }
}

function Select-BestCandidate {
    param(
        [AllowEmptyCollection()][string[]]$Candidates,
        [Parameter(Mandatory = $true)][string]$Source
    )

    $seen = @{}
    $validCandidates = @()
    foreach ($candidate in @($Candidates)) {
        if ([string]::IsNullOrWhiteSpace($candidate)) {
            continue
        }
        $key = $candidate.Trim().ToLowerInvariant()
        if ($seen.ContainsKey($key)) {
            continue
        }
        $seen[$key] = $true
        $result = Test-PythonCandidate $candidate
        if ($result.Valid) {
            $validCandidates += $result
        }
        else {
            Write-Diagnostic "Rejected $Source candidate: $($result.Reason)"
        }
    }
    if ($validCandidates.Count -eq 0) {
        return $null
    }
    $selected = @(
        $validCandidates | Sort-Object -Property `
            @{ Expression = { $_.Patch }; Descending = $true }, `
            @{ Expression = { $_.Candidate }; Descending = $false }
    )[0]
    Write-Diagnostic (
        "Selected source={0} version={1}.{2}.{3} implementation={4} bits={5} base_sha256={6}" -f `
            $Source,
            $selected.Major,
            $selected.Minor,
            $selected.Patch,
            $selected.Implementation,
            $selected.Bits,
            $selected.BaseHash
    )
    return [string]$selected.Candidate
}

if (-not [string]::IsNullOrWhiteSpace($env:CONSULTATION_PYTHON)) {
    $evaluation = Test-PythonCandidate $env:CONSULTATION_PYTHON
    if (-not $evaluation.Valid) {
        Write-Diagnostic "Rejected explicit CONSULTATION_PYTHON: $($evaluation.Reason)"
        exit $NotFoundExitCode
    }
    Write-Diagnostic (
        "Selected source=explicit version={0}.{1}.{2} implementation={3} bits={4} base_sha256={5}" -f `
            $evaluation.Major,
            $evaluation.Minor,
            $evaluation.Patch,
            $evaluation.Implementation,
            $evaluation.Bits,
            $evaluation.BaseHash
    )
    [Console]::Out.WriteLine([string]$evaluation.Candidate)
    exit 0
}

if (Get-OperationBoolean -Operation "HasPymanager") {
    $discovery = Invoke-ResolverOperation -Operation "DiscoverPymanager"
    if ($discovery.ExitCode -eq 0) {
        $selectedPath = Select-BestCandidate -Candidates @($discovery.Lines) -Source "pymanager"
        if ($null -ne $selectedPath) {
            [Console]::Out.WriteLine($selectedPath)
            exit 0
        }
    }
    else {
        Write-Diagnostic "pymanager discovery failed"
    }
}

if (Get-OperationBoolean -Operation "HasLegacyLauncher") {
    $discovery = Invoke-ResolverOperation -Operation "DiscoverLegacy"
    if ($discovery.ExitCode -eq 0) {
        $selectedPath = Select-BestCandidate -Candidates @($discovery.Lines) -Source "legacy-launcher"
        if ($null -ne $selectedPath) {
            [Console]::Out.WriteLine($selectedPath)
            exit 0
        }
    }
    else {
        Write-Diagnostic "legacy launcher discovery failed"
    }
}

$discovery = Invoke-ResolverOperation -Operation "DiscoverRegistry"
if ($discovery.ExitCode -eq 0) {
    $selectedPath = Select-BestCandidate -Candidates @($discovery.Lines) -Source "pep514-registry"
    if ($null -ne $selectedPath) {
        [Console]::Out.WriteLine($selectedPath)
        exit 0
    }
}
else {
    Write-Diagnostic "PEP 514 registry discovery failed"
}

Write-Diagnostic "No compatible independent CPython $RequiredSeries x$RequiredBits runtime was found"
exit $NotFoundExitCode
