<#
.SYNOPSIS
    Production-grade repository formatter and linter (Ruff, Clang-Format, Prettier)
    with persistent SHA-256 file hash caching and live progress tracking.
.EXAMPLE
    .\format.ps1 -Scope All -IncludeIgnored
.EXAMPLE
    .\format.ps1 -Scope Ignored
.EXAMPLE
    .\format.ps1 -Scope Uncommitted -NoCache
.EXAMPLE
    .\format.ps1 -Scope Committed -Since "HEAD~1" -Path "src" -Tools Cpp,Python
#>
[CmdletBinding()]
param (
    [Parameter(Position = 0)]
    [string]$Path = ".",

    [Parameter()]
    [ValidateSet("All", "Uncommitted", "Staged", "Committed", "Ignored")]
    [string]$Scope = "All",

    # Git ref or range used when Scope is 'Committed' (e.g. 'HEAD~1', 'origin/main...HEAD')
    [Parameter()]
    [string]$Since = "HEAD~1",

    # Include gitignored files in addition to the selected Scope
    [Parameter()]
    [switch]$IncludeIgnored,

    # Dry-run check without modifying files on disk
    [Parameter()]
    [switch]$Check,

    # Specific formatters to run
    [Parameter()]
    [ValidateSet("All", "Python", "Cpp", "Markdown")]
    [string[]]$Tools = @("All"),

    # Directories to always skip during scans (prevents corrupting .git, venvs, node_modules, or build trees)
    [Parameter()]
    [string[]]$ExcludeDirs = @(
        ".git", "node_modules", ".venv", "venv", "__pycache__",
        "build", "out", "dist", "target", "bin", "obj", ".vs", "CMakeFiles", "vcpkg_installed", "demo", "nlohmann", "third_party", "vendor", "external"
    ),

    # Maximum file size in KB to format (prevents clang-format/prettier from hanging on huge generated/decompiled files; 0 = unlimited)
    [Parameter()]
    [int]$MaxFileSizeKB = 256,

    # Bypass the file hash cache and re-process all discovered files
    [Parameter()]
    [switch]$NoCache,

    # Delete the existing hash cache file before running
    [Parameter()]
    [switch]$ClearCache,

    # Optional custom path for the hash cache file
    [Parameter()]
    [string]$CacheFile = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$global:LASTEXITCODE = 0
if (Test-Path Variable:\PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}

# --- 1. Locate Tool Binaries & Repo Root ---
$hasGit  = [bool](Get-Command git -ErrorAction SilentlyContinue)
$hasRuff = [bool](Get-Command ruff -ErrorAction SilentlyContinue)

# Prefer npx.cmd over npx.ps1 on Windows to avoid npx.ps1's buggy Invoke-Expression wrapper
$npxCmd = Get-Command npx.cmd -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue
if (-not $npxCmd) {
    $npxCmd = Get-Command npx -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue
}

$clangCmd = Get-Command clang-format -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty Source -ErrorAction SilentlyContinue

if (-not $clangCmd) {
    $fallbackPaths = @(
        "C:\msys64\ucrt64\bin\clang-format.exe",
        "C:\msys64\mingw64\bin\clang-format.exe",
        "C:\msys64\usr\bin\clang-format.exe",
        "${env:ProgramFiles}\LLVM\bin\clang-format.exe"
    )
    foreach ($p in $fallbackPaths) {
        if ([System.IO.File]::Exists($p)) {
            $clangCmd = $p
            break
        }
    }
}

$script:InGitRepo = $false
$script:RepoRoot  = $PWD.Path
if ($hasGit) {
    $topLevel = git rev-parse --show-toplevel 2>$null
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($topLevel)) {
        $script:InGitRepo = $true
        $script:RepoRoot  = [System.IO.Path]::GetFullPath(([string]$topLevel).Trim())
    }
}

# --- 2. File Hash Cache Engine ---
$CACHE_SCHEMA_VERSION = 1
if ([string]::IsNullOrWhiteSpace($CacheFile)) {
    $gitDir = Join-Path -Path $script:RepoRoot -ChildPath ".git"
    if ($script:InGitRepo -and [System.IO.Directory]::Exists($gitDir)) {
        $CacheFile = Join-Path -Path $gitDir -ChildPath "format-cache.json"
    } else {
        $CacheFile = Join-Path -Path $script:RepoRoot -ChildPath ".format-cache.json"
    }
}

$script:HashCache = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$script:Sha256    = [System.Security.Cryptography.SHA256]::Create()

function Get-NormalizedCacheKey {
    param([string]$FullPath)
    return [System.IO.Path]::GetRelativePath($script:RepoRoot, $FullPath).Replace('\', '/')
}

function Get-FastFileHash {
    param([string]$FullPath)
    try {
        $stream = [System.IO.File]::Open($FullPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        try {
            $hashBytes = $script:Sha256.ComputeHash($stream)
            return [System.BitConverter]::ToString($hashBytes).Replace('-', '')
        } finally {
            $stream.Dispose()
        }
    } catch {
        return $null
    }
}

function Import-HashCache {
    if ($ClearCache -and [System.IO.File]::Exists($CacheFile)) {
        Remove-Item -LiteralPath $CacheFile -Force -ErrorAction SilentlyContinue
        Write-Host "Cleared existing format cache: $CacheFile" -ForegroundColor DarkGray
        return
    }
    if ($NoCache -or -not [System.IO.File]::Exists($CacheFile)) { return }

    try {
        $rawJson = [System.IO.File]::ReadAllText($CacheFile)
        if ([string]::IsNullOrWhiteSpace($rawJson)) { return }
        $parsed = ConvertFrom-Json -InputObject $rawJson -ErrorAction Stop
        if ($null -ne $parsed -and $parsed.PSObject.Properties['version'] -and $parsed.version -eq $CACHE_SCHEMA_VERSION) {
            if ($parsed.PSObject.Properties['files'] -and $null -ne $parsed.files) {
                foreach ($prop in $parsed.files.PSObject.Properties) {
                    $script:HashCache[$prop.Name] = [string]$prop.Value
                }
            }
        }
    } catch {
        Write-Warning "Format cache file was corrupted or unreadable. Starting with a fresh cache."
    }
}

function Export-HashCache {
    if ($NoCache) { return }
    try {
        $orderedFiles = [ordered]@{}
        foreach ($k in ($script:HashCache.Keys | Sort-Object)) {
            $orderedFiles[$k] = $script:HashCache[$k]
        }
        $payload = [ordered]@{
            version   = $CACHE_SCHEMA_VERSION
            updatedAt = (Get-Date).ToString("o")
            files     = $orderedFiles
        }
        $json = ConvertTo-Json -InputObject $payload -Depth 4
        [System.IO.File]::WriteAllText($CacheFile, $json, [System.Text.Encoding]::UTF8)
    } catch {
        Write-Warning "Failed to save format cache to $CacheFile : $_"
    }
}

function Select-UnchangedFiles {
    param([string[]]$CandidateFiles)
    if ($NoCache -or -not $CandidateFiles -or $CandidateFiles.Count -eq 0) {
        return $CandidateFiles
    }

    $changed = [System.Collections.Generic.List[string]]::new()
    $total   = $CandidateFiles.Count
    $idx     = 0

    foreach ($file in $CandidateFiles) {
        $idx++
        if ($idx % 25 -eq 0 -or $idx -eq $total) {
            $pct = [int](($idx / $total) * 100)
            Write-Progress -Id 1 -Activity "Checking File Hashes" -Status "Inspecting $idx of $total file(s)..." -PercentComplete $pct
        }

        $key         = Get-NormalizedCacheKey -FullPath $file
        $currentHash = Get-FastFileHash -FullPath $file

        if ($null -eq $currentHash) {
            $changed.Add($file)
            continue
        }

        $cachedHash = $null
        if ($script:HashCache.TryGetValue($key, [ref]$cachedHash) -and $cachedHash -eq $currentHash) {
            continue
        }

        $changed.Add($file)
    }

    Write-Progress -Id 1 -Activity "Checking File Hashes" -Completed
    return $changed.ToArray()
}

function Update-CacheForFiles {
    param([string[]]$ProcessedFiles)
    if ($NoCache -or -not $ProcessedFiles -or $ProcessedFiles.Count -eq 0) { return }

    $total = $ProcessedFiles.Count
    $idx   = 0
    foreach ($file in $ProcessedFiles) {
        $idx++
        if ($idx % 25 -eq 0 -or $idx -eq $total) {
            $pct = [int](($idx / $total) * 100)
            Write-Progress -Id 1 -Activity "Updating File Hash Cache" -Status "Hashing $idx of $total file(s)..." -PercentComplete $pct
        }
        $newHash = Get-FastFileHash -FullPath $file
        if ($null -ne $newHash) {
            $key = Get-NormalizedCacheKey -FullPath $file
            $script:HashCache[$key] = $newHash
        }
    }
    Write-Progress -Id 1 -Activity "Updating File Hash Cache" -Completed
}

# --- 3. File Discovery & Scope Engine ---
$supportedExtRegex = '\.(py|pyi|c|cpp|cc|cxx|h|hpp|hxx|md|markdown)$'

$escapedExcludes = ($ExcludeDirs | ForEach-Object { [Regex]::Escape($_) }) -join '|'
$excludeDirRegex = if ($escapedExcludes) { "(^|[\\/](?:$escapedExcludes))([\\/]|$)" } else { $null }
$maxBytes        = if ($MaxFileSizeKB -gt 0) { [int64]$MaxFileSizeKB * 1024L } else { 0L }

function Test-IsAllowedPath {
    param([string]$FullPath)
    if ($FullPath -notmatch $supportedExtRegex) { return $false }
    if ($excludeDirRegex -and ($FullPath -match $excludeDirRegex)) { return $false }
    try {
        $info = [System.IO.FileInfo]::new($FullPath)
        if (-not $info.Exists) { return $false }
        if ($maxBytes -gt 0 -and $info.Length -gt $maxBytes) { return $false }
        return $true
    } catch {
        return $false
    }
}

function Add-ResolvedFiles {
    param(
        [System.Collections.Generic.HashSet[string]]$TargetSet,
        [AllowNull()][object[]]$RawPaths,
        [string]$BaseDir
    )
    if ($null -eq $RawPaths) { return }
    foreach ($item in $RawPaths) {
        if ($null -eq $item) { continue }
        $str = ([string]$item).Trim()
        if ([string]::IsNullOrWhiteSpace($str)) { continue }

        try {
            $full = if ([System.IO.Path]::IsPathRooted($str)) {
                [System.IO.Path]::GetFullPath($str)
            } else {
                [System.IO.Path]::GetFullPath((Join-Path -Path $BaseDir -ChildPath $str))
            }
            if (Test-IsAllowedPath -FullPath $full) {
                [void]$TargetSet.Add($full)
            }
        } catch {
            # Ignore malformed path strings
        }
    }
}

function Get-DiskFiles {
    param([string]$SearchPath)
    if ([System.IO.File]::Exists($SearchPath)) {
        return $SearchPath
    }
    if (-not [System.IO.Directory]::Exists($SearchPath)) {
        return @()
    }
    $files = Get-ChildItem -LiteralPath $SearchPath -Recurse -File -Force -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty FullName
    return $files
}

function Get-ScopedFiles {
    param (
        [string]$TargetScope,
        [string]$TargetPath,
        [switch]$IncludeIgnoredFiles
    )

    $results = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    $fullTargetPath = if ([System.IO.Path]::IsPathRooted($TargetPath)) {
        [System.IO.Path]::GetFullPath($TargetPath)
    } else {
        [System.IO.Path]::GetFullPath((Join-Path -Path $PWD.Path -ChildPath $TargetPath))
    }

    if (-not [System.IO.File]::Exists($fullTargetPath) -and -not [System.IO.Directory]::Exists($fullTargetPath)) {
        Write-Warning "Target path does not exist: $fullTargetPath"
        return @()
    }

    Write-Progress -Id 1 -Activity "Discovering Files" -Status "Querying scope '$TargetScope'..." -PercentComplete 20

    if (-not $script:InGitRepo -or ($TargetScope -eq "All" -and $IncludeIgnoredFiles)) {
        if (-not $script:InGitRepo) {
            Write-Warning "Not inside a Git repository. Falling back to full disk scan."
        }
        $diskFiles = @(Get-DiskFiles -SearchPath $fullTargetPath)
        Add-ResolvedFiles -TargetSet $results -RawPaths $diskFiles -BaseDir $script:RepoRoot
        Write-Progress -Id 1 -Activity "Discovering Files" -Completed
        return ($results | Sort-Object)
    }

    $relTarget = [System.IO.Path]::GetRelativePath($script:RepoRoot, $fullTargetPath).Replace('\', '/')

    $collectIgnored = {
        $nonIgnoredSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $nonIgnoredRaw = @(git -C $script:RepoRoot -c core.quotepath=false ls-files --cached --others --exclude-standard -- $relTarget)
        Add-ResolvedFiles -TargetSet $nonIgnoredSet -RawPaths $nonIgnoredRaw -BaseDir $script:RepoRoot

        $trackedIgnoredRaw = @(git -C $script:RepoRoot -c core.quotepath=false ls-files --cached --ignored --exclude-standard -- $relTarget)
        Add-ResolvedFiles -TargetSet $results -RawPaths $trackedIgnoredRaw -BaseDir $script:RepoRoot

        $allDisk = @(Get-DiskFiles -SearchPath $fullTargetPath)
        foreach ($f in $allDisk) {
            if ((Test-IsAllowedPath -FullPath $f) -and (-not $nonIgnoredSet.Contains($f))) {
                [void]$results.Add($f)
            }
        }
    }

    switch ($TargetScope) {
        "All" {
            $out = @(git -C $script:RepoRoot -c core.quotepath=false ls-files --cached --others --exclude-standard -- $relTarget)
            Add-ResolvedFiles -TargetSet $results -RawPaths $out -BaseDir $script:RepoRoot
        }
        "Uncommitted" {
            git -C $script:RepoRoot rev-parse --verify HEAD >$null 2>&1
            if ($LASTEXITCODE -eq 0) {
                $diffOut = @(git -C $script:RepoRoot -c core.quotepath=false diff --name-only HEAD -- $relTarget)
            } else {
                $diffOut = @(git -C $script:RepoRoot -c core.quotepath=false diff --name-only --cached -- $relTarget)
            }
            $untrackedOut = @(git -C $script:RepoRoot -c core.quotepath=false ls-files --others --exclude-standard -- $relTarget)
            Add-ResolvedFiles -TargetSet $results -RawPaths $diffOut -BaseDir $script:RepoRoot
            Add-ResolvedFiles -TargetSet $results -RawPaths $untrackedOut -BaseDir $script:RepoRoot
        }
        "Staged" {
            $out = @(git -C $script:RepoRoot -c core.quotepath=false diff --name-only --cached -- $relTarget)
            Add-ResolvedFiles -TargetSet $results -RawPaths $out -BaseDir $script:RepoRoot
        }
        "Committed" {
            $out = @(git -C $script:RepoRoot -c core.quotepath=false diff --name-only $Since -- $relTarget)
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "Git ref '$Since' could not be resolved. Falling back to files in HEAD commit."
                $out = @(git -C $script:RepoRoot -c core.quotepath=false diff-tree --no-commit-id --name-only -r HEAD -- $relTarget)
            }
            Add-ResolvedFiles -TargetSet $results -RawPaths $out -BaseDir $script:RepoRoot
        }
        "Ignored" {
            & $collectIgnored
        }
    }

    if ($IncludeIgnoredFiles -and $TargetScope -ne "Ignored") {
        & $collectIgnored
    }

    Write-Progress -Id 1 -Activity "Discovering Files" -Completed
    return ($results | Sort-Object)
}

# --- 4. Chunked Execution Engine with Safe Invocation ---
$script:HadErrors   = $false
$script:FailedFiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

function Invoke-BatchCommand {
    param (
        [string]$Executable,
        [string[]]$BaseArgs,
        [string[]]$FileList,
        [string]$ActivityName = "Processing files",
        [int]$BatchSize = 40,
        [switch]$UsePosixRelativePaths
    )

    if (-not $FileList -or $FileList.Count -eq 0) { return }

    $currentDir   = $PWD.Path
    $safeList     = @($FileList)
    $totalFiles   = $safeList.Count
    $totalBatches = [Math]::Ceiling($totalFiles / $BatchSize)
    $currentBatch = 0

    for ($i = 0; $i -lt $totalFiles; $i += $BatchSize) {
        $currentBatch++
        $endIndex       = [Math]::Min($i + $BatchSize - 1, $totalFiles - 1)
        $processedCount = $endIndex + 1
        $pct            = [int](($processedCount / $totalFiles) * 100)

        # Update top-level Id 1 directly so Minimal view always shows live batch progress
        Write-Progress -Id 1 -Activity $ActivityName `
            -Status "Batch $currentBatch of $totalBatches ($processedCount / $totalFiles files)" `
            -PercentComplete $pct

        $rawChunk = @($safeList[$i..$endIndex])
        [string[]]$chunk = foreach ($f in $rawChunk) {
            $rel = [System.IO.Path]::GetRelativePath($currentDir, $f)
            if ($UsePosixRelativePaths) {
                $rel.Replace('\', '/')
            } else {
                $rel
            }
        }

        # Prevent PowerShell argument flattening bug on Windows batch files (.cmd/.bat)
        if ($Executable -match '\.(cmd|bat)$') {
            $allArgs = @($BaseArgs) + @($chunk)
            $quotedArgs = $allArgs | ForEach-Object { "`"$_`"" }
            $fullCommand = "`"$Executable`" " + ($quotedArgs -join ' ')
            & cmd.exe /c $fullCommand
        } else {
            & $Executable @BaseArgs @chunk
        }

        if ($LASTEXITCODE -ne 0) {
            $script:HadErrors = $true
            foreach ($f in $rawChunk) {
                [void]$script:FailedFiles.Add($f)
            }
        }
    }
}

# --- 5. Main Execution Flow ---
try {
    Import-HashCache

    $forceIgnoreOverride = ($Scope -eq "Ignored") -or $IncludeIgnored.IsPresent

    Write-Host ">>> Scanning files [Scope: $Scope | Path: $Path | IncludeIgnored: $IncludeIgnored]..." -ForegroundColor Cyan
    [string[]]$allScopedFiles = @(Get-ScopedFiles -TargetScope $Scope -TargetPath $Path -IncludeIgnoredFiles:$IncludeIgnored)

    if ($allScopedFiles.Count -eq 0) {
        Write-Host "No matching Python, C/C++, or Markdown files found for the given scope." -ForegroundColor Yellow
        exit 0
    }

    [string[]]$targetFiles = @(Select-UnchangedFiles -CandidateFiles $allScopedFiles)
    $skippedCount = $allScopedFiles.Count - $targetFiles.Count

    if ($skippedCount -gt 0) {
        Write-Host "Discovered $($allScopedFiles.Count) file(s): $skippedCount unchanged (cached), $($targetFiles.Count) to process.`n" -ForegroundColor Gray
    } else {
        Write-Host "Discovered $($targetFiles.Count) candidate file(s).`n" -ForegroundColor Gray
    }

    if ($targetFiles.Count -eq 0) {
        Write-Host "All matching files match the hash cache. Nothing to format!" -ForegroundColor Green
        exit 0
    }

    $shouldRunAll = "All" -in $Tools
    $activeTools  = [System.Collections.Generic.List[string]]::new()
    if ($shouldRunAll -or "Python"   -in $Tools) { $activeTools.Add("Python") }
    if ($shouldRunAll -or "Cpp"      -in $Tools) { $activeTools.Add("Cpp") }
    if ($shouldRunAll -or "Markdown" -in $Tools) { $activeTools.Add("Markdown") }

    $totalStages  = $activeTools.Count
    $currentStage = 0
    $processedByActiveTools = [System.Collections.Generic.List[string]]::new()

    # === [1/3] Python (Ruff) ===
    if ("Python" -in $activeTools) {
        $currentStage++
        Write-Host ">>> [$currentStage/$totalStages] Processing Python files via Ruff..." -ForegroundColor Cyan
        if ($hasRuff) {
            [string[]]$pyFiles = @(@($targetFiles) | Where-Object { $_ -match '\.(py|pyi)$' })
            if ($pyFiles.Count -gt 0) {
                Write-Host "Running Ruff on $($pyFiles.Count) Python file(s)..." -ForegroundColor Gray
                $extraRuffFlags = if ($forceIgnoreOverride) { @("--no-respect-gitignore") } else { @() }

                if ($Check) {
                    Invoke-BatchCommand -Executable "ruff" -BaseArgs (@("check") + $extraRuffFlags) -FileList $pyFiles -ActivityName "[$currentStage/$totalStages] Ruff Linter (Check)"
                    Invoke-BatchCommand -Executable "ruff" -BaseArgs (@("format", "--check") + $extraRuffFlags) -FileList $pyFiles -ActivityName "[$currentStage/$totalStages] Ruff Formatter (Check)"
                } else {
                    Invoke-BatchCommand -Executable "ruff" -BaseArgs (@("check", "--fix") + $extraRuffFlags) -FileList $pyFiles -ActivityName "[$currentStage/$totalStages] Ruff Linter (--fix)"
                    Invoke-BatchCommand -Executable "ruff" -BaseArgs (@("format") + $extraRuffFlags) -FileList $pyFiles -ActivityName "[$currentStage/$totalStages] Ruff Formatter"
                }
                $processedByActiveTools.AddRange($pyFiles)
                Write-Host "Processed $($pyFiles.Count) Python file(s)." -ForegroundColor Green
            } else {
                Write-Host "No modified Python files need formatting." -ForegroundColor Gray
            }
        } else {
            Write-Host "Notice: Ruff binary not detected in PATH. Skipping." -ForegroundColor Yellow
        }
    }

    # === [2/3] C/C++ (Clang-Format) ===
    if ("Cpp" -in $activeTools) {
        $currentStage++
        Write-Host "`n>>> [$currentStage/$totalStages] Formatting C/C++ files via Clang-Format..." -ForegroundColor Cyan
        if ($clangCmd) {
            [string[]]$cppFiles = @(@($targetFiles) | Where-Object { $_ -match '\.(c|cpp|cc|cxx|h|hpp|hxx)$' })
            if ($cppFiles.Count -gt 0) {
                Write-Host "Running Clang-Format on $($cppFiles.Count) C/C++ file(s) via $clangCmd..." -ForegroundColor Gray
                $baseArgs = if ($Check) { @("--dry-run", "--Werror") } else { @("-i") }
                Invoke-BatchCommand -Executable $clangCmd -BaseArgs $baseArgs -FileList $cppFiles -ActivityName "[$currentStage/$totalStages] Clang-Format"
                $processedByActiveTools.AddRange($cppFiles)
                Write-Host "Processed $($cppFiles.Count) C/C++ file(s)." -ForegroundColor Green
            } else {
                Write-Host "No modified C/C++ files need formatting." -ForegroundColor Gray
            }
        } else {
            Write-Host "Notice: clang-format binary not found. Skipping." -ForegroundColor Yellow
        }
    }

    # === [3/3] Markdown (Prettier) ===
    if ("Markdown" -in $activeTools) {
        $currentStage++
        Write-Host "`n>>> [$currentStage/$totalStages] Formatting Markdown files via Prettier..." -ForegroundColor Cyan
        if ($npxCmd) {
            [string[]]$mdFiles = @(@($targetFiles) | Where-Object { $_ -match '\.(md|markdown)$' })
            if ($mdFiles.Count -gt 0) {
                Write-Host "Running Prettier on $($mdFiles.Count) Markdown file(s)..." -ForegroundColor Gray
                $actionFlag = if ($Check) { "--check" } else { "--write" }
                $prettierArgs = @("prettier", $actionFlag, "--log-level", "error", "--no-error-on-unmatched-pattern")

                if ($forceIgnoreOverride) {
                    $tempEmptyIgnore = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "prettier_empty_ignore"
                    if (-not [System.IO.File]::Exists($tempEmptyIgnore)) {
                        [System.IO.File]::WriteAllText($tempEmptyIgnore, "")
                    }
                    $prettierArgs += @("--ignore-path", $tempEmptyIgnore)
                }

                Invoke-BatchCommand -Executable $npxCmd -BaseArgs $prettierArgs -FileList $mdFiles -ActivityName "[$currentStage/$totalStages] Prettier (Markdown)" -UsePosixRelativePaths
                $processedByActiveTools.AddRange($mdFiles)
                Write-Host "Processed $($mdFiles.Count) Markdown file(s)." -ForegroundColor Green
            } else {
                Write-Host "No modified Markdown files need formatting." -ForegroundColor Gray
            }
        } else {
            Write-Host "Notice: npx.cmd binary not detected. Skipping." -ForegroundColor Yellow
        }
    }

    Write-Progress -Id 1 -Activity "Repository Formatter & Linter" -Completed

    [string[]]$successfulFiles = @(@($processedByActiveTools) | Where-Object { -not $script:FailedFiles.Contains($_) })
    if ($successfulFiles.Count -gt 0) {
        Update-CacheForFiles -ProcessedFiles $successfulFiles
        Export-HashCache
    }

    if ($script:HadErrors) {
        Write-Host "`nCompleted with linter/formatter warnings or errors (see output above)." -ForegroundColor Yellow
        exit 1
    } else {
        Write-Host "`nCompleted successfully with 0 errors." -ForegroundColor Green
        exit 0
    }
} finally {
    Write-Progress -Id 1 -Activity "Repository Formatter & Linter" -Completed -ErrorAction SilentlyContinue
    if ($null -ne $script:Sha256) {
        $script:Sha256.Dispose()
    }
}

