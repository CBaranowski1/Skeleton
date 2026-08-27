param(
    [string]$PackageRoot = 'R:\SkeletonOwnerOffline\Phase11_1\FoundationBootstrapPackageV1'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-JsonFile {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [object]$Value
    )
    $json = $Value | ConvertTo-Json -Depth 20 -Compress
    [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
}

function New-DeterministicZip {
    param(
        [Parameter(Mandatory)] [string]$SourceRoot,
        [Parameter(Mandatory)] [string]$Destination
    )
    Add-Type -AssemblyName System.IO.Compression
    if (Test-Path -LiteralPath $Destination) {
        throw "Refusing to replace existing archive: $Destination"
    }
    $stream = [System.IO.File]::Open(
        $Destination,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None
    )
    try {
        $archive = [System.IO.Compression.ZipArchive]::new(
            $stream,
            [System.IO.Compression.ZipArchiveMode]::Create,
            $true
        )
        try {
            $sourcePrefix = [System.IO.Path]::GetFullPath($SourceRoot).TrimEnd('\') + '\'
            $files = Get-ChildItem -LiteralPath $SourceRoot -File -Recurse | Sort-Object FullName
            foreach ($file in $files) {
                $full = [System.IO.Path]::GetFullPath($file.FullName)
                if (-not $full.StartsWith($sourcePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                    throw "Source archive path escaped root: $full"
                }
                $relative = $full.Substring($sourcePrefix.Length).Replace('\', '/')
                $entry = $archive.CreateEntry($relative, [System.IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = [System.DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [System.TimeSpan]::Zero)
                $input = [System.IO.File]::OpenRead($full)
                $output = $entry.Open()
                try {
                    $input.CopyTo($output)
                }
                finally {
                    $output.Dispose()
                    $input.Dispose()
                }
            }
        }
        finally {
            $archive.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Invoke-NativeChecked {
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string[]]$Arguments
    )
    $output = & $FilePath @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "Native command failed ($exitCode): $FilePath $($Arguments -join ' ')`n$($output -join "`n")"
    }
    return $output
}

$sourceRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$manifestPath = Join-Path $sourceRoot 'Cargo.toml'
$lockPath = Join-Path $sourceRoot 'Cargo.lock'
$targetRoot = Join-Path $sourceRoot 'target\release'
$signerSource = Join-Path $targetRoot 'FoundationBootstrapSigner.exe'
$verifierSource = Join-Path $targetRoot 'FoundationTerminalVerifier.exe'
$builderSource = Join-Path $targetRoot 'foundation-package-builder.exe'

if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
    throw 'Cargo.lock is required. Generate it once with cargo generate-lockfile --offline and review it before building.'
}

$packageFull = [System.IO.Path]::GetFullPath($PackageRoot)
$requiredFull = [System.IO.Path]::GetFullPath('R:\SkeletonOwnerOffline\Phase11_1\FoundationBootstrapPackageV1')
if (-not [string]::Equals($packageFull.TrimEnd('\'), $requiredFull.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Default build accepts only the exact USB target: $requiredFull"
}
if (-not (Test-Path -LiteralPath $packageFull -PathType Container)) {
    throw "Package target does not exist: $packageFull"
}
if (@(Get-ChildItem -LiteralPath $packageFull -Force).Count -ne 0) {
    throw "Package target must be empty: $packageFull"
}

$partition = Get-Partition -DriveLetter R -ErrorAction Stop
$disk = Get-Disk -Number $partition.DiskNumber -ErrorAction Stop
$volume = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='R:'"
if ($disk.BusType -ne 'USB' -or $volume.DriveType -ne 2) {
    throw 'R: is not a removable USB target; refusing package publication.'
}

$cargo = (Get-Command cargo.exe -ErrorAction Stop).Source
$rustc = (Get-Command rustc.exe -ErrorAction Stop).Source
$dumpbinCandidates = @(
    'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe',
    'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\dumpbin.exe'
)
$dumpbin = $dumpbinCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
if (-not $dumpbin) {
    throw 'A fixed x64 PE import observer (dumpbin.exe) is required.'
}

$temporaryBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
$stage = Join-Path $temporaryBase ("SkeletonFoundationPackage-" + [guid]::NewGuid().ToString('N'))
$usbParent = Split-Path -Parent $packageFull
$usbStage = Join-Path $usbParent ("FoundationBootstrapPackageV1.staging-" + [guid]::NewGuid().ToString('N'))
$published = $false

try {
    Push-Location $sourceRoot
    try {
        & $cargo test --manifest-path $manifestPath --locked --offline
        if ($LASTEXITCODE -ne 0) { throw "cargo test failed with exit code $LASTEXITCODE" }
        & $cargo build --manifest-path $manifestPath --release --locked --offline
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
    }
    finally {
        Pop-Location
    }

    foreach ($path in @($signerSource, $verifierSource, $builderSource)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Expected build output missing: $path"
        }
    }

    New-Item -ItemType Directory -Path $stage | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $stage 'source') | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $stage 'archives') | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $stage 'evidence') | Out-Null

    Copy-Item -LiteralPath $signerSource -Destination (Join-Path $stage 'FoundationBootstrapSigner.exe')
    Copy-Item -LiteralPath $verifierSource -Destination (Join-Path $stage 'FoundationTerminalVerifier.exe')
    foreach ($name in @('Cargo.toml', 'Cargo.lock', 'README.md', 'TRUST-BOUNDARY.md', 'BUILD-RECIPE.md', 'build-package.ps1')) {
        Copy-Item -LiteralPath (Join-Path $sourceRoot $name) -Destination (Join-Path $stage "source\$name")
    }
    Copy-Item -LiteralPath (Join-Path $sourceRoot 'src') -Destination (Join-Path $stage 'source\src') -Recurse
    New-DeterministicZip -SourceRoot (Join-Path $stage 'source') -Destination (Join-Path $stage 'archives\foundation-bootstrap-source.zip')

    $rustcIdentity = @(& $rustc -Vv)
    if ($LASTEXITCODE -ne 0) { throw 'rustc identity observation failed' }
    $cargoIdentity = (& $cargo -V)
    if ($LASTEXITCODE -ne 0) { throw 'cargo identity observation failed' }
    $metadataRaw = & $cargo metadata --manifest-path $manifestPath --format-version 1 --locked --offline
    if ($LASTEXITCODE -ne 0) { throw 'cargo metadata failed' }
    $metadata = $metadataRaw | ConvertFrom-Json
    $dependencies = @(
        $metadata.packages |
            Sort-Object name, version |
            ForEach-Object {
                [ordered]@{
                    name = $_.name
                    version = $_.version
                    source = if ($_.source) { $_.source } else { 'local-source' }
                }
            }
    )
    Write-JsonFile -Path (Join-Path $stage 'evidence\DEPENDENCY-CLOSURE.json') -Value ([ordered]@{
        cargo = $cargoIdentity
        packages = $dependencies
        rustc = $rustcIdentity
        status = 'observed_offline_locked'
    })

    $imports = [ordered]@{}
    foreach ($binary in @('FoundationBootstrapSigner.exe', 'FoundationTerminalVerifier.exe')) {
        $dump = @(& $dumpbin /nologo /dependents (Join-Path $stage $binary))
        if ($LASTEXITCODE -ne 0) { throw "dumpbin failed for $binary" }
        $dlls = @(
            $dump |
                ForEach-Object { if ($_ -match '^\s+([A-Za-z0-9_.-]+\.dll)\s*$') { $Matches[1].ToUpperInvariant() } } |
                Sort-Object -Unique
        )
        $imports[$binary] = $dlls
    }
    Write-JsonFile -Path (Join-Path $stage 'evidence\IMPORT-CLOSURE.json') -Value ([ordered]@{
        binaries = $imports
        observer = $dumpbin
        status = 'observed'
    })

    $signerKatRaw = Invoke-NativeChecked -FilePath (Join-Path $stage 'FoundationBootstrapSigner.exe') -Arguments @('--operation', 'PackageSelfKAT')
    $verifierKatRaw = Invoke-NativeChecked -FilePath (Join-Path $stage 'FoundationTerminalVerifier.exe') -Arguments @('--operation', 'PackageSelfKAT')
    $unknownOutput = & (Join-Path $stage 'FoundationTerminalVerifier.exe') --operation UnknownOperation 2>&1
    $unknownExit = $LASTEXITCODE
    if ($unknownExit -eq 0) { throw 'Unknown-operation hostile KAT unexpectedly passed' }
    $signAttemptOutput = & (Join-Path $stage 'FoundationBootstrapSigner.exe') --operation FoundationBootstrapSign 2>&1
    $signAttemptExit = $LASTEXITCODE
    if ($signAttemptExit -eq 0) { throw 'Signer hostile KAT unexpectedly enabled authority mutation' }
    Write-JsonFile -Path (Join-Path $stage 'evidence\KAT-RESULTS.json') -Value ([ordered]@{
        cargo_tests = 'passed'
        negative = [ordered]@{
            authority_mutation_without_finalized_package_exit = $signAttemptExit
            authority_mutation_without_finalized_package_output = ($signAttemptOutput -join "`n")
            unknown_operation_exit = $unknownExit
            unknown_operation_output = ($unknownOutput -join "`n")
        }
        signer = (($signerKatRaw -join "`n") | ConvertFrom-Json)
        status = 'passed'
        verifier = (($verifierKatRaw -join "`n") | ConvertFrom-Json)
    })

    $signatureFacts = @()
    foreach ($binary in @('FoundationBootstrapSigner.exe', 'FoundationTerminalVerifier.exe')) {
        $signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $stage $binary)
        $signatureFacts += [ordered]@{
            file = $binary
            signer_certificate_present = [bool]$signature.SignerCertificate
            status = [string]$signature.Status
            status_message = [string]$signature.StatusMessage
        }
    }
    Write-JsonFile -Path (Join-Path $stage 'evidence\AUTHENTICODE-STATUS.json') -Value ([ordered]@{
        promotion_eligible = $false
        signatures = $signatureFacts
        status = 'trusted_chain_missing'
    })
    Write-JsonFile -Path (Join-Path $stage 'evidence\PUBLIC-KEY-STATUS.json') -Value ([ordered]@{
        owner_authority_public_key = $null
        publisher_public_key = $null
        status = 'not_provisioned'
    })

    $gitHead = (& git -C (Split-Path -Parent (Split-Path -Parent $sourceRoot)) rev-parse HEAD).Trim()
    $gitStatus = @(& git -C (Split-Path -Parent (Split-Path -Parent $sourceRoot)) status --short)
    $buildTime = [DateTimeOffset]::UtcNow.ToString('o')
    Write-JsonFile -Path (Join-Path $stage 'evidence\PROVENANCE.json') -Value ([ordered]@{
        build_class = 'owner_built_local_candidate'
        build_time_utc = $buildTime
        git_head = $gitHead
        git_worktree_clean = ($gitStatus.Count -eq 0)
        git_worktree_status = $gitStatus
        independently_obtained = $false
        publisher = 'local-owner-build-session'
        source_directory = 'source/'
        source_zip = 'archives/foundation-bootstrap-source.zip'
        status = 'local_candidate'
    })
    Write-JsonFile -Path (Join-Path $stage 'evidence\CUSTODY.json') -Value ([ordered]@{
        acquisition_channel = 'built_locally_for_owner'
        build_time_utc = $buildTime
        disk = [ordered]@{
            bus_type = [string]$disk.BusType
            friendly_name = [string]$disk.FriendlyName
            serial_number = ([string]$disk.SerialNumber).Trim()
            size_bytes = [uint64]$disk.Size
        }
        independent_custody = $false
        media = [ordered]@{
            drive_letter = 'R:'
            filesystem = [string]$volume.FileSystem
            volume_name = [string]$volume.VolumeName
        }
        status = 'owner_usb_staging'
    })
    Write-JsonFile -Path (Join-Path $stage 'evidence\OPERATION-CONTRACT.json') -Value ([ordered]@{
        authority_mutation_enabled = $false
        signer_operations = @('Describe', 'PackageSelfKAT', 'FoundationBootstrapSign')
        verifier_operations = @('Describe', 'PackageSelfKAT', 'PreGenesisSafeBootstrapVerify', 'PostGenesisSafeBootstrapVerify', 'FoundationTerminalVerify')
        unknown_arguments = 'reject'
        privileged_operations = 'typed_blocked_result'
    })

    $finalizeOutput = Invoke-NativeChecked -FilePath $builderSource -Arguments @('--operation', 'FinalizePackage', '--package-root', $stage)
    $finalizeReport = (($finalizeOutput -join "`n") | ConvertFrom-Json)
    $stageVerification = Invoke-NativeChecked -FilePath (Join-Path $stage 'FoundationTerminalVerifier.exe') -Arguments @('--operation', 'PackageSelfKAT')

    if (Test-Path -LiteralPath $usbStage) {
        throw "Unexpected USB staging path already exists: $usbStage"
    }
    New-Item -ItemType Directory -Path $usbStage | Out-Null
    foreach ($item in Get-ChildItem -LiteralPath $stage -Force) {
        Copy-Item -LiteralPath $item.FullName -Destination $usbStage -Recurse
    }
    $usbStageVerification = Invoke-NativeChecked -FilePath (Join-Path $usbStage 'FoundationTerminalVerifier.exe') -Arguments @('--operation', 'PackageSelfKAT')
    if (@(Get-ChildItem -LiteralPath $packageFull -Force).Count -ne 0) {
        throw "Final USB target became non-empty during build: $packageFull"
    }
    Remove-Item -LiteralPath $packageFull
    Move-Item -LiteralPath $usbStage -Destination $packageFull
    $published = $true
    $usbVerification = Invoke-NativeChecked -FilePath (Join-Path $packageFull 'FoundationTerminalVerifier.exe') -Arguments @('--operation', 'PackageSelfKAT')

    [ordered]@{
        finalize = $finalizeReport
        package_root = $packageFull
        stage_verification = (($stageVerification -join "`n") | ConvertFrom-Json)
        status = 'published_local_candidate'
        usb_stage_verification = (($usbStageVerification -join "`n") | ConvertFrom-Json)
        usb_verification = (($usbVerification -join "`n") | ConvertFrom-Json)
    } | ConvertTo-Json -Depth 20
}
finally {
    $stageFull = [System.IO.Path]::GetFullPath($stage)
    if ($stageFull.StartsWith($temporaryBase, [System.StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $stageFull)) {
        Remove-Item -LiteralPath $stageFull -Recurse -Force
    }
    if (-not $published -and (Test-Path -LiteralPath $usbStage)) {
        $usbStageFull = [System.IO.Path]::GetFullPath($usbStage)
        $usbParentFull = [System.IO.Path]::GetFullPath($usbParent).TrimEnd('\') + '\'
        if ($usbStageFull.StartsWith($usbParentFull, [System.StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $usbStageFull -Recurse -Force
        }
    }
}
