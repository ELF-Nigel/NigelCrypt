# NigelCrypt sample pack script (PowerShell)
# This script builds the packer and generates packed/secret_blob.hpp
# Usage:
#   $env:NIGELCRYPT_PASSPHRASE = "your-strong-passphrase"
#   .\tools\pack_sample.ps1 -PlaintextPath .\secret.txt

param(
    [Parameter(Mandatory = $true)]
    [string]$PlaintextPath,

    [string]$OutHeader = "packed/secret_blob.hpp",
    [string]$SymbolName = "secret",
    [string]$Alg = "aes",
    [string]$Binding = "none",
    [string]$Aad = "",
    [int]$Iterations = 1000000,
    [int]$KeyId = 1
)

if (-not $env:NIGELCRYPT_PASSPHRASE) {
    Write-Error "Set NIGELCRYPT_PASSPHRASE before running."
    exit 1
}

# Build packer (MSVC cl). Adjust if you prefer another compiler.
$packer = "tools/nigelcrypt_pack.exe"

if (-not (Test-Path $packer)) {
    Write-Host "Building packer..."
    & cl /nologo /std:c++20 /EHsc /O2 tools\nigelcrypt_pack.cpp /Fe:$packer
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host "Packing $PlaintextPath -> $OutHeader"
& $packer --in $PlaintextPath --out $OutHeader --name $SymbolName --pass-env NIGELCRYPT_PASSPHRASE --alg $Alg --binding $Binding --iterations $Iterations --key-id $KeyId --aad $Aad
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Done. Generated $OutHeader"
