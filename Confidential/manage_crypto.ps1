# Manage-Crypto.ps1
# A script to recursively encrypt or decrypt a directory structure using AES-256.

# --- Configuration ---
# Get the directory where the script is located to ensure paths are always correct.
$scriptRoot = $PSScriptRoot

# Build absolute paths based on the script's location.
$encryptedDir = Join-Path -Path $scriptRoot -ChildPath "encrypted"
$decryptedDir = Join-Path -Path $scriptRoot -ChildPath "decrypted"
# --- End Configuration ---

#region Functions
# This region contains the core cryptographic functions.

function Encrypt-SingleFile {
    param (
        [string]$SourcePath,
        [string]$DestPath,
        [System.Security.SecureString]$Password
    )
    $salt = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($salt)

    $keyDerivation = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($Password, $salt, 600000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $key = $keyDerivation.GetBytes(32)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $key
    $aes.GenerateIV()
    $iv = $aes.IV

    $fileBytes = [System.IO.File]::ReadAllBytes($SourcePath)
    $encryptor = $aes.CreateEncryptor()
    $encryptedBytes = $encryptor.TransformFinalBlock($fileBytes, 0, $fileBytes.Length)

    $outputStream = [System.IO.File]::Create($DestPath)
    $outputStream.Write($salt, 0, $salt.Length)
    $outputStream.Write($iv, 0, $iv.Length)
    $outputStream.Write($encryptedBytes, 0, $encryptedBytes.Length)
    
    # Clean up
    $aes.Dispose()
    $keyDerivation.Dispose()
    $outputStream.Dispose()
}

function Decrypt-SingleFile {
    param (
        [string]$SourcePath,
        [string]$DestPath,
        [System.Security.SecureString]$Password
    )
    $inputStream = [System.IO.File]::OpenRead($SourcePath)
    $salt = New-Object byte[] 16
    $iv = New-Object byte[] 16
    $inputStream.Read($salt, 0, $salt.Length) | Out-Null
    $inputStream.Read($iv, 0, $iv.Length) | Out-Null

    $keyDerivation = [System.Security.Cryptography.Rfc2898DeriveBytes]::new($Password, $salt, 600000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $key = $keyDerivation.GetBytes(32)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $key
    $aes.IV = $iv

    $ciphertextStream = [System.IO.MemoryStream]::new()
    $inputStream.CopyTo($ciphertextStream)
    $ciphertextBytes = $ciphertextStream.ToArray()

    $decryptor = $aes.CreateDecryptor()
    $decryptedBytes = $decryptor.TransformFinalBlock($ciphertextBytes, 0, $ciphertextBytes.Length)
    [System.IO.File]::WriteAllBytes($DestPath, $decryptedBytes)

    # Clean up
    $aes.Dispose()
    $keyDerivation.Dispose()
    $inputStream.Dispose()
    $ciphertextStream.Dispose()
}
#endregion

# --- Main Logic ---
Clear-Host
Write-Host "Recursive Crypto Management" -ForegroundColor Yellow
Write-Host "---------------------------"
$choice = Read-Host "Do you want to (e)ncrypt or (d)ecrypt?"

# Paths are already absolute, so we just check for their existence.
switch ($choice.ToLower()) {
    'e' {
        if (-not (Test-Path -Path $decryptedDir -PathType Container)) {
            Write-Error "Source directory '$decryptedDir' not found. Please create it and place your files inside."
            return
        }
        $sourceDir = $decryptedDir
        $destDir = $encryptedDir
        $password = Read-Host "Enter password to ENCRYPT all files" -AsSecureString
    }
    'd' {
        if (-not (Test-Path -Path $encryptedDir -PathType Container)) {
            Write-Error "Source directory '$encryptedDir' not found."
            return
        }
        $sourceDir = $encryptedDir
        $destDir = $decryptedDir
        $password = Read-Host "Enter password to DECRYPT all files" -AsSecureString
    }
    default {
        Write-Error "Invalid choice. Please run the script again and select 'e' or 'd'."
        return
    }
}

try {
    # Create destination directory if it doesn't exist
    if (-not (Test-Path -Path $destDir)) {
        New-Item -ItemType Directory -Path $destDir | Out-Null
    }

    Write-Host "--- Starting Operation ---"
    # Get all files recursively
    $files = Get-ChildItem -Path $sourceDir -Recurse -File

    foreach ($file in $files) {
        # Calculate the relative path to maintain the folder structure
        # We use Substring($sourceDir.Length + 1) to remove the leading path separator
        $relativePath = $file.FullName.Substring($sourceDir.Length + 1)
        
        if ($choice.ToLower() -eq 'e') {
            $destFilePath = Join-Path -Path $destDir -ChildPath "$($relativePath).enc"
            Write-Host "Encrypting: $($file.FullName) -> $($destFilePath)"
            
            # Ensure the destination subdirectory exists
            $destSubDir = Split-Path -Parent -Path $destFilePath
            if (-not (Test-Path -Path $destSubDir)) {
                New-Item -ItemType Directory -Path $destSubDir | Out-Null
            }
            Encrypt-SingleFile -SourcePath $file.FullName -DestPath $destFilePath -Password $password

        } else { # Decryption
            # Remove the .enc extension
            $decryptedRelativePath = [System.IO.Path]::ChangeExtension($relativePath, $null)
            $destFilePath = Join-Path -Path $destDir -ChildPath $decryptedRelativePath
            Write-Host "Decrypting: $($file.FullName) -> $($destFilePath)"

            $destSubDir = Split-Path -Parent -Path $destFilePath
            if (-not (Test-Path -Path $destSubDir)) {
                New-Item -ItemType Directory -Path $destSubDir | Out-Null
            }
            try {
                Decrypt-SingleFile -SourcePath $file.FullName -DestPath $destFilePath -Password $password
            } catch {
                 Write-Warning "Failed to decrypt $($file.FullName). Check password or file integrity."
                 # Remove the failed (likely empty/garbage) output file
                 Remove-Item -Path $destFilePath -ErrorAction SilentlyContinue
            }
        }
    }
    Write-Host "--- Operation Complete ---" -ForegroundColor Green
}
finally {
    # Securely clear the password from memory
    if ($password) { $password.Dispose() }
}