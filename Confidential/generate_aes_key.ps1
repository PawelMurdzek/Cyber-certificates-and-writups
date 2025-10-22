# Create an AES provider instance
$aes = [System.Security.Cryptography.Aes]::Create()

# Set the key size to 256 bits
$aes.KeySize = 256

# Generate a new random key and IV
$aes.GenerateKey()
$aes.GenerateIV()

# Convert the key and IV (which are byte arrays) to Base64 strings
$base64Key = [System.Convert]::ToBase64String($aes.Key)
$base64IV = [System.Convert]::ToBase64String($aes.IV)

# --- Display the results to the console ---
Write-Output "Generated AES-256 Key and IV"
Write-Output "-----------------------------"
Write-Output "Base64 Key: $base64Key"
Write-Output "Base64 IV:  $base64IV"
Write-Output "" # Add a newline for better readability

# --- Save the results to a file ---
# Define the output file path relative to the script's location for robustness.
# $PSScriptRoot is an automatic variable that contains the directory of the script.
$filePath = Join-Path -Path $PSScriptRoot -ChildPath "..\..\keys\aes_key_and_iv.txt"

# Create a string containing the key and IV for file output.
# Using a "Here-String" (@" "@) for easy multi-line formatting.
$fileContent = @"
AES-256 Key and IV
Generated on: $(Get-Date)
-----------------------------
Base64 Key: $base64Key
Base64 IV:  $base64IV
"@

# Ensure the directory for the file path exists
$directoryPath = (Resolve-Path -Path $filePath).Parent.FullName
if (-not (Test-Path -Path $directoryPath)) {
    New-Item -ItemType Directory -Path $directoryPath | Out-Null
    Write-Host "Created directory: $directoryPath" -ForegroundColor Yellow
}

# Save the AES key and IV to the file
Set-Content -Path $filePath -Value $fileContent
Write-Host "Successfully saved the key and IV to: $filePath" -ForegroundColor Green

# Navigate to the directory and commit the changes
Set-Location -Path $directoryPath
& git add .
& git commit -m "New key"
& git push
