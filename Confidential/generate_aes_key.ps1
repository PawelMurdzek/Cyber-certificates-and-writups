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
# Define the output file path. Using .txt to be explicit about the file type.
$filePath = "aes_key_and_iv.txt"

# Create a string containing the key and IV for file output.
# Using a "Here-String" (@" "@) for easy multi-line formatting.
$fileContent = @"
AES-256 Key and IV
Generated on: $(Get-Date)
-----------------------------
Base64 Key: $base64Key
Base64 IV:  $base64IV
"@

# Use Set-Content to write the string to the specified file.
# This will create the file if it doesn't exist or overwrite it if it does.
Set-Content -Path $filePath -Value $fileContent

# Confirm that the file has been saved.
Write-Host "Successfully saved the key and IV to: $filePath" -ForegroundColor Green
