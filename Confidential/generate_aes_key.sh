#!/bin/bash

# Define the output file path
file_path="../../keys/aes_key_and_iv.txt"

directory_path=$(dirname "$file_path")

# Ensure the directory exists
if [ ! -d "$directory_path" ]; then
    mkdir -p "$directory_path"
    echo "Created directory: $directory_path"
fi

# Generate AES-256 key and IV
key=$(openssl rand -base64 32) # 256-bit key
iv=$(openssl rand -base64 16)  # 128-bit IV

# Create the file content
file_content="AES-256 Key and IV
Generated on: $(date)
-----------------------------
Base64 Key: $key
Base64 IV:  $iv"

# Write the content to the file
echo "$file_content" > "$file_path"

echo "Successfully saved the key and IV to: $file_path"

# Navigate to the directory and commit the changes
cd "$directory_path"
git add .
git commit -m "New key"
git push