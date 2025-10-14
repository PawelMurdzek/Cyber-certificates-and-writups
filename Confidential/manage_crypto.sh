#!/bin/bash

# A script to recursively encrypt or decrypt a directory structure.
# Works with two folders: 'encrypted/' and 'decrypted/'.

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
ENCRYPTED_DIR="encrypted"
DECRYPTED_DIR="decrypted"
CIPHER="aes-256-cbc"
# --- End Configuration ---

# Function to perform encryption
do_encrypt() {
    SOURCE_DIR=$DECRYPTED_DIR
    DEST_DIR=$ENCRYPTED_DIR

    if [ ! -d "$SOURCE_DIR" ]; then
        echo "Error: Source directory '$SOURCE_DIR' not found."
        echo "Please create it and place your files inside."
        exit 1
    fi

    # Prompt for password
    read -s -p "Enter password to ENCRYPT all files: " password
    echo
    read -s -p "Confirm password: " password_confirm
    echo
    if [ "$password" != "$password_confirm" ]; then
        echo "Error: Passwords do not match."
        exit 1
    fi

    echo "--- Starting Encryption ---"
    # Find every file in the source directory
    find "$SOURCE_DIR" -type f | while read -r file; do
        # Determine the relative path to maintain the folder structure
        relative_path="${file#$SOURCE_DIR/}"
        dest_file="$DEST_DIR/$relative_path.enc"

        # Create the destination directory if it doesn't exist
        mkdir -p "$(dirname "$dest_file")"

        echo "Encrypting: $file -> $dest_file"
        openssl enc -$CIPHER -salt -pbkdf2 -in "$file" -out "$dest_file" -pass pass:"$password"
    done

    # Clear password from memory
    unset password
    unset password_confirm
    echo "--- Encryption Complete ---"
}

# Function to perform decryption
do_decrypt() {
    SOURCE_DIR=$ENCRYPTED_DIR
    DEST_DIR=$DECRYPTED_DIR

    if [ ! -d "$SOURCE_DIR" ]; then
        echo "Error: Source directory '$SOURCE_DIR' not found."
        exit 1
    fi

    # Prompt for password
    read -s -p "Enter password to DECRYPT all files: " password
    echo

    echo "--- Starting Decryption ---"
    # Find every file in the source directory (we assume they end with .enc)
    find "$SOURCE_DIR" -type f -name "*.enc" | while read -r file; do
        relative_path="${file#$SOURCE_DIR/}"
        # Remove the .enc extension for the destination file
        dest_file="$DEST_DIR/${relative_path%.enc}"

        mkdir -p "$(dirname "$dest_file")"

        echo "Decrypting: $file -> $dest_file"
        openssl enc -d -$CIPHER -pbkdf2 -in "$file" -out "$dest_file" -pass pass:"$password" || {
            echo "Warning: Failed to decrypt $file. Check password or file integrity."
            # Remove the failed (likely empty/garbage) output file
            rm -f "$dest_file"
        }
    done

    unset password
    echo "--- Decryption Complete ---"
}


# --- Main Menu ---
echo "Recursive Crypto Management"
echo "---------------------------"
read -p "Do you want to (e)ncrypt or (d)ecrypt? " choice

case "${choice,,}" in # Convert choice to lowercase
    e|encrypt)
        do_encrypt
        ;;
    d|decrypt)
        do_decrypt
        ;;
    *)
        echo "Invalid choice. Please run the script again and select 'e' or 'd'."
        exit 1
        ;;
esac