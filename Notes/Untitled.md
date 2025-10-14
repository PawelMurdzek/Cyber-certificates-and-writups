# Recursive File Encryption Scripts

This repository contains two scripts, one for Bash (Linux/macOS) and one for PowerShell (Windows), that recursively encrypt and decrypt the entire contents of a directory structure. They provide a simple command-line interface to secure a collection of files with a password.

## Important Security Warning

These scripts are provided for educational and convenience purposes. For protecting highly sensitive or critical data, you should use professionally developed, audited, and dedicated security software like **GnuPG (GPG)**, **VeraCrypt**, or native OS solutions like **BitLocker** (Windows) or **FileVault** (macOS).
- **DO NOT LOSE YOUR PASSWORD.** There is absolutely no way to recover your data if you forget the password.
- **Use a strong and unique password.** The security of your files depends entirely on the strength of your password.
- **Backup your data.** Before performing any encryption or decryption, ensure you have a backup of your original files.
---
## How It Works
The scripts operate on two dedicated folders in the same directory where the script is located:
- `decrypted/`: This is the source folder for encryption. Place all the files and sub-folders you want to protect inside this directory.
- `encrypted/`: This is the destination for encrypted files. The script will recreate the directory structure from `decrypted/` inside this folder, but with all files encrypted (with a `.enc` extension).

The process is reversed for decryption: the scripts read from `encrypted/` and write the decrypted content to `decrypted/`, overwriting any existing files.

**Encryption Flow:** `decrypted/folder/document.txt` → `encrypted/folder/document.txt.enc`

**Decryption Flow:** `encrypted/folder/document.txt.enc` → `decrypted/folder/document.txt`

---
## Bash Version (`manage_crypto.sh`) for Linux & macOS

This script uses `openssl`, a standard command-line tool available on most Linux and macOS systems.
### Prerequisites
- A Linux, macOS, or other Unix-like system.
- `openssl` command-line tool installed. You can check if it's installed by running: !!!sh openssl version !!!
### Setup

1. Save the Bash script code into a file named `manage_crypto.sh`.
2. Open your terminal and navigate to the directory where you saved the file.
3. Make the script executable: !!!sh chmod +x manage_crypto.sh !!!
### Usage
#### To Encrypt
1. Create the `decrypted` directory: `mkdir decrypted`
2. Place all the files and folders you want to encrypt inside the `decrypted` directory.
3. Run the script: !!!sh ./manage_crypto.sh !!!
4. When prompted, type `e` and press Enter.
5. Enter and confirm a strong password.
6. The script will create the `encrypted/` directory and fill it with the encrypted versions of your files.
#### To Decrypt

1. Make sure the `encrypted/` directory (containing your encrypted files) is in the same location as the script.
2. Run the script: !!!sh ./manage_crypto.sh !!!
3. When prompted, type `d` and press Enter.
4. Enter the password you used for encryption.
5. The script will create the `decrypted/` directory and restore your original files. **This will overwrite any existing content in `decrypted/`**.

---

## PowerShell Version (`Manage-Crypto.ps1`) for Windows

This script uses the built-in .NET Framework cryptography libraries for robust AES-256 encryption.
### Prerequisites
- Windows 10/11 with PowerShell 5.1 (pre-installed) or newer.
### Setup
1. Save the PowerShell script code into a file named `Manage-Crypto.ps1`.
2. By default, Windows security policy prevents running local scripts. You will likely need to change this policy for your current session.
    - Open PowerShell (you can search for it in the Start Menu).
    - Navigate to the directory where you saved the script.
    - Run the following command to allow scripts to run only in the current PowerShell window: !!!powershell Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass !!!
### Usage
#### To Encrypt
1. In PowerShell, create the `decrypted` directory: `New-Item -ItemType Directory -Name "decrypted"`
2. Using File Explorer, place all files and folders you want to encrypt inside the `decrypted` directory.
3. Run the script from your PowerShell terminal: !!!powershell .\Manage-Crypto.ps1 !!!
4. When prompted, type `e` and press Enter.
5. A secure prompt will appear for your password. Type it and press Enter.
6. The script will create the `encrypted/` directory and its corresponding structure with encrypted files.
#### To Decrypt

1. Ensure the `encrypted/` directory is present.
2. Run the script from your PowerShell terminal: !!!powershell .\Manage-Crypto.ps1 !!!
3. When prompted, type `d` and press Enter.
4. Enter the correct password at the prompt.
5. The script will restore your files in the `decrypted/` directory. **This will overwrite existing files.**

---
### Notes
- **Empty Directories:** The scripts only process files. Any empty directories in your source folder will not be recreated in the destination folder.
- **File Integrity:** If an encrypted file becomes corrupted, decryption will fail for that file. The scripts include basic error handling to prevent a single failed file from stopping the entire process.