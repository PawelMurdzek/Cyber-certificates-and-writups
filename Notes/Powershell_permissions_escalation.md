## How to enable scripts

Here are four common solutions, ordered from the safest/most temporary to the most permanent.
### Step 1: Check Your Current Policy
First, open a PowerShell terminal and find out what your current execution policy is.
```PowerShell
Get-ExecutionPolicy
```
You will likely see `Restricted`.
### Step 2: Choose a Solution
#### Solution 1: Bypass for a Single Execution (Safest & Recommended)

This method is perfect for running a single script without changing any system settings. It starts a new PowerShell process with a temporary policy, runs the script, and then closes.
```PowerShell
PowerShell.exe -ExecutionPolicy Bypass -File .\filename.ps1
```
#### Solution 2: Change Policy for the Current Session Only
This is a great option if you need to run multiple scripts but only in your current PowerShell window. The setting reverts back to the default as soon as you close the terminal.
1. Set the policy for the current process:
```PowerShell
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
```
2. Now you can run your script normally:
```PowerShell
    .\filename.ps1
```
- **`RemoteSigned`**: 
- A secure setting that allows local scripts to run but requires scripts downloaded from the internet to have a trusted digital signature.
- **`-Scope Process`**: Ensures the policy change only applies to your current PowerShell window.
#### Solution 3: Change Policy for the Current User (Good for Developers)
If you frequently write and run your own scripts, you can change the policy just for your user account. This does **not** require administrator rights.
1. Run the following command in PowerShell. You may be asked to confirm the change with `Y`.
```PowerShell
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```
2. From now on, you can run local scripts directly in any PowerShell terminal you open.
#### Solution 4: Change Policy for the Entire System (Requires Administrator)

**Use with caution**, as this changes the default policy for all users on the computer.
1. Right-click the PowerShell icon in your Start Menu and select **"Run as Administrator"**.
2. In the elevated Administrator terminal, execute the following command:
    ```PowerShell
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
    ```
3. Confirm the security prompt by typing `Y` and pressing Enter.