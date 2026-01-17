# Active Directory

## Core Concepts

- **Active Directory (AD)**: Microsoft's directory service for Windows domain networks. It is a database and set of services that connect users with the network resources they need to get their work done.
- **Domain Controller (DC)**: A server that responds to security authentication requests (logging in, checking permissions, etc.) within a Windows domain. It stores the AD database (`ntds.dit`).
- **Domain**: A logical group of network objects (computers, users, devices) that share the same Active Directory database.
- **Tree**: A collection of one or more domains that share a contiguous namespace.
- **Forest**: A collection of one or more domain trees that share a common schema, configuration, and global catalog. It is the highest level of organization.
- **Organizational Unit (OU)**: A container within a domain that can hold users, groups, and computers. It is the smallest unit to which you can assign Group Policy settings or administrative permissions.
- **Global Catalog (GC)**: A distributed data repository that contains a searchable, partial representation of every object in every domain in a multi-domain Active Directory Domain Services (AD DS) forest.
- **LDAP (Lightweight Directory Access Protocol)**: The industry independent protocol used to access and manage directory information.
- **Kerberos**: The default authentication protocol used by Windows which uses tickets to allow nodes communicating over a non-secure network to prove their identity to one another in a secure manner. See [Kerberos](Kerberos.md) for details.

## Security Groups

| Security Group | Description |
| :--- | :--- |
| **Domain Admins** | Users of this group have administrative privileges over the entire domain. By default, they can administer any computer on the domain, including the DCs. |
| **Server Operators** | Users in this group can administer Domain Controllers. They cannot change any administrative group memberships. |
| **Backup Operators** | Users in this group are allowed to access any file, ignoring their permissions. They are used to perform backups of data on computers. |
| **Account Operators** | Users in this group can create or modify other accounts in the domain. |
| **Domain Users** | Includes all existing user accounts in the domain. |
| **Domain Computers** | Includes all existing computers in the domain. |
| **Domain Controllers** | Includes all existing DCs on the domain. |
| **Enterprise Admins** | Users in this group have administrative privileges over the entire forest. They can add/remove domains and manage the forest structure. |
| **Schema Admins** | Users in this group can modify the Active Directory schema (the structure of the directory). |
| **Group Policy Creator Owners** | Members can create Group Policy Objects (GPOs) in the domain. |

## FSMO Roles

Active Directory uses five Flexible Single Master Operation (FSMO) roles assigned to one or more Domain Controllers:

| Role | Scope | Description |
| :--- | :--- | :--- |
| **Schema Master** | Forest | Controls all updates and modifications to the schema. There is only one Schema Master in the entire forest. |
| **Domain Naming Master** | Forest | Controls the addition or removal of domains in the forest. |
| **PDC Emulator** | Domain | Acts as the Primary Domain Controller for backward compatibility, manages time synchronization, and handles password changes/lockouts. |
| **RID Master** | Domain | Allocates pools of Relative IDs (RIDs) to DCs to assign to new objects (users, computers, groups). |
| **Infrastructure Master** | Domain | Responsible for updating references to objects in other domains (e.g., group memberships). |

## Object Management

### Preventing Accidental Deletion
To protect or unprotect objects (OUs, Users, Groups) from deletion:
1. In **Active Directory Users and Computers** (ADUC), enable `View` -> `Advanced Features`.
2. Right-click the target object -> `Properties`.
3. Navigate to the `Object` tab.
4. Toggle the **Protect object from accidental deletion** checkbox.
   - **Note**: This must be unchecked to delete a protected object.

### Delegate Control
Used to grant specific permissions to non-admin users for specific OUs (applying the Principle of Least Privilege).
1. Right-click the OU or Container -> `Delegate Control...`.
2. Add the User or Group you want to delegate permissions to.
3. Select the specific tasks to delegate (e.g., "Reset user passwords and force password change at next logon", "Create, delete and manage user accounts").

## Group Policy Objects (GPO)

Group Policy allows admins to manage configurations for users and computers in the domain.

### Processing Order (LSDOU)
Policies are applied in this order (later policies overwrite earlier ones):
1. **L**ocal Policy
2. **S**ite
3. **D**omain
4. **O**rganizational **U**nit (OU)

### Key Concepts
- **GPO (Group Policy Object)**: A collection of settings.
- **GPC (Group Policy Container)**: Stored in AD (LDAP), contains properties/version info.
- **GPT (Group Policy Template)**: Stored in SYSVOL, contains the actual policy data (scripts, admx types).
- **Enforced**: Prevents a policy from being blocked or overwritten by a lower-level GPO.
- **Block Inheritance**: Prevents policies from higher levels from applying to this OU (unless Enforced).

### Common Commands

```powershell
# Force usage of new GPO immediately
gpupdate /force

# Generate report of applied policies
gpresult /r

# Generate HTML report
gpresult /h report.html
```

## PowerShell Management

**Prerequisite**: Install RSAT tools or use a Domain Controller. Import module: `Import-Module ActiveDirectory`

### User Management

```powershell
# Create a new user with a password
$pass = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
New-ADUser -Name "John Doe" -GivenName "John" -Surname "Doe" -SamAccountName "jdoe" -UserPrincipalName "jdoe@domain.com" -AccountPassword $pass -Enabled $true

# Get a user and listed properties
Get-ADUser -Identity "jdoe" -Properties *

# Filter users (e.g., all enabled users)
Get-ADUser -Filter {Enabled -eq $true} -Properties Name, EmailAddress

# Modify user attributes (e.g., Department, Title)
Set-ADUser -Identity "jdoe" -Department "IT" -Title "System Administrator"

# Reset Password with prompt
Set-ADAccountPassword "jdoe" -Reset -NewPassword (Read-Host -AsSecureString -Prompt "New Password")

# Force password change at next logon
Set-ADUser -Identity "jdoe" -ChangePasswordAtLogon $true

# Disable/Enable account
Disable-ADAccount -Identity "jdoe"
Enable-ADAccount -Identity "jdoe"

# Delete a user (with confirmation)
Remove-ADUser -Identity "jdoe"
```

### Group Management

```powershell
# Create a new Global Security Group
New-ADGroup -Name "IT_Admins" -GroupScope Global -GroupCategory Security

# Add members to a group
Add-ADGroupMember -Identity "IT_Admins" -Members "jdoe", "sophie"

# Get group members
Get-ADGroupMember -Identity "IT_Admins"

# Remove member from group
Remove-ADGroupMember -Identity "IT_Admins" -Members "jdoe"
```

### Computer & OU Management

```powershell
# Get all computers in the domain
Get-ADComputer -Filter * -Properties IPv4Address

# Create a new Organizational Unit
New-ADOrganizationalUnit -Name "IT_Department" -Path "DC=domain,DC=com"

# Move user to a different OU
Move-ADObject -Identity "CN=jdoe,CN=Users,DC=domain,DC=com" -TargetPath "OU=IT_Department,DC=domain,DC=com"
```

### General Querying

```powershell
# Search for any object by name
Get-ADObject -Filter {Name -like "*Admin*"}

# Get FSMO Role Holders
Get-ADDomain | Select-Object InfrastructureMaster, RIDMaster, PDCEmulator
Get-ADForest | Select-Object SchemaMaster, DomainNamingMaster
```
