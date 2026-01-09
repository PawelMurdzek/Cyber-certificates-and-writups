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
- **Kerberos**: The default authentication protocol used by Windows which uses tickets to allow nodes communicating over a non-secure network to prove their identity to one another in a secure manner.

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
