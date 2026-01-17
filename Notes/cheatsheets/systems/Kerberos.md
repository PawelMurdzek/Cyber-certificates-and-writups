# Kerberos

## Core Concepts

Kerberos is a network authentication protocol permitting nodes communicating over a non-secure network to prove their identity to one another in a secure manner. It is the default authentication protocol for Windows Domain environments.

### Components

- **KDC (Key Distribution Center)**: Trusted third party that authenticates users and computers. Installed on the Domain Controller (DC). Consists of:
    - **AS (Authentication Service)**: Issues TGTs.
    - **TGS (Ticket Granting Service)**: Issues Service Tickets.
- **Principal**: A unique identity (user or service) in Kerberos.
- **Realm**: The domain over which the KDC has authority (equivalent to AD Domain).

### Terminology

- **TGT (Ticket Granting Ticket)**: Proof that a user has authenticated to the KDC. Used to request access to specific services.
- **TGS-REQ / TGS-REP**: Request and Reply for a Service Ticket.
- **AS-REQ / AS-REP**: Request and Reply for initial authentication (TGT).
- **Service Ticket (ST)**: Ticket used to authenticate to a specific service (e.g., SMB, SQL).
- **SPN (Service Principal Name)**: Unique identifier for a service instance. Required for Kerberos mapping.
- **PAC (Privilege Attribute Certificate)**: Contains the user's SIDs and group memberships. Embedded in the TGT and Service Tickets.
- **Session Key**: Temporary encryption key used for secure communication between parties.

## Authentication Flow

1.  **AS-REQ**: Client -> KDC (AS)
    - Client sends request encrypted with a timestamp (pre-authentication).
2.  **AS-REP**: KDC (AS) -> Client
    - KDC validates creds, sends back **TGT** (encrypted with KRBTGT hash) and a **Session Key**.
3.  **TGS-REQ**: Client -> KDC (TGS)
    - Client sends TGT + Authenticator + SPN of desired service.
4.  **TGS-REP**: KDC (TGS) -> Client
    - KDC checks TGT, sends **Service Ticket** (encrypted with Service Account's hash).
5.  **AP-REQ**: Client -> Service
    - Client presents Service Ticket to the Application Server.
6.  **AP-REP**: Service -> Client (Optional)
    - Mutual authentication (Service proves it is who it says it is).

## Common Attacks

### Kerberoasting
- **Target**: Service Accounts with SPNs.
- **Method**: Request a Service Ticket for a service. The ticket is encrypted with the service account's NTLM hash. Attackers extract this ticket from memory (Mimikatz) or network traffic and crack it offline.
- **Tool**: Rubeus, Invoke-Kerberoast.

### AS-REP Roasting
- **Target**: Accounts with "Do not require Kerberos preauthentication" enabled.
- **Method**: Request AS-REP for the user. The KDC returns an encrypted chunk (with user's NTLM hash) without requiring a password. Crack offline.

### Golden Ticket
- **Target**: Domain dominance.
- **Requirement**: KRBTGT account NTLM hash.
- **Method**: Forge a valid TGT for any user (e.g., fake Enterprise Admin) with explicit groups in the PAC.
- **Persistence**: Valid until KRBTGT password is changed (twice).

### Silver Ticket
- **Target**: Specific service persistence.
- **Requirement**: Service Account NTLM hash.
- **Method**: Forge a Service Ticket. No KDC communication needed.

## Useful Commands

```powershell
# List cached Kerberos tickets
klist

# Purge cached tickets
klist purge

# View SPNs for a user
setspn -L domain\user

# Register a new SPN
setspn -S SQL/server1.domain.com domain\sql_svc
```
