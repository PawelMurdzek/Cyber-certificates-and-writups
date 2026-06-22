# Azure Security Testing

Techniques for testing Azure cloud environments.

> [!CAUTION]
> Only test Azure environments you own or have explicit authorization to test.

---

## Authentication

### Azure CLI
```bash
# Interactive login
az login

# Service principal login
az login --service-principal -u <app-id> -p <password> --tenant <tenant-id>

# Check current account
az account show
az account list
```

### Get Tokens
```bash
# Access token
az account get-access-token

# For specific resource
az account get-access-token --resource https://graph.microsoft.com
```

---

## Enumeration

### Tenant & Subscription
```bash
# List subscriptions
az account list

# Current tenant
az account show --query tenantId
```

### Users (Azure AD)
```bash
# List users
az ad user list
az ad user show --id <user@domain.com>

# List groups
az ad group list
az ad group member list --group <group-id>

# List applications
az ad app list
```

### Resources
```bash
# All resources
az resource list

# Resource groups
az group list

# Virtual Machines
az vm list
az vm list --show-details

# Storage accounts
az storage account list
```

---

## Storage

### Blob Storage
```bash
# List containers
az storage container list --account-name <storage-account>

# List blobs
az storage blob list --container-name <container> --account-name <account>

# Download blob
az storage blob download --container-name <container> --name <blob> --file <local-file> --account-name <account>
```

### Check for Public Access
```bash
# Using curl (public blobs)
curl https://<account>.blob.core.windows.net/<container>/<blob>

# List container (if public)
curl "https://<account>.blob.core.windows.net/<container>?restype=container&comp=list"
```

---

## Key Vault

```bash
# List vaults
az keyvault list

# List secrets
az keyvault secret list --vault-name <vault>

# Get secret value
az keyvault secret show --vault-name <vault> --name <secret>
```

---

## Virtual Machines

```bash
# List VMs
az vm list --show-details

# Get instance metadata (from inside VM)
curl -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# Get access token from VM identity
curl -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

---

## Azure AD

### ROADTools
```bash
# Collect Azure AD info
roadrecon gather -u user@domain.com -p password

# Analyze
roadrecon gui
```

### AzureHound (BloodHound for Azure)
```bash
# Collect data
azurehound --refresh-token <token> -a collect

# Import into BloodHound
```

---

## Common Misconfigurations

| Misconfiguration | Risk |
|:-----------------|:-----|
| Public blob storage | Data exposure |
| Weak RBAC | Privilege escalation |
| Exposed access tokens | Account takeover |
| Guest user abuse | Unauthorized access |
| Managed identity abuse | Privilege escalation |

---

## Tools

| Tool | Purpose |
|:-----|:--------|
| **ROADTools** | Azure AD reconnaissance |
| **AzureHound** | Azure attack paths |
| **ScoutSuite** | Multi-cloud security audit |
| **Stormspotter** | Azure AD visualization |
| **MicroBurst** | Azure security toolkit |
| **o365creeper** | Office 365 enumeration |

### MicroBurst Examples
```powershell
# Import
Import-Module MicroBurst.psm1

# Enumerate storage
Invoke-EnumerateAzureBlobs -Target <target>

# Find exposed function apps
Get-AzDomainInfo
```

---

## Privilege Escalation Paths

| Path | Description |
|:-----|:------------|
| Managed identity abuse | Steal token from compromised VM |
| Automation account | Run malicious runbooks |
| Custom role abuse | Assign higher privileges |
| Service principal secrets | Credentials in portal |
| Logic Apps | Steal OAuth tokens |

---

## Resources

- [HackTricks - Azure](https://book.hacktricks.wiki/cloud-security/azure)
- [ROADTools](https://github.com/dirkjanm/ROADtools)
- [AzureHound](https://github.com/BloodHoundAD/AzureHound)
- [Azure Goat (Practice)](https://github.com/ine-labs/AzureGoat)
