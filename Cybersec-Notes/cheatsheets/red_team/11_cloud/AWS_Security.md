# AWS Security Testing

Techniques for testing AWS cloud environments.

> [!CAUTION]
> Only test AWS environments you own or have explicit authorization to test.

---

## Initial Enumeration

### Check for Exposed Credentials
```bash
# Environment variables
env | grep -i aws
cat ~/.aws/credentials
cat ~/.aws/config

# EC2 metadata (from compromised EC2)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

### AWS CLI Setup
```bash
# Configure with access keys
aws configure

# Check identity
aws sts get-caller-identity
```

---

## IAM Enumeration

```bash
# Current user
aws iam get-user
aws iam list-attached-user-policies --user-name <user>
aws iam list-user-policies --user-name <user>

# All users
aws iam list-users

# Roles
aws iam list-roles
aws iam get-role --role-name <role>

# Groups
aws iam list-groups
aws iam list-group-policies --group-name <group>
```

---

## S3 Enumeration

```bash
# List buckets
aws s3 ls
aws s3 ls s3://<bucket-name>

# Download files
aws s3 cp s3://<bucket>/<file> .
aws s3 sync s3://<bucket> ./local-dir

# Check bucket policy
aws s3api get-bucket-policy --bucket <bucket>
aws s3api get-bucket-acl --bucket <bucket>
```

### Finding Public Buckets
```bash
# Common naming patterns
# <company>-backup
# <company>-logs
# <company>-data

# Use tools like:
# - S3Scanner
# - bucket_finder
# - AWSBucketDump
```

---

## EC2 Enumeration

```bash
# List instances
aws ec2 describe-instances

# Security groups
aws ec2 describe-security-groups

# Key pairs
aws ec2 describe-key-pairs

# Snapshots (may contain secrets)
aws ec2 describe-snapshots --owner-ids self
```

---

## Lambda

```bash
# List functions
aws lambda list-functions

# Get function code
aws lambda get-function --function-name <name>

# Get environment variables (often contain secrets)
aws lambda get-function-configuration --function-name <name>
```

---

## Secrets Manager & SSM

```bash
# Secrets Manager
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id <id>

# SSM Parameter Store
aws ssm describe-parameters
aws ssm get-parameter --name <name> --with-decryption
```

---

## Common Misconfigurations

| Misconfiguration | Risk |
|:-----------------|:-----|
| Public S3 buckets | Data exposure |
| Overly permissive IAM | Privilege escalation |
| EC2 metadata accessible | Credential theft |
| Unencrypted snapshots | Data exposure |
| Exposed access keys | Full account compromise |

---

## Tools

| Tool | Purpose |
|:-----|:--------|
| **Pacu** | AWS exploitation framework |
| **ScoutSuite** | Multi-cloud security audit |
| **Prowler** | AWS security best practices |
| **CloudMapper** | AWS visualization |
| **S3Scanner** | Find public S3 buckets |
| **enumerate-iam** | IAM enumeration |

### Pacu Example
```bash
# Install
pip install pacu

# Run
pacu

# In Pacu
> import_keys <profile>
> run iam__enum_users_roles_policies_groups
> run s3__bucket_finder
```

---

## Privilege Escalation Paths

| Path | Description |
|:-----|:------------|
| Lambda code injection | Modify Lambda to run attacker code |
| PassRole abuse | Attach high-priv role to EC2/Lambda |
| SSM command execution | Run commands on EC2 via SSM |
| CloudFormation | Create resources with higher privileges |

**Reference:** [Rhino Security Labs - AWS IAM PrivEsc](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)

---

## Resources

- [HackTricks - AWS](https://book.hacktricks.wiki/cloud-security/aws)
- [Pacu Framework](https://github.com/RhinoSecurityLabs/pacu)
- [flAWS Challenge](http://flaws.cloud/)
