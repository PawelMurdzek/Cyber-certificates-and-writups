# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

A personal cybersecurity portfolio: notes, cheatsheets, certificates, published articles, and writeups from learning platforms (TryHackMe, CyberDefenders, CryptoHack, MSLearn, SNYK, Mixeway Academy) and CTFs. **It is a content/knowledge repo, not a software project** — most of it is Markdown and PDF. The only executable code lives in `Confidential/` (file-encryption helpers).

When asked to "add a writeup", "make a cheatsheet", "fix a note", treat this as a documentation task, not a code task. Do not introduce build tooling, package managers, linters, or tests — none are appropriate here.

## Top-level layout (the parts that aren't self-explanatory)

- `Notes/` is an **Obsidian vault** (`.obsidian/` config). Notes may use `[[wiki-links]]` and other Obsidian-specific syntax — don't "fix" them to standard Markdown. Renaming a note can break backlinks elsewhere in the vault, so prefer in-place edits over renames.
- `Notes/cheatsheets/` — the largest body of original content, organized by domain:
  - `red_team/` is split by **kill-chain phase** (`00_fundamentals`, `01_reconnaissance`, `02_exploitation`, … `13_ai_security`, plus `rv_shells`). When adding a red-team note, place it under the matching phase folder.
  - `blue_team/` is split by **discipline** (`forensics`, `incident_response`, `malware_analysis`, `network_analysis`, `secure_development`, `threat_hunting`).
  - `networks/` is a numbered CCNA study guide (`00_…_Index.md` through `25_Troubleshooting.md`). Keep the numeric prefix when adding files so the index ordering is preserved.
  - `systems/` holds OS / protocol references (Linux, Windows, AD, Kerberos, SQL, HTML).
  - `editors/` — editor cheatsheets (e.g. VIM).
- `Learning_websites_Writeups/` — finished platform writeups, grouped by source (`THM/`, `Cryptohack/`, `91_PCAP/`). Most are PDFs; PCAPs and sample artifacts live alongside them.
- `ctf_writeups/` — per-event folders (`CTF_…`, `ctf_…`). Screenshots and artifacts are committed alongside the writeup.
- `Articles/` — `PL/` (Polish originals) and `ENG-translations/` (English versions of the same files). When adding or updating an article, keep the two trees in sync — same filename in both.
- `Certificates/` — earned certificates (`CCNA/`, `CyberMIL/`).
- `finished_rooms/README.md` — **the canonical index** of completed platform rooms / challenges, grouped by platform and track. Update this file whenever a new room/lab is completed; it is the human-readable progress log for the whole repo.
- `Confidential/` — see below.

## The `Confidential/` encryption scripts

The repo's only code. Two pairs of bash + PowerShell scripts:

- `manage_crypto.sh` / `manage_crypto.ps1` — recursively encrypt/decrypt files between sibling `decrypted/` and `encrypted/` folders, preserving directory structure and adding `.enc` extensions. Bash uses `openssl aes-256-cbc`; PowerShell uses .NET AES-256.
- `generate_aes_key.sh` / `generate_aes_key.ps1` — key/IV generation helpers used by the manage scripts.
- `secret_password` is also present in this folder.

Critical behaviors to preserve if you ever modify these scripts:

- `Confidential/decrypted/` and `Confidential/aes_key_and_iv.txt` are in `.gitignore` — they must **never** be committed. The `encrypted/` tree is what gets committed; `decrypted/` is the working copy that exists only on the user's machine.
- Decryption **overwrites** any existing files in `decrypted/`. Don't add a "merge" mode without explicit instruction.
- The bash and PowerShell scripts implement the same workflow — keep each pair (`manage_crypto.*`, `generate_aes_key.*`) at feature parity if you change one side.

Run from inside `Confidential/`:

```sh
./manage_crypto.sh        # then 'e' to encrypt, 'd' to decrypt
```

```powershell
.\manage_crypto.ps1       # then 'e' or 'd'
```

## Conventions

- **Languages mix.** Notes, commit messages, and folder names are sometimes Polish, sometimes English. Don't "normalize" existing content to one language — match what's already there in the file/folder you're editing. Articles specifically have parallel `PL/` and `ENG-translations/` trees with matching filenames.
- **Numeric prefixes** (`01_`, `02_`, …) in `networks/` and `red_team/` folders define display order. Keep them consistent when adding new files.
- **No build, no tests, no lint.** There is nothing to run for this repo aside from the encryption scripts. Do not invent commands.
- When the user mentions completing a new room/lab/article, the change typically spans two places: the writeup file itself plus an entry in `finished_rooms/README.md`.
