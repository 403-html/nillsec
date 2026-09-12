# nillsec

[![Release](https://github.com/403-html/nillsec/actions/workflows/release.yml/badge.svg)](https://github.com/403-html/nillsec/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/403-html/nillsec)](https://github.com/403-html/nillsec/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A small command-line tool for storing project secrets in an encrypted, version-control-friendly vault.

## Features

- AES-256-GCM authenticated encryption with Argon2id key derivation
- Atomic vault writes with private permissions and link protection
- Hidden secret input and command-scoped environment injection
- POSIX shell and PowerShell exports
- Checksum-verified self-updates

## Installation

Download the archive for your platform from the [latest release](https://github.com/403-html/nillsec/releases/latest) and verify it against `checksums.txt` before extracting it.

Linux example:

```sh
asset=nillsec-linux-amd64.tar.gz
curl -LO "https://github.com/403-html/nillsec/releases/latest/download/$asset"
curl -LO https://github.com/403-html/nillsec/releases/latest/download/checksums.txt
grep "  $asset$" checksums.txt | sha256sum --check -
tar -xzf "$asset"
sudo install nillsec-linux-amd64 /usr/local/bin/nillsec
```

Install from source with Go 1.26 or newer:

```sh
go install github.com/403-html/nillsec@latest
```

## Quick start

```sh
nillsec init
nillsec add database_password
nillsec exec -- npm run dev
```

`init` creates `secrets.vault` and asks for a master password of at least 12 characters. Use a unique, randomly generated passphrase.

## Commands

| Command | Description |
|---|---|
| `nillsec init [path]` | Create a vault |
| `nillsec add <key> [value]` | Add a secret |
| `nillsec set <key> [value]` | Add or replace a secret |
| `nillsec get <key>` | Print a secret value |
| `nillsec list` | List keys without values |
| `nillsec remove <key>` | Delete a secret |
| `nillsec edit` | Edit the decrypted vault |
| `nillsec env [--shell sh\|powershell]` | Print environment assignments |
| `nillsec exec [--] <command> ...` | Run a command with vault secrets |
| `nillsec upgrade` | Install the latest release |
| `nillsec version` | Print the installed version |

Omit the value from `add` and `set` to enter it through a hidden prompt. Passing a value as an argument is supported for compatibility but can expose it through shell history or process listings.

## Shell integration

Prefer `exec` when a single process needs the secrets:

```sh
nillsec exec -- docker compose up
```

To export secrets into the current shell:

```sh
eval "$(nillsec env --shell sh)"
```

```powershell
Invoke-Expression (& nillsec env --shell powershell | Out-String)
```

Vault keys are converted to uppercase environment names. Invalid names, NUL values, case-insensitive collisions, and `NILLSEC_PASSWORD` are rejected. The master password is never passed to commands started by `exec`.

## Editing

`nillsec edit` uses `VISUAL`, then `EDITOR`, with `vi` as the Unix default and Notepad as the Windows default. Editor arguments and quoted executable paths are supported.

On Linux, plaintext is placed in `/dev/shm` when available. Other systems use a private OS temporary file. Nillsec overwrites and removes that file after the editor exits, but filesystem journaling, swap, editor backups, or a crash may still retain plaintext.

## Upgrading

```sh
nillsec upgrade
```

The updater verifies the selected artifact against the release's `checksums.txt`, rejects malformed or oversized downloads, and installs only a newer semantic version. Major upgrades require confirmation.

## Comparison

| Approach | Repository content | Access model | Best fit | Main tradeoff |
|---|---|---|---|---|
| **nillsec** | One encrypted vault | Shared master password | Local development and small teams that need fast environment injection | Password distribution and rotation are manual |
| Plain `.env` | Plaintext configuration | File access | Local, non-sensitive configuration | No encryption at rest |
| [dotenvx](https://dotenvx.com/) | Encrypted `.env` files | Separate private key | Teams keeping the dotenv workflow | Requires a separate key lifecycle |
| [SOPS](https://github.com/getsops/sops) | Structured encrypted files | age, PGP, or cloud KMS | Infrastructure configuration and multi-key teams | More setup and key-provider concepts |
| [git-crypt](https://github.com/AGWA/git-crypt) | Selected files encrypted through Git filters | GPG users or a shared key | Transparent encryption of repository files | Git-specific setup; not focused on environment injection |
| Managed secrets service | Centrally stored secrets | Accounts, policies, and machine identities | Teams needing audit logs, access control, and rotation | External service and operational dependency |

Nillsec is intentionally narrow. Use it when encrypted secrets should travel with a repository and be injected locally without an external service. Prefer a managed service when centralized revocation, auditing, or automated rotation is required.

## Configuration

| Variable | Description | Default |
|---|---|---|
| `NILLSEC_VAULT` | Vault path | `secrets.vault` |
| `NILLSEC_PASSWORD` | Master password for automation | None |
| `VISUAL` | Preferred editor | None |
| `EDITOR` | Fallback editor | `vi` or Notepad |

## Security

- Anyone with a copy of the vault can attempt password guesses offline. Encryption cannot make a weak password safe.
- Vault files are replaced atomically. Symlinks and other non-regular paths are rejected.
- Environment variables may be visible to the child process, its descendants, debuggers, and other processes running under the same account.
- Use `NILLSEC_PASSWORD` only through protected automation secrets and unset it when no longer needed.
- Release checksums detect corruption or substitution only while GitHub release metadata remains trustworthy. They are not an independent signature.
