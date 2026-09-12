# nillsec

[![Release](https://github.com/403-html/nillsec/actions/workflows/release.yml/badge.svg)](https://github.com/403-html/nillsec/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/403-html/nillsec)](https://github.com/403-html/nillsec/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A simple command-line tool for managing encrypted project secrets stored in a single file.

## Features

- **AES-256-GCM** authenticated encryption
- **Argon2id** key derivation (brute-force resistant)
- Single encrypted vault file designed for version control (see [Security considerations](#security-considerations))
- Secrets are decrypted only in memory; the `edit` command attempts to keep plaintext off disk (using `/dev/shm` on Linux when available; see below)
- Export secrets as environment variables (`eval "$(nillsec env)"`)
- Run processes with injected secrets (`nillsec exec -- <command>`)

## Installation

**Pre-built binary (macOS / Linux / Windows)**

Download the archive for your platform from the [latest release](https://github.com/403-html/nillsec/releases/latest). Each release includes `checksums.txt`; verify the selected archive before extracting it. For example:

```sh
# Linux (x86-64)
asset=nillsec-linux-amd64.tar.gz
curl -LO "https://github.com/403-html/nillsec/releases/latest/download/$asset"
curl -LO https://github.com/403-html/nillsec/releases/latest/download/checksums.txt
grep "  $asset$" checksums.txt | sha256sum --check -
tar -xzf "$asset"
sudo mv nillsec-linux-amd64 /usr/local/bin/nillsec
```

For macOS, select `nillsec-darwin-arm64.tar.gz` (Apple Silicon) or `nillsec-darwin-amd64.tar.gz` (Intel) and replace `sha256sum --check` with `shasum -a 256 --check`. Extracting in the terminal avoids Finder adding a quarantine flag.

**Via Go toolchain**

```sh
go install github.com/403-html/nillsec@latest
```

Go 1.26 or newer is required when building from source.

**Build from source**

```sh
go build -o nillsec .
```

## Vault file format

```
$VAULT;1
kdf: argon2id
salt: <base64>
nonce: <base64>
cipher: aes-256-gcm
data: <base64>
```

## Usage

### Create a new vault

```sh
nillsec init
# Or choose a path explicitly:
nillsec init path/to/secrets.vault
```

New master passwords must be at least 12 characters. Use a unique, randomly generated passphrase: anyone who obtains the encrypted file can attempt password guesses offline.

### Add a secret

```sh
nillsec add database_password
# Secret value: (input is hidden)
```

For non-interactive automation, omit the value and send one line on standard input; inject `NILLSEC_PASSWORD` as a protected CI variable. For backwards compatibility, a value may still be supplied as the second argument. That form emits a warning because the value can be retained in shell history and exposed in process listings.

### Update an existing secret

```sh
nillsec set database_password
# Secret value: (input is hidden)
```

### Retrieve a secret

```sh
nillsec get database_password
# → super-secret
```

### List all secret keys (values are not printed)

```sh
nillsec list
# → api_token
# → database_password
```

### Delete a secret

```sh
nillsec remove api_token
```

### Edit vault contents in `$VISUAL` or `$EDITOR`

```sh
nillsec edit
```

> **Security note:** The `edit` command temporarily exposes vault plaintext so
> that the editor can open it.
>
> - **Linux:** the file is created in `/dev/shm`, a `tmpfs` mount backed
>   by RAM when that location is available.
>   If `/dev/shm` is unavailable or unwritable, `nillsec` falls back to the OS
>   temp directory.
> - **Other platforms:** a private temp file (`0600`, where supported) is used
>   in the OS temp directory. Its contents are overwritten and the file is
>   deleted as soon as the editor exits.
>
> Filesystem journaling, copy-on-write storage, swap, editor backup/swap files,
> and crash recovery can retain plaintext despite that cleanup. Configure the
> selected editor accordingly. If the temporary file cannot be removed,
> `nillsec` aborts and does not save the vault.

`VISUAL` takes precedence over `EDITOR`. Quoted executable paths and arguments such as `code --wait` are supported without invoking a shell. The default is `vi` on Unix-like systems and Notepad on Windows.

### Run a command with secrets injected

```sh
nillsec exec -- npm run dev
```

Secrets are injected as environment variables into the child process directly. No shell expansion occurs, so secret values are not interpreted as shell code. Vault secrets take precedence over identically-named inherited variables. The `NILLSEC_PASSWORD` control variable is always removed before the child starts.

```sh
nillsec exec -- python manage.py runserver
nillsec exec -- docker compose up

# Open a secure shell with all secrets available as env vars:
nillsec exec -- $SHELL
```

The `--` separator is optional but recommended to clearly distinguish nillsec flags from the command being run.

### Export secrets as environment variables

If you need to export secrets into your current shell session rather than running a subprocess, use:

```sh
eval "$(nillsec env --shell sh)"
# Sets DATABASE_PASSWORD and API_TOKEN in the current shell.
```

PowerShell:

```powershell
Invoke-Expression (& nillsec env --shell powershell | Out-String)
```

With no `--shell` option, `env` defaults to `sh` output on Unix-like systems and PowerShell output on Windows. Keys are upper-cased. Invalid keys, NUL-containing values, the reserved `NILLSEC_PASSWORD` key, and case-only collisions such as `token`/`TOKEN` are rejected rather than exported ambiguously.

### Upgrade to the latest release

```sh
nillsec upgrade
```

`nillsec upgrade` fetches the latest release from GitHub, verifies the complete
artifact against its entry in the release's `checksums.txt`, replaces the
running binary in-place, and exits. Missing, malformed, mismatched, or oversized
artifacts are rejected. If the latest release is a **major version bump**
(e.g. v1 → v2), you will be warned that breaking changes may be present and
asked to confirm before the download begins. If you are already on a version
equal to or newer than the latest release, no replacement is attempted.

## Security considerations

- AES-GCM protects vault confidentiality and integrity, while Argon2id slows password guessing. It cannot make a weak password safe after an encrypted vault is copied, because guesses can be tested offline.
- Vault replacement is atomic and uses private permissions. Symlink and other non-regular vault paths are rejected to avoid writing through unexpected filesystem objects.
- `add <key> [value]` and `set <key> [value]` retain their argument form for compatibility, but omitting the value is safer because command-line arguments can be logged or inspected.
- Environment variables are visible to the executed process and its descendants and may be observable by other processes running with the same account or debugging privileges. Prefer short-lived `nillsec exec` processes to exporting into a long-running shell.
- `NILLSEC_PASSWORD` is intended for non-interactive automation. Environment-based credentials can be exposed by CI configuration, crash reports, or process inspection; use a protected CI secret and unset it as soon as practical. Nillsec does not pass it to `exec` children or editors.
- Release checksums detect corrupted or substituted artifact downloads when GitHub's release metadata remains trustworthy. They are not an independent signature if the project release account itself is compromised.

## Comparison with similar tools

| Tool / approach | Encrypted at rest | Git-friendly | Export to env vars | Needs external service | Best fit |
|---|:---:|:---:|:---:|:---:|---|
| **nillsec** | ✅ | ✅ | ✅ | No | Local dev and small teams; encrypted secrets in Git with quick env export; separate master password to manage |
| Plain `.env` | ❌ | ⚠️ | ✅ | No | Prototypes and non-sensitive config; easy to leak |
| direnv / dotenv | ❌ | ⚠️ | ✅ | No | Convenient env auto-loading; still plaintext |
| dotenvx | ✅ | ✅ | ✅ | No | `.env`-style workflow with added encryption; separate key to manage |
| Ansible Vault / SOPS / git-crypt | ✅ | ✅ | ⚠️ | No | Encrypting files or whole repos; not optimised for env export |
| OS keychain (envchain, Keychain) | ✅ | ❌ | ✅ | No | Workstation secrets in OS keystore; not portable across machines |
| Doppler / Infisical / 1Password CLI | ✅ | ❌ | ✅ | **Yes** | Centralised secret lifecycle with sharing, audit, and rotation |
| CI/CD secrets (GitHub Actions, etc.) | ✅ | ❌ | ✅ | **Yes** | Build and deploy pipelines; not local dev friendly |
| Vault / Kubernetes Secrets | ✅ | ⚠️ | ❌ | **Yes** | Enterprise platform-level secret management; high complexity |

## Environment variables

| Variable           | Description                                  | Default         |
|--------------------|----------------------------------------------|-----------------|
| `NILLSEC_VAULT`    | Path to the vault file                       | `secrets.vault` |
| `NILLSEC_PASSWORD` | Master password (for scripting / CI use)     | None            |
| `VISUAL`           | Preferred editor used by `edit`              | None            |
| `EDITOR`           | Fallback editor used by `edit`               | `vi` / Notepad   |

## Typical workflow

```sh
nillsec init
nillsec add database_password
nillsec add api_token

# Run a command directly with secrets injected:
nillsec exec -- npm run dev

# Or open a shell with all secrets available:
nillsec exec -- $SHELL

# If you need the secrets exported into your current shell session:
eval "$(nillsec env)"
echo "$DATABASE_PASSWORD"
```
