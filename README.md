# nillsec

[![Release](https://github.com/403-html/nillsec/actions/workflows/release.yml/badge.svg)](https://github.com/403-html/nillsec/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/403-html/nillsec)](https://github.com/403-html/nillsec/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A simple command-line tool for managing encrypted project secrets stored in a single file.

## Features

- **AES-256-GCM** authenticated encryption
- **Argon2id** key derivation (brute-force resistant)
- Single encrypted vault file — safe to commit to version control
- Secrets are decrypted only in memory; the `edit` command attempts to keep plaintext off disk (using `/dev/shm` on Linux when available — see below)
- Export secrets as environment variables (`eval "$(nillsec env)"`)

## Installation

**Pre-built binary (macOS / Linux / Windows)**

Download the archive for your platform from the [latest release](https://github.com/403-html/nillsec/releases/latest), then extract and install:

```sh
# macOS (Apple Silicon)
curl -L https://github.com/403-html/nillsec/releases/latest/download/nillsec-darwin-arm64.tar.gz | tar -xz
sudo mv nillsec-darwin-arm64 /usr/local/bin/nillsec

# macOS (Intel)
curl -L https://github.com/403-html/nillsec/releases/latest/download/nillsec-darwin-amd64.tar.gz | tar -xz
sudo mv nillsec-darwin-amd64 /usr/local/bin/nillsec

# Linux (x86-64)
curl -L https://github.com/403-html/nillsec/releases/latest/download/nillsec-linux-amd64.tar.gz | tar -xz
sudo mv nillsec-linux-amd64 /usr/local/bin/nillsec
```

> **macOS note:** always extract with `tar -xzf` (or pipe through `tar -xz` as above) rather than double-clicking the archive in Finder. Extracting in the terminal prevents macOS from applying the quarantine flag to the binary, which avoids the *"Apple could not verify…"* Gatekeeper prompt.

**Via Go toolchain**

```sh
go install github.com/403-html/nillsec@latest
```

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
```

### Add a secret

```sh
nillsec add database_password super-secret
nillsec add api_token abcdef
```

### Update an existing secret

```sh
nillsec set database_password new-value
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

### Edit vault contents in `$EDITOR`

```sh
nillsec edit
```

> **Security note:** The `edit` command temporarily exposes vault plaintext so
> that the editor can open it.
>
> - **Linux** — the file is created in `/dev/shm`, a `tmpfs` mount backed
>   entirely by RAM.  The decrypted content never reaches a physical disk.
>   If `/dev/shm` is unavailable or unwritable, `nillsec` falls back to the OS
>   temp directory.
> - **Other platforms** — a private temp file (`0600`) is used in the OS temp
>   directory.  Its contents are zero-wiped and the file is deleted as soon as
>   the editor exits.
>
> On all platforms the editor file is wiped and removed once the editor exits.
> If the file cannot be removed, `nillsec` aborts and does not save the vault,
> so that plaintext is never silently left behind.

### Export secrets as environment variables

```sh
eval "$(nillsec env)"
# Sets DATABASE_PASSWORD and API_TOKEN in the current shell.
```

### Upgrade to the latest release

```sh
nillsec upgrade
```

`nillsec upgrade` fetches the latest release from GitHub, replaces the running
binary in-place, and exits.  If the latest release is a **major version bump**
(e.g. v1 → v2), you will be warned that breaking changes may be present and
asked to confirm before the download begins.  If you are already on the latest
version, the command simply tells you so and exits without making any changes.

## Comparison with similar tools

| Tool / approach | Encrypted at rest | Git-friendly | Export to env vars | Needs external service | Best fit |
|---|:---:|:---:|:---:|:---:|---|
| **nillsec** | ✅ | ✅ | ✅ | No | Local dev & small teams — encrypted secrets in Git with quick env export; separate master password to manage |
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
| `NILLSEC_PASSWORD` | Master password (for scripting / CI use)     | —               |
| `EDITOR`           | Editor used by the `edit` command            | `vi`            |

## Typical workflow

```sh
nillsec init
nillsec add database_password secret
nillsec add api_token token123

# Later, in any script or shell session:
eval "$(nillsec env)"
echo "$DATABASE_PASSWORD"
```
