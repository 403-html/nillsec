# nillsec

[![Release](https://github.com/403-html/nillsec/actions/workflows/release.yml/badge.svg)](https://github.com/403-html/nillsec/actions/workflows/release.yml)
[![Latest Release](https://img.shields.io/github/v/release/403-html/nillsec)](https://github.com/403-html/nillsec/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A simple command-line tool for managing encrypted project secrets stored in a single file.

## Features

- **AES-256-GCM** authenticated encryption
- **Argon2id** key derivation (brute-force resistant)
- Single encrypted vault file — safe to commit to version control
- Secrets are decrypted only in memory, never written to disk in plaintext (except during `edit`, which uses a temporary file — see below)
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

> **Security note:** The `edit` command temporarily decrypts vault contents into a
> plaintext file in the system's temp directory (`os.TempDir()`) so that the editor
> can open it. The file is created with mode `0600` (owner-readable only), wiped, and
> deleted as soon as the editor exits. Avoid using `edit` on shared or untrusted
> machines where the temp directory may be accessible to other users or where the
> filesystem retains deleted data.

### Export secrets as environment variables

```sh
eval "$(nillsec env)"
# Sets DATABASE_PASSWORD and API_TOKEN in the current shell.
```

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
