# nillsec

A simple command-line tool for managing encrypted project secrets stored in a single file.

## Features

- **AES-256-GCM** authenticated encryption
- **Argon2id** key derivation (brute-force resistant)
- Single encrypted vault file — safe to commit to version control
- Secrets are decrypted only in memory, never written to disk in plaintext
- Export secrets as environment variables (`eval "$(nillsec env)"`)

## Installation

```sh
go install github.com/403-html/nillsec@latest
```

Or build from source:

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
