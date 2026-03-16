# nillsec

Another tool for secrets encryption/decryption

`nillsec` is a minimal command-line tool that manages encrypted project secrets stored in a single vault file. Secrets are protected with AES-256-GCM encryption and an Argon2id-derived key. The vault file is safe to commit to version control.

## Installation

Build from source:

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
data: <base64 encrypted YAML>
```

## Usage

### Initialize a new vault

```sh
nillsec init
# Vault created: secrets.vault
```

### Add a secret

```sh
nillsec add database_password super-secret
nillsec add api_token tok-abc123
```

### Update a secret

```sh
nillsec set database_password new-password
```

### Retrieve a secret

```sh
nillsec get database_password
# super-secret
```

### List all keys (values are never shown)

```sh
nillsec list
# api_token
# database_password
```

### Remove a secret

```sh
nillsec remove api_token
```

### Export as environment variables

```sh
eval "$(nillsec env)"
# Exports DATABASE_PASSWORD and API_TOKEN into the current shell.
```

### Edit vault in your $EDITOR

```sh
nillsec edit
```

### Rotate the master password

```sh
nillsec rekey
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-f, --file` | `secrets.vault` | Path to the vault file |

## Security

- **KDF**: Argon2id (64 MiB memory, 3 iterations, parallelism 4)
- **Cipher**: AES-256-GCM with a unique random nonce per save
- **No plaintext on disk**: secrets are never written unencrypted outside of memory
- **Atomic writes**: the vault file is replaced atomically via a temporary file
