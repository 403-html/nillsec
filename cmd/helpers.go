package cmd

import (
	"github.com/403-html/nillsec/internal/vault"
	"gopkg.in/yaml.v3"
)

// unmarshalVaultYAML parses a YAML blob into a Vault struct.
func unmarshalVaultYAML(data []byte, v *vault.Vault) error {
	return yaml.Unmarshal(data, v)
}

// zeroSlice overwrites a byte slice with zeros.
func zeroSlice(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
