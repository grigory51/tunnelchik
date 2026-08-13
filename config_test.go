package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigIsStrict(t *testing.T) {
	valid := `
listen: ":8022"
host_key: /var/lib/tunnelchik/ssh_host_ed25519_key
known_hosts: /etc/tunnelchik/known_hosts
recordings_dir: /var/lib/tunnelchik/recordings
oidc:
  issuer: https://id.example.com
  client_id: tunnelchik
  scopes: [openid, profile, email]
routes:
  bots:
    address: 127.0.0.1:22
    users:
      ozhegov:
        required_roles: [tunnelchik:user]
`

	for name, contents := range map[string]string{
		"valid":           valid,
		"unknown field":   valid + "unknown: true\n",
		"second document": valid + "---\nlisten: ':9000'\n",
		"missing openid":  strings.Replace(valid, "[openid, profile, email]", "[profile, email]", 1),
		"invalid route":   strings.Replace(valid, "  bots:", "  'bad+route':", 1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			loaded, err := loadConfig(path)
			if name == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				target, err := loaded.resolveTarget("bots+ozhegov")
				if err != nil {
					t.Fatal(err)
				}
				if target.Address != "127.0.0.1:22" || target.User != "ozhegov" {
					t.Fatalf("unexpected target: %+v", target)
				}
				return
			}
			if err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
