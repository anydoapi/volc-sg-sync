package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRejectsInsecureIPProvider(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(`ip_providers: [http://example.test/ip]
rules:
  - name: ssh
    region: cn-beijing
    security_group_id: sg-1
    port_start: 22
    port_end: 22
`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Fatal("insecure provider accepted")
	}
}

func TestLoadDefaultsAndValidatesRules(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(`rules:
  - name: ssh
    region: cn-beijing
    security_group_id: sg-1
    protocol: tcp
    port_start: 22
    port_end: 22
`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Rules[0].Priority != 1 || len(cfg.IPProviders) < 2 {
		t.Fatalf("cfg=%#v", cfg)
	}
	if got, _ := CIDR("1.2.3.4"); got != "1.2.3.4/32" {
		t.Fatal(got)
	}
}
