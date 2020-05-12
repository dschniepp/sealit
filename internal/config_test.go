package internal

import "testing"

var basicConfig = []byte(`
sealing_rules:
  - file_regex: \.dev\.yaml$
    name: mysecret
    namespace: default
    encrypt_regex: (password|pin)$
    maxAge: 720h
    cert: 
      kubernetes: 
        context: docker-desktop
        name: sealit-sealed-secrets
        namespace: kube-system
`)

func TestLoadConfig(t *testing.T) {
	config, _ := LoadConfig(basicConfig, "~/.kube/config")

	t.Logf("%v", config)
}
