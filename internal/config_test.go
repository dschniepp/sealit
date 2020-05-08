package internal

import "testing"

var basicConfig = []byte(`
sealing_rules:
  - file_regex: \.dev\.yaml$
    name: mysecret
    namespace: default
    encrypt_regex: (password|pin)$
    cert: 
      controller: 
        context: docker-desktop
        name: sealit-sealed-secrets
        namespace: kube-system
      maxAge: 720h
`)

func TestLoadConfig(t *testing.T) {
	config, _ := LoadConfig(basicConfig, "~/.kube/config")

	t.Logf("%v", config)
}
