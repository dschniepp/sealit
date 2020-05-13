package internal

import "testing"

var basicConfig = []byte(`
sealingRules:
  - fileRegex: \.dev\.yaml$
    name: mysecret
    namespace: default
    secretsRegex: (password|pin)$
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
