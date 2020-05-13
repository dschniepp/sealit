package internal

import (
	"testing"
	"time"
)

var basicConfig = []byte(`
sealingRules:
  - fileRegex: \.dev\.yaml$
    name: mysecret
    namespace: default
    secretsRegex: (password|pin)$
    cert: 
      maxAge: 720h
      sources:
        kubernetes: 
          context: docker-desktop
          name: sealit-sealed-secrets
          namespace: kube-system
`)

func TestLoadConfig(t *testing.T) {
	config, _ := LoadConfig(basicConfig)

	maxAge := config.SealingRuleSets[0].Cert.MaxAge
	duration, _ := time.ParseDuration("720h")

	if maxAge != duration {
		t.Errorf("Priority was incorrect, got: \n%s\n, want: \n%s\n.", maxAge, duration)
	}
}
