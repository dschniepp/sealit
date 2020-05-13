package internal

import (
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	SealingRuleSets []SealingRuleSet `yaml:"sealingRules"`
}

// ExampleConfig Provide an example config of the `.sealit.yaml`
func ExampleConfig() Config {
	d, _ := time.ParseDuration("720h")

	return Config{
		SealingRuleSets: []SealingRuleSet{
			{
				FileRegex:    "\\.dev\\.yaml$",
				Name:         "secret",
				Namespace:    "default",
				SecretsRegex: "(password|pin)$",
				Cert: &Cert{
					MaxAge: d,
					Sources: &Sources{
						Kubernetes: KubernetesCertSource{
							Context:   "KubeContextName",
							Name:      "sealed-secrets",
							Namespace: "kube-system",
						},
						Url:  "https://example.org",
						Path: "cert.pem",
					},
				},
			},
		},
	}
}

func LoadConfig(file []byte) (config Config, err error) {
	return config, yaml.Unmarshal(file, &config)
}
