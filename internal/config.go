package internal

import (
	"time"

	"gopkg.in/yaml.v3"

	// Register Auth providers
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

var kubeConfig string

type Config struct {
	SealingRuleSets []SealingRuleSet `yaml:"sealing_rules"`
}

// ExampleConfig Provide an example config of the `.sealit.yaml`
func ExampleConfig() Config {
	d, _ := time.ParseDuration("720h")

	return Config{
		SealingRuleSets: []SealingRuleSet{
			SealingRuleSet{
				FileRegex:    "\\.dev\\.yaml$",
				Name:         "secret",
				Namespace:    "default",
				EncryptRegex: "(password|pin)$",
				CertSource: CertSource{
					Url:  "https://example.org",
					Path: "cert.pem",
					Controller: SealedSecretController{
						Context:   "KubeContextName",
						Name:      "secret-controller",
						Namespace: "sealed-secret-namespace",
					},
					MaxAge: d,
				},
			},
		},
	}
}

func LoadConfig(file []byte, kubeConfig string) (Config, error) {
	kubeConfig = kubeConfig
	var config Config
	err := yaml.Unmarshal(file, &config)
	return config, err
}