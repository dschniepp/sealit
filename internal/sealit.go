package internal

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Source for this template is https://github.com/bitnami-labs/sealed-secrets#sealedsecrets-as-templates-for-secrets
var template = []byte(`apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  {{- if (ne "" .Values.sealit.name) }}
  name: {{ .Values.sealit.name }}
  {{- end }}
  {{- if (ne "" .Values.sealit.namespace) }}
  name: {{ .Values.sealit.namespace }}
  {{- end }}
  labels:
    {{- include "sample-chart.labels" . | nindent 4 }}
{{- if and (ne "" .Values.sealit.namespace) (ne "" .Values.sealit.name) }}
  annotations:
  {{- if (eq "" .Values.sealit.namespace) }}
    "sealedsecrets.bitnami.com/cluster-wide": "true"
  {{- else if (eq "" .Values.sealit.name) }}
    "sealedsecrets.bitnami.com/namespace-wide": "true"
  {{- end }}
{{- end }}
spec:
  encryptedData:
    # Here you list your env variables. Do not forget to trim the prefixed "ENC:"!
    #PASSWORD: {{ .Values.env.password | trimPrefix "ENC:" }}
`)

type Sealit struct {
	config    *Config
	fetchCert bool
}

func Init(sealitconfig string, force bool) (err error) {
	if file, _ := os.Stat(sealitconfig); file != nil && !force {
		return fmt.Errorf("config file %v exists already", file.Name())
	}

	exampleConfig := ExampleConfig()

	d, err := yaml.Marshal(exampleConfig)
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(sealitconfig, d, 0644); err != nil {
		return err
	}

	return nil
}

func Template(sealedSecretPath string) (err error) {
	if sealedSecretPath == "" {
		fmt.Printf("%s", template)
		return nil
	}

	return ioutil.WriteFile(sealedSecretPath, template, 0644)
}

func New(sealitconfig string, kubeconfig string, fetchCert bool) (*Sealit, error) {
	log.Printf("[DEBUG] Load config file %s", sealitconfig)
	configFile, err := ioutil.ReadFile(sealitconfig)

	if err != nil {
		return nil, err
	}

	config, err := LoadConfig(configFile, kubeconfig)

	if err != nil {
		return nil, err
	}

	return &Sealit{
		config:    &config,
		fetchCert: fetchCert,
	}, nil
}

func (s *Sealit) Seal(force bool) (err error) {
	return s.applyToEveryMatchingFile(func(srs *SealingRuleSet, f os.FileInfo) (err error) {
		data, err := ioutil.ReadFile(f.Name())
		if err != nil {
			return err
		}

		log.Printf("[DEBUG] Load values file %s", f.Name())
		vf, err := NewValueFile(data)
		if err != nil {
			return err
		}

		log.Print("[DEBUG] Load sealer based on config and values file")
		sealer, err := NewSealer(srs, vf.Metadata, s.fetchCert)
		if err != nil {
			return err
		}

		log.Print("[DEBUG] Apply sealing function")
		err = vf.ApplyFuncToValues(sealer.Seal)
		if err != nil {
			return err
		}

		log.Print("[DEBUG] Export sealed yaml.Node tree")
		data, err = vf.Export()
		if err != nil {
			return err
		}

		return ioutil.WriteFile(f.Name(), data, 0644)
	})
}

func (s *Sealit) Verify() (err error) {
	return s.applyToEveryMatchingFile(func(srs *SealingRuleSet, fi os.FileInfo) (err error) {
		data, err := ioutil.ReadFile(fi.Name())
		if err != nil {
			return err
		}

		log.Printf("[DEBUG] Load values file %s", fi.Name())
		vf, err := NewValueFile(data)
		if err != nil {
			return err
		}

		log.Print("[DEBUG] Load sealer based on config and values file")
		sealer, err := NewSealer(srs, vf.Metadata, s.fetchCert)
		if err != nil {
			return err
		}

		log.Print("[DEBUG] Apply sealing function")
		err = vf.ApplyFuncToValues(sealer.Verify)

		if err != nil {
			return fmt.Errorf("in file %s %s", fi.Name(), err.Error())
		}

		return err
	})
}

func (s *Sealit) applyToEveryMatchingFile(fun func(*SealingRuleSet, os.FileInfo) error) error {
	files, err := ioutil.ReadDir(".")

	if err != nil {
		return err
	}

	for _, f := range files {
		if !f.IsDir() {
			for _, srs := range s.config.SealingRuleSets {
				fileNamePattern := regexp.MustCompile(srs.FileRegex)
				if fileNamePattern.MatchString(f.Name()) {
					if err := fun(&srs, f); err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}
