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
	config *Config
}

func Init(sealitconfig string, force bool) (err error) {
	if file, err := os.Stat(sealitconfig); file != nil && !force {
		log.Fatalf("config file %s already exists", sealitconfig)
		return err
	}

	d, err := yaml.Marshal(ExampleConfig())

	if err := ioutil.WriteFile(sealitconfig, d, 0644); err != nil {
		return err
	}

	return nil
}

func Template(sealedSecretPath string) (err error) {
	if sealedSecretPath == "" {
		fmt.Printf("%s", template)
		return nil
	} else {
		return ioutil.WriteFile(sealedSecretPath, template, os.ModePerm)
	}
}

func New(sealitconfig string, kubeconfig string) *Sealit {
	configFile, err := ioutil.ReadFile(sealitconfig)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}

	config, _ := LoadConfig(configFile, kubeconfig)

	return &Sealit{
		config: &config,
	}
}

func (s *Sealit) Seal(force bool) (err error) {
	files, err := ioutil.ReadDir(".")
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		if !f.IsDir() {
			for _, srs := range s.config.SealingRuleSets {
				fileNamePattern := regexp.MustCompile(srs.FileRegex)
				if fileNamePattern.MatchString(f.Name()) {
					data, _ := ioutil.ReadFile(f.Name())
					vf := NewValueFile(data)
					sealer := NewSealer(&srs, vf.Sealit)
					vf.ApplyFuncToValues(sealer.seal)
					metaData := sealer.Export()
					vf.updateMetadata(metaData)
					data = vf.Export()
					ioutil.WriteFile(f.Name(), data, 0644)
				}
			}
		}
	}

	return nil
}

func (s *Sealit) Verify() (err error) {
	files, err := ioutil.ReadDir(".")
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range files {
		if !f.IsDir() {
			for _, srs := range s.config.SealingRuleSets {
				fileNamePattern := regexp.MustCompile(srs.FileRegex)
				if fileNamePattern.MatchString(f.Name()) {
					data, _ := ioutil.ReadFile(f.Name())
					vf := NewValueFile(data)
					sealer := NewSealer(&srs, vf.Sealit)
					vf.ApplyFuncToValues(sealer.seal)
					metaData := sealer.Export()
					if vf.Sealit == nil || vf.Sealit.SealedAt != metaData.SealedAt {
						fmt.Printf("\nWarning: %s is not completely encrypted!\n", f.Name())
					}
				}
			}
		}
	}

	return nil
}
