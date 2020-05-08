package internal

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	ssv1alpha1 "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
	"github.com/bitnami-labs/sealed-secrets/pkg/crypto"
	"gopkg.in/yaml.v3"
	"k8s.io/client-go/util/cert"
)

type Sealer struct {
	Name      string
	Namespace string
	SealedAt  string
	Cert      string
	Regexp    *regexp.Regexp
	PublicKey *rsa.PublicKey
}

type SealingRules struct {
	Name          string
	Namespace     string
	SecretsRegexp *regexp.Regexp
}

// Pass metadata

func NewSealer(srs *SealingRuleSet, m *Metadata) *Sealer {
	var pKey *rsa.PublicKey
	var cert string
	var sealedAt string

	if m != nil {
		if m.Name != "" && srs.Name != m.Name {
			fmt.Printf("Old secrets are limited to secret name %s, but new name is %s. Re-encryption is needed!", m.Name, srs.Name)
		}

		if m.Namespace != "" && srs.Namespace != m.Namespace {
			fmt.Printf("Old secrets are limited to secret namespace %s, but new namespace is %s. Re-encryption is needed!", m.Namespace, srs.Namespace)
		}

		cert = m.Cert
		sealedAt = m.SealedAt
		// cert is old
		s, _ := certStatus([]byte(cert), srs.CertSource.MaxAge)
		if s < 1 {
			cert = string(srs.GetRecentCert())
		}
		pKey, _ = getFirstPublicCert([]byte(cert))
	} else {
		cert = string(srs.GetRecentCert())
		pKey, _ = getFirstPublicCert([]byte(cert))
	}

	return &Sealer{
		Name:      srs.Name,
		Namespace: srs.Namespace,
		Regexp:    regexp.MustCompile(srs.EncryptRegex),
		Cert:      cert,
		SealedAt:  sealedAt,
		PublicKey: pKey,
	}
}

func (s *Sealer) Export() *Metadata {
	return &Metadata{
		Name:      s.Name,
		Namespace: s.Namespace,
		SealedAt:  s.SealedAt,
		Cert:      s.Cert,
	}
}

func getFirstPublicCert(d []byte) (*rsa.PublicKey, error) {
	certs, err := cert.ParseCertsPEM(d)
	if err != nil {
		return nil, err
	}

	// ParseCertsPem returns error if len(certs) == 0, but best to be sure...
	if len(certs) == 0 {
		return nil, errors.New("Failed to read any certificates")
	}

	cert, ok := certs[0].PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Expected RSA public key but found %v", certs[0].PublicKey)
	}

	return cert, nil
}

func certStatus(data []byte, d time.Duration) (int, error) {
	certs, err := cert.ParseCertsPEM(data)
	if err != nil {
		return -1, err
	}

	// ParseCertsPem returns error if len(certs) == 0, but best to be sure...
	if len(certs) == 0 {
		return -1, errors.New("Failed to read any certificates")
	}

	if time.Now().After(certs[0].NotBefore) && time.Now().Before(certs[0].NotAfter) {
		if time.Now().Before(certs[0].NotBefore.Add(d)) {
			return 1, nil
		}
		return 0, nil
	}
	return -1, nil
}

func (s *Sealer) seal(key *yaml.Node, value *yaml.Node) {
	if s.Regexp.MatchString(key.Value) && !strings.HasPrefix(value.Value, "ENC:") {
		ciphertext, err := crypto.HybridEncrypt(rand.Reader, s.PublicKey, []byte(value.Value), s.getLabel())

		if err != nil {
			fmt.Printf("Error appeared while sealing of secret %s: %v", key.Value, err)
		}

		encodedSecret := base64.StdEncoding.EncodeToString(ciphertext)

		value.SetString(fmt.Sprintf("ENC:%s", encodedSecret))
		s.SealedAt = time.Now().Format(time.RFC3339)
	}
}

func (s *Sealer) getLabel() []byte {
	if s.Name != "" && s.Namespace != "" {
		return ssv1alpha1.EncryptionLabel(s.Namespace, s.Name, ssv1alpha1.StrictScope)
	} else if s.Name == "" && s.Namespace != "" {
		return ssv1alpha1.EncryptionLabel(s.Namespace, s.Name, ssv1alpha1.NamespaceWideScope)
	} else {
		return ssv1alpha1.EncryptionLabel(s.Namespace, s.Name, ssv1alpha1.ClusterWideScope)
	}
}
