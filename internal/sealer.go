package internal

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/bitnami-labs/sealed-secrets/pkg/crypto"
	"gopkg.in/yaml.v3"
	"k8s.io/client-go/util/cert"
)

const (
	invalidCert = iota
	deprecatedCert
	validCert
)

type Sealer struct {
	regexp    *regexp.Regexp
	publicKey *rsa.PublicKey
	label     []byte
	metadata  *Metadata
}

func NewSealer(srs *SealingRuleSet, m *Metadata) (*Sealer, error) {
	log.Printf("[DEBUG] Create sealer based on sealing rules %v and metadata %v", srs, m)
	if *m == (Metadata{}) {
		log.Printf("[DEBUG] File was never encoded before, init metadata block")

		m.Name = srs.Name
		m.Namespace = srs.Namespace

		cert, _ := srs.GetRecentCert()
		m.Cert = string(cert)
	} else {
		log.Printf("[DEBUG] File has encoded values and a meta block")

		if m.Name != "" && srs.Name != m.Name {
			return nil, fmt.Errorf("old secrets are limited to secret name %s, but new name is %s. Re-encryption is needed", m.Name, srs.Name)
		}

		if m.Namespace != "" && srs.Namespace != m.Namespace {
			return nil, fmt.Errorf("old secrets are limited to secret namespace %s, but new namespace is %s. Re-encryption is needed", m.Namespace, srs.Namespace)
		}

		certStatus, err := certStatus([]byte(m.Cert), srs.CertSource.MaxAge)

		if err != nil {
			return nil, err
		}

		if certStatus != validCert {
			cert, _ := srs.GetRecentCert()
			m.Cert = string(cert)
		}
	}

	pKey, err := getPublicCert([]byte(m.Cert))

	if err != nil {
		return nil, err
	}

	return &Sealer{
		regexp:    regexp.MustCompile(srs.EncryptRegex),
		publicKey: pKey,
		label:     m.getLabel(),
		metadata:  m,
	}, nil
}

func (s *Sealer) seal(key *yaml.Node, value *yaml.Node) error {
	if s.regexp.MatchString(key.Value) {
		if !strings.HasPrefix(value.Value, "ENC:") {
			ciphertext, err := crypto.HybridEncrypt(rand.Reader, s.publicKey, []byte(value.Value), s.label)

			if err != nil {
				return err
			}

			encodedSecret := base64.StdEncoding.EncodeToString(ciphertext)
			value.SetString(fmt.Sprintf("ENC:%s", encodedSecret))
			s.metadata.SealedAt = time.Now().Format(time.RFC3339)

			log.Printf("[DEBUG] Encoded value of `%s`", key.Value)

			return nil
		}
		log.Printf("[DEBUG] Value of `%s` was already encoded", key.Value)
	}
	log.Printf("[DEBUG] `%s` did not match regex %s", key.Value, s.regexp.String())

	return nil
}

func getFirstCert(d []byte) (*x509.Certificate, error) {
	if len(d) == 0 {
		return nil, fmt.Errorf("No cert was provided")
	}

	certs, err := cert.ParseCertsPEM(d)

	if err != nil {
		return nil, err
	}

	// ParseCertsPem returns error if len(certs) == 0, but best to be sure...
	if len(certs) == 0 {
		return nil, errors.New("Failed to read any certificates")
	}

	return certs[0], nil
}

func getPublicCert(d []byte) (*rsa.PublicKey, error) {
	cert, err := getFirstCert(d)

	if err != nil {
		return nil, err
	}

	publicCert, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Expected RSA public key but found %v", cert.PublicKey)
	}

	return publicCert, nil
}

func certStatus(d []byte, maxAge time.Duration) (int, error) {
	cert, err := getFirstCert(d)

	if err != nil {
		return invalidCert, err
	}

	log.Printf("[DEBUG] Cert is valid from %s till %s. Maximum cert age is set to %s", cert.NotBefore, cert.NotAfter, maxAge)
	if time.Now().After(cert.NotBefore) && time.Now().Before(cert.NotAfter) {
		if time.Now().Before(cert.NotBefore.Add(maxAge)) {
			return validCert, nil
		}
		return deprecatedCert, nil
	}
	return invalidCert, nil
}
