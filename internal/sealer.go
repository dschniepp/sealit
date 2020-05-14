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

const encodeIdentifier = "ENC:"

type Sealer struct {
	secretsRegexp *regexp.Regexp
	publicKey     *rsa.PublicKey
	label         []byte
	metadata      *Metadata
}

type Resealer struct {
	secretsRegexp *regexp.Regexp
	publicKey     *rsa.PublicKey
	privateKeys   map[string]*rsa.PrivateKey
	label         []byte
	newLabel      []byte
	metadata      *Metadata
}

func NewSealer(srs *SealingRuleSet, m *Metadata, fetchCert bool) (s *Sealer, err error) {
	log.Printf("[DEBUG] Create sealer based on sealing rules %v and metadata %v", srs, m)
	if *m == (Metadata{}) {
		log.Printf("[DEBUG] File was never encoded before, init metadata block")

		m.Name = srs.Name
		m.Namespace = srs.Namespace

		if m.Cert, err = srs.GetCert(); err != nil {
			return nil, err
		}
	} else {
		log.Printf("[DEBUG] File has encoded values and a meta block")

		if m.Name != "" && srs.Name != m.Name {
			return nil, fmt.Errorf("old secrets are limited to secret name %s, but new name is %s. Re-encryption is needed", m.Name, srs.Name)
		}

		if m.Namespace != "" && srs.Namespace != m.Namespace {
			return nil, fmt.Errorf("old secrets are limited to secret namespace %s, but new namespace is %s. Re-encryption is needed", m.Namespace, srs.Namespace)
		}

		certStatus, err := certStatus([]byte(m.Cert), srs.Cert.MaxAge)

		if err != nil {
			return nil, err
		}

		if certStatus != validCert || fetchCert {
			if m.Cert, err = srs.GetCert(); err != nil {
				return nil, err
			}
		}
	}

	pKey, err := getPublicCert([]byte(m.Cert))

	if err != nil {
		return nil, err
	}

	return &Sealer{
		secretsRegexp: srs.GetSecretsRegex(),
		publicKey:     pKey,
		label:         m.getLabel(),
		metadata:      m,
	}, nil
}

func NewResealer(srs *SealingRuleSet, m *Metadata) (s *Resealer, err error) {
	log.Printf("[DEBUG] Create resealer based on sealing rules %v and metadata %v", srs, m)

	if (srs.Cert.Sources.Kubernetes == KubernetesCertSource{}) {
		return s, errors.New("resealing works only with Kubernetes cert source")
	}

	pKeys, pKey, err := srs.Cert.Sources.Kubernetes.fetchKeys()

	if err != nil {
		return nil, err
	}

	return &Resealer{
		secretsRegexp: srs.GetSecretsRegex(),
		publicKey:     pKey,
		privateKeys:   pKeys,
		label:         m.getLabel(),
		newLabel:      srs.getLabel(),
		metadata:      m,
	}, nil
}

func (s *Sealer) valueNeedsToBeSealed(key *yaml.Node, value *yaml.Node) bool {
	if s.secretsRegexp.MatchString(key.Value) {
		if !strings.HasPrefix(value.Value, encodeIdentifier) {
			return true
		}
		log.Printf("[DEBUG] Value of `%s` was already encrypted", key.Value)

		return false
	}
	log.Printf("[DEBUG] `%s` did not match regex %s", key.Value, s.secretsRegexp.String())

	return false
}

func (r *Resealer) Reseal(key *yaml.Node, value *yaml.Node) error {
	if r.secretsRegexp.MatchString(key.Value) {
		if strings.HasPrefix(value.Value, encodeIdentifier) {
			secret := strings.TrimPrefix(value.Value, encodeIdentifier)
			decodedSecret, err := base64.StdEncoding.DecodeString(secret)

			if err != nil {
				return err
			}

			plaintext, err := crypto.HybridDecrypt(rand.Reader, r.privateKeys, decodedSecret, r.label)

			if err != nil {
				return err
			}

			value.SetString(string(plaintext))

			log.Printf("[DEBUG] Decrypted value of `%s`", key.Value)
		}

		ciphertext, err := crypto.HybridEncrypt(rand.Reader, r.publicKey, []byte(value.Value), r.newLabel)

		if err != nil {
			return err
		}

		if value.Value == "" {
			log.Printf("[WARNING] Value of `%s` is an empty string", key.Value)
		} else if value.Value != strings.TrimSpace(value.Value) {
			log.Printf("[WARNING] Value of `%s` is padded with whitespace", key.Value)
		}

		encodedSecret := base64.StdEncoding.EncodeToString(ciphertext)
		value.SetString(fmt.Sprintf("%s%s", encodeIdentifier, encodedSecret))
		r.metadata.SealedAt = time.Now().Format(time.RFC3339)
		log.Printf("[DEBUG] Encrypted value of `%s`", key.Value)
	}

	return nil
}

func (s *Sealer) Seal(key *yaml.Node, value *yaml.Node) error {
	if s.valueNeedsToBeSealed(key, value) {
		ciphertext, err := crypto.HybridEncrypt(rand.Reader, s.publicKey, []byte(value.Value), s.label)

		if err != nil {
			return err
		}

		if value.Value == "" {
			log.Printf("[WARNING] Value of `%s` is an empty string", key.Value)
		} else if value.Value != strings.TrimSpace(value.Value) {
			log.Printf("[WARNING] Value of `%s` is padded with whitespace", key.Value)
		}

		encodedSecret := base64.StdEncoding.EncodeToString(ciphertext)
		value.SetString(fmt.Sprintf("%s%s", encodeIdentifier, encodedSecret))
		s.metadata.SealedAt = time.Now().Format(time.RFC3339)
		log.Printf("[DEBUG] Encrypted value of `%s`", key.Value)
	}

	return nil
}

func (s *Sealer) Verify(key *yaml.Node, value *yaml.Node) error {
	if s.valueNeedsToBeSealed(key, value) {
		return fmt.Errorf("key `%s` is not encrypted", key.Value)
	}

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
