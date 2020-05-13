package internal

import (
	"crypto/rsa"
	"math/rand"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func testGeneratePrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.New(rand.NewSource(42)), 2048)
}
func TestSealSecrets(t *testing.T) {
	key, _ := testGeneratePrivateKey()

	s := Sealer{
		secretsRegexp: regexp.MustCompile(`(password|pin)$`),
		publicKey:     &key.PublicKey,
		metadata:      &Metadata{},
	}

	k := &yaml.Node{Value: "test_password"}
	v := &yaml.Node{Value: "secret!"}
	s.Seal(k, v)

	if strings.Contains(v.Value, "secret!") && !strings.HasPrefix(v.Value, "ENC:") {
		t.Errorf("Sealing was unsuccessful, got: %s, which contains: %s or no ENC indicator.", v.Value, "secret!")
	}
}

func TestVerifySecrets(t *testing.T) {
	key, _ := testGeneratePrivateKey()

	s := Sealer{
		secretsRegexp: regexp.MustCompile(`(password|pin)$`),
		publicKey:     &key.PublicKey,
		metadata:      &Metadata{},
	}

	k := &yaml.Node{Value: "test_password"}
	v := &yaml.Node{Value: "ENC:secret!"}
	err := s.Verify(k, v)

	if err != nil {
		t.Errorf("Verify was unsuccessful, got an error %s.", err.Error())
	}
}

func TestVerifyUnsealedSecrets(t *testing.T) {
	key, _ := testGeneratePrivateKey()

	s := Sealer{
		secretsRegexp: regexp.MustCompile(`(password|pin)$`),
		publicKey:     &key.PublicKey,
		metadata:      &Metadata{},
	}

	k := &yaml.Node{Value: "test_password"}
	v := &yaml.Node{Value: "secret!"}
	err := s.Verify(k, v)

	if err == nil {
		t.Errorf("Verify was unsuccessful, got no error due to unsealed secret.")
	}
}

func TestSealingOfAlreadySealedSecrets(t *testing.T) {
	key, _ := testGeneratePrivateKey()

	s := Sealer{
		secretsRegexp: regexp.MustCompile(`(password|pin)$`),
		publicKey:     &key.PublicKey,
		metadata:      &Metadata{},
	}

	k := &yaml.Node{Value: "test_password"}
	v := &yaml.Node{Value: "ENC:secret!"}
	s.Seal(k, v)

	if v.Value != "ENC:secret!" {
		t.Errorf("Sealing sealed again, got: %s, want: %s.", v.Value, "ENC:secret!")
	}
}

func TestSealNonSecrets(t *testing.T) {
	key, _ := testGeneratePrivateKey()

	s := Sealer{
		secretsRegexp: regexp.MustCompile(`(password|pin)$`),
		publicKey:     &key.PublicKey,
		metadata:      &Metadata{},
	}

	k := &yaml.Node{Value: "test"}
	v := &yaml.Node{Value: "secret!"}
	s.Seal(k, v)

	if v.Value != "secret!" {
		t.Errorf("Sealed yaml was incorrect, got: %s, want: %s.", v.Value, "secret!")
	}
}
