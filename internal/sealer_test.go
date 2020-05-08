package internal

import (
	"crypto/rsa"
	"math/rand"
	"reflect"
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
		Regexp:    regexp.MustCompile(`(password|pin)$`),
		PublicKey: &key.PublicKey,
	}

	k := &yaml.Node{Value: "test_password"}
	v := &yaml.Node{Value: "secret!"}
	s.seal(k, v)

	if strings.Contains(v.Value, "secret!") && !strings.HasPrefix(v.Value, "ENC:") {
		t.Errorf("Sealing was unsuccessful, got: %s, which contains: %s or no ENC indicator.", v.Value, "secret!")
	}
}

func TestSealingOfAlreadySealedSecrets(t *testing.T) {
	key, _ := testGeneratePrivateKey()

	s := Sealer{
		Regexp:    regexp.MustCompile(`(password|pin)$`),
		PublicKey: &key.PublicKey,
	}

	k := &yaml.Node{Value: "test_password"}
	v := &yaml.Node{Value: "ENC:secret!"}
	s.seal(k, v)

	if v.Value != "ENC:secret!" {
		t.Errorf("Sealing sealed again, got: %s, want: %s.", v.Value, "ENC:secret!")
	}
}

func TestSealNonSecrets(t *testing.T) {
	key, _ := testGeneratePrivateKey()

	s := Sealer{
		Regexp:    regexp.MustCompile(`(password|pin)$`),
		PublicKey: &key.PublicKey,
	}

	k := &yaml.Node{Value: "test"}
	v := &yaml.Node{Value: "secret!"}
	s.seal(k, v)

	if v.Value != "secret!" {
		t.Errorf("Sealed yaml was incorrect, got: %s, want: %s.", v.Value, "secret!")
	}
}

func TestGetLabelForNamespaceAndName(t *testing.T) {
	s := Sealer{
		Namespace: "default",
		Name:      "secret",
	}

	l := s.getLabel()

	if !reflect.DeepEqual(l, []byte("default/secret")) {
		t.Errorf("Label was incorrect, got: %s, want: %s.", l, "default/secret")
	}
}

func TestGetLabelForNamespaceOnly(t *testing.T) {
	s := Sealer{
		Namespace: "default",
	}

	l := s.getLabel()

	if !reflect.DeepEqual(l, []byte("default")) {
		t.Errorf("Label was incorrect, got: %s, want: %s.", l, "default")
	}
}

func TestGetLabelForUndefinedNameAndNamespace(t *testing.T) {
	s := Sealer{}
	l := s.getLabel()

	if !reflect.DeepEqual(l, []byte("")) {
		t.Errorf("Label was incorrect, got: %s, want: %s.", l, "")
	}
}
