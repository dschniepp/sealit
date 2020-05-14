package internal

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"time"

	ssv1alpha1 "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
	"github.com/bitnami-labs/sealed-secrets/pkg/crypto"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"
	certUtil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"

	// Register Auth providers
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

var kubeConfig string

type certSource interface {
	fetch() (io.ReadCloser, error)
}

type SealingRuleSet struct {
	FileRegex    string `yaml:"fileRegex"`
	Name         string `yaml:"name"`
	Namespace    string `yaml:"namespace"`
	SecretsRegex string `yaml:"secretsRegex"`
	Cert         *Cert  `yaml:"cert"`
}

type Cert struct {
	MaxAge  time.Duration `yaml:"maxAge"`
	Sources *Sources      `yaml:"sources"`
}

type Sources struct {
	Url        UrlCertSource        `yaml:"url,omitempty"`
	Path       PathCertSource       `yaml:"path,omitempty"`
	Kubernetes KubernetesCertSource `yaml:"kubernetes,omitempty"`
}

type UrlCertSource string

type PathCertSource string

type KubernetesCertSource struct {
	Context   string `yaml:"context"`
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
}

func (srs *SealingRuleSet) GetSecretsRegex() *regexp.Regexp {
	return regexp.MustCompile(srs.SecretsRegex)
}

// GetCert fetches the cert from different sources
// Prio:
// 1. fetch from Kubernetes cluster
// 2. fetch from url
// 3. fetch from file path
func (cs *SealingRuleSet) GetCert() (string, error) {
	res, err := cs.Cert.getSource()
	if err != nil {
		return "", err
	}

	r, err := res.fetch()
	if err != nil {
		return "", err
	}

	cert, err := ioutil.ReadAll(r)

	return string(cert), err
}

func (c *Cert) getSource() (certSource, error) {
	if c.Sources != nil {
		if (c.Sources.Kubernetes != KubernetesCertSource{}) {
			return c.Sources.Kubernetes, nil
		} else if c.Sources.Url != "" {
			return c.Sources.Url, nil
		} else if c.Sources.Path != "" {
			return c.Sources.Path, nil
		}
	}

	return nil, errors.New("no cert source like `kubernetes`, `url` or `path` was specified")
}

func (path PathCertSource) fetch() (io.ReadCloser, error) {
	log.Print("[DEBUG] Fetch cert from file system")
	return os.Open(string(path))
}

func (url UrlCertSource) fetch() (io.ReadCloser, error) {
	log.Print("[DEBUG] Fetch cert from url")
	resp, err := http.Get(string(url))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cannot fetch %q: %s", string(url), resp.Status)
	}
	return resp.Body, nil
}

func (kubernetes KubernetesCertSource) fetch() (io.ReadCloser, error) {
	log.Print("[DEBUG] Fetch cert from within Kubernetes sealed secrets service")
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.DefaultClientConfig = &clientcmd.DefaultClientConfig
	if kubeConfig != "" {
		loadingRules.ExplicitPath = kubeConfig
	}
	overrides := clientcmd.ConfigOverrides{}

	if kubernetes.Context != "" {
		overrides.CurrentContext = kubernetes.Context
	}

	clientConfig := clientcmd.NewInteractiveDeferredLoadingClientConfig(loadingRules, &overrides, os.Stdin)
	conf, err := clientConfig.ClientConfig()

	if err != nil {
		return nil, err
	}
	conf.AcceptContentTypes = "application/x-pem-file, */*"
	restClient, err := corev1.NewForConfig(conf)
	if err != nil {
		return nil, err
	}

	f, err := restClient.
		Services(kubernetes.Namespace).
		ProxyGet("http", kubernetes.Name, "", "/v1/cert.pem", nil).
		Stream()

	if err != nil {
		return nil, fmt.Errorf("cannot fetch certificate: %v", err)
	}

	return f, nil
}

func (k KubernetesCertSource) fetchKeys() (map[string]*rsa.PrivateKey, *rsa.PublicKey, error) {
	log.Print("[DEBUG] Fetch cert from within Kubernetes sealed secrets service")
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.DefaultClientConfig = &clientcmd.DefaultClientConfig
	if kubeConfig != "" {
		loadingRules.ExplicitPath = kubeConfig
	}
	overrides := clientcmd.ConfigOverrides{}

	if k.Context != "" {
		overrides.CurrentContext = k.Context
	}

	clientConfig := clientcmd.NewInteractiveDeferredLoadingClientConfig(loadingRules, &overrides, os.Stdin)
	conf, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, nil, err
	}

	restClient, err := corev1.NewForConfig(conf)
	if err != nil {
		return nil, nil, err
	}

	list, err := restClient.Secrets(k.Namespace).List(metav1.ListOptions{
		LabelSelector: "sealedsecrets.bitnami.com/sealed-secrets-key",
	})
	if err != nil {
		return nil, nil, err
	}

	if len(list.Items) == 0 {
		return nil, nil, fmt.Errorf("No certificates found")
	}

	sort.Sort(ssv1alpha1.ByCreationTimestamp(list.Items))

	latestKey := &list.Items[len(list.Items)-1]

	privKey, err := keyutil.ParsePrivateKeyPEM(latestKey.Data[v1.TLSPrivateKeyKey])
	if err != nil {
		return nil, nil, err
	}

	certs, err := certUtil.ParseCertsPEM(latestKey.Data[v1.TLSCertKey])
	if err != nil {
		return nil, nil, err
	}

	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("Failed to read any certificates")
	}

	rsaPrivKey := privKey.(*rsa.PrivateKey)
	fp, err := crypto.PublicKeyFingerprint(&rsaPrivKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	privKeys := map[string]*rsa.PrivateKey{fp: rsaPrivKey}

	cert, ok := certs[0].PublicKey.(*rsa.PublicKey)

	if !ok {
		return nil, nil, fmt.Errorf("Expected RSA public key but found %v", certs[0].PublicKey)
	}

	return privKeys, cert, err
}

func (s *SealingRuleSet) getLabel() []byte {
	if s.Name != "" && s.Namespace != "" {
		log.Printf("[DEBUG] Scope of secrets is limited to secert: `%s` and namespace: `%s`", s.Name, s.Namespace)
		return ssv1alpha1.EncryptionLabel(s.Namespace, s.Name, ssv1alpha1.StrictScope)
	} else if s.Name == "" && s.Namespace != "" {
		log.Printf("[DEBUG] Scope of secrets is limited to namespace: `%s`", s.Namespace)
		return ssv1alpha1.EncryptionLabel(s.Namespace, s.Name, ssv1alpha1.NamespaceWideScope)
	} else {
		log.Print("[DEBUG] Scope of secrets is not limited")
		return ssv1alpha1.EncryptionLabel(s.Namespace, s.Name, ssv1alpha1.ClusterWideScope)
	}
}
