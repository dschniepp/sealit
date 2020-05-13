package internal

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"time"

	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"

	// Register Auth providers
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

type certSource interface {
	fetch() (io.ReadCloser, error)
}

type SealingRuleSet struct {
	FileRegex    string        `yaml:"fileRegex"`
	Name         string        `yaml:"name"`
	Namespace    string        `yaml:"namespace"`
	SecretsRegex string        `yaml:"secretsRegex"`
	MaxAge       time.Duration `yaml:"maxAge"`
	CertSources  CertSources   `yaml:"cert"`
}

type CertSources struct {
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

func (srs *SealingRuleSet) GetRegexForSecrets() *regexp.Regexp {
	return regexp.MustCompile(srs.SecretsRegex)
}

// GetCert fetches the cert from different sources
// Prio:
// 1. fetch from Kubernetes cluster
// 2. fetch from url
// 3. fetch from file path
func (cs *SealingRuleSet) GetCert() (string, error) {
	res, err := cs.CertSources.getCertSource()
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

func (cs *CertSources) getCertSource() (certSource, error) {
	if (cs.Kubernetes != KubernetesCertSource{}) {
		return cs.Kubernetes, nil
	} else if cs.Url != "" {
		return cs.Url, nil
	} else if cs.Path != "" {
		return cs.Path, nil
	}

	return nil, errors.New("no cert provider like `path`, `url`, or `kubernetes` was specified")
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
