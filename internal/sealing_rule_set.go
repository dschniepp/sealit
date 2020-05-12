package internal

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	corev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/clientcmd"

	// Register Auth providers
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

type SealingRuleSet struct {
	FileRegex    string     `yaml:"file_regex"`
	Name         string     `yaml:"name"`
	Namespace    string     `yaml:"namespace"`
	EncryptRegex string     `yaml:"encrypt_regex"`
	CertSource   CertSource `yaml:"cert"`
}

type CertSource struct {
	Url        string               `yaml:"url,omitempty"`
	Path       string               `yaml:"path,omitempty"`
	Kubernetes KubernetesCertSource `yaml:"kubernetes,omitempty"`
	MaxAge     time.Duration        `yaml:"maxAge"`
}

type KubernetesCertSource struct {
	Context   string `yaml:"context"`
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
}

// GetRecentCert Fetch recent cert.
// Prio:
// 1. fetch from cluster
// 2. fetch from url
// 3. fetch from file system
func (s *SealingRuleSet) GetRecentCert() (cert []byte, err error) {
	if (s.CertSource.Kubernetes != KubernetesCertSource{}) {
		r, err := openCertFromCluster(s.CertSource.Kubernetes)
		if err != nil {
			return cert, err
		}
		cert, err := ioutil.ReadAll(r)
		return cert, err
	} else if s.CertSource.Url != "" {
		r, err := openRemoteCert(s.CertSource.Url)
		if err != nil {
			return cert, err
		}
		cert, err := ioutil.ReadAll(r)
		return cert, err
	} else if s.CertSource.Path != "" {
		r, err := openLocalCert(s.CertSource.Path)
		if err != nil {
			return cert, err
		}
		cert, err := ioutil.ReadAll(r)
		return cert, err
	}
	err = errors.New("no cert provider like `path`, `url`, or `kubernetes` was specified")
	return cert, err
}

func openLocalCert(filename string) (io.ReadCloser, error) {
	log.Print("[DEBUG] Fetch cert from file system")
	return os.Open(filename)
}

func openRemoteCert(uri string) (io.ReadCloser, error) {
	log.Print("[DEBUG] Fetch cert from url")
	resp, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cannot fetch %q: %s", uri, resp.Status)
	}
	return resp.Body, nil
}

func openCertFromCluster(kubernetes KubernetesCertSource) (io.ReadCloser, error) {
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
