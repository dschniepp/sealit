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
	Url        string                 `yaml:"url,omitempty"`
	Path       string                 `yaml:"path,omitempty"`
	Controller SealedSecretController `yaml:"controller,omitempty"`
	MaxAge     time.Duration          `yaml:"maxAge"`
}

type SealedSecretController struct {
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
	if (s.CertSource.Controller != SealedSecretController{}) {
		r, err := openCertFromCluster(s.CertSource.Controller)
		cert, err = ioutil.ReadAll(r)
		return cert, err
	} else if s.CertSource.Url != "" {
		r, err := openRemoteCert(s.CertSource.Url)
		cert, err := ioutil.ReadAll(r)
		return cert, err
	} else if s.CertSource.Path != "" {
		r, err := openLocalCert(s.CertSource.Path)
		cert, err := ioutil.ReadAll(r)
		return cert, err
	}
	err = errors.New("no cert provider like `path`, `url`, or `controller` was specified")
	return cert, err
}

func openLocalCert(filename string) (io.ReadCloser, error) {
	log.Print("[DEBUG] Fetch from file system")
	return os.Open(filename)
}

func openRemoteCert(uri string) (io.ReadCloser, error) {
	log.Print("[DEBUG] Fetch from url")
	resp, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cannot fetch %q: %s", uri, resp.Status)
	}
	return resp.Body, nil
}

func openCertFromCluster(controller SealedSecretController) (io.ReadCloser, error) {
	log.Print("[DEBUG] Fetch from within K8s sealed secret controller")
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.DefaultClientConfig = &clientcmd.DefaultClientConfig
	if kubeConfig != "" {
		loadingRules.ExplicitPath = kubeConfig
	}
	overrides := clientcmd.ConfigOverrides{}

	if controller.Context != "" {
		overrides.CurrentContext = controller.Context
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
		Services(controller.Namespace).
		ProxyGet("http", controller.Name, "", "/v1/cert.pem", nil).
		Stream()
	if err != nil {
		return nil, fmt.Errorf("cannot fetch certificate: %v", err)
	}

	return f, nil
}
