package internal

import (
	"errors"
	"log"

	ssv1alpha1 "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
	"gopkg.in/yaml.v3"
)

const sealitYamlKey = "sealit"

type File struct {
	values   *yaml.Node
	Metadata *Metadata `yaml:"sealit,omitempty"`
}

type Metadata struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
	SealedAt  string `yaml:"sealedAt"`
	Cert      string `yaml:"cert"`
}

func NewValueFile(d []byte) (*File, error) {
	log.Print("[DEBUG] Unmarshal file and prepare yaml nodes")
	var f File

	if err := yaml.Unmarshal(d, &f); err != nil {
		return nil, err
	}

	if f.Metadata == nil {
		f.Metadata = &Metadata{}
	}

	var n yaml.Node

	if err := yaml.Unmarshal(d, &n); err != nil {
		return nil, err
	}

	f.values = &n

	if len(f.values.Content) > 1 {
		return nil, errors.New("sealing yaml files with more then one document is not supported")
	}

	return &f, nil
}

func (f *File) ApplyFuncToValues(manipulator func(*yaml.Node, *yaml.Node) error) error {
	log.Printf("[DEBUG] Apply manipulation function to values tree")
	return walkAndApplyFunc(f.values.Content[0], manipulator)
}

func walkAndApplyFunc(node *yaml.Node, manipulator func(*yaml.Node, *yaml.Node) error) (err error) {
	for i := 0; i < len(node.Content); i = i + 2 {
		key := node.Content[i]
		value := node.Content[i+1]
		// Only walk through non sealit elements
		if key.Value != sealitYamlKey {
			if value.Kind == yaml.ScalarNode {
				if err := manipulator(key, value); err != nil {
					return err
				}
			} else if value.Kind == yaml.SequenceNode {
				for _, childNode := range value.Content {
					if childNode.Kind == yaml.ScalarNode {
						if err := manipulator(key, childNode); err != nil {
							return err
						}
					} else {
						if err := walkAndApplyFunc(childNode, manipulator); err != nil {
							return err
						}
					}
				}
			} else {
				if err := walkAndApplyFunc(value, manipulator); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (f *File) Export() ([]byte, error) {
	if err := f.updateMetadata(); err != nil {
		return nil, err
	}

	return yaml.Marshal(f.values)
}

// Update MetaData
func (f *File) updateMetadata() (err error) {
	log.Printf("[DEBUG] Write back metadata into yaml tree")
	// Search for sealit element an check if present
	for i := 0; i < len(f.values.Content[0].Content); i = i + 2 {
		if f.values.Content[0].Content[i].Value == sealitYamlKey {
			node, err := metadataToYamlNode(f.Metadata)

			if err == nil {
				// Replace sealit node
				f.values.Content[0].Content[i+1] = node.Content[0].Content[1]
			}

			return err
		}
	}

	// As no sealit element was found add it
	node, err := metadataToYamlNode(f.Metadata)

	if err == nil {
		// Append sealit node
		f.values.Content[0].Content = append(f.values.Content[0].Content, node.Content[0].Content...)
	}

	return err
}

func metadataToYamlNode(metadata *Metadata) (node yaml.Node, err error) {
	nodeData, err := yaml.Marshal(File{
		Metadata: metadata,
	})

	if err == nil {
		err = yaml.Unmarshal(nodeData, &node)
	}

	return node, err
}

func (m *Metadata) getLabel() []byte {
	if m.Name != "" && m.Namespace != "" {
		log.Printf("[DEBUG] Scope of secrets is limited to secert: `%s` and namespace: `%s`", m.Name, m.Namespace)
		return ssv1alpha1.EncryptionLabel(m.Namespace, m.Name, ssv1alpha1.StrictScope)
	} else if m.Name == "" && m.Namespace != "" {
		log.Printf("[DEBUG] Scope of secrets is limited to namespace: `%s`", m.Namespace)
		return ssv1alpha1.EncryptionLabel(m.Namespace, m.Name, ssv1alpha1.NamespaceWideScope)
	} else {
		log.Print("[DEBUG] Scope of secrets is not limited")
		return ssv1alpha1.EncryptionLabel(m.Namespace, m.Name, ssv1alpha1.ClusterWideScope)
	}
}
