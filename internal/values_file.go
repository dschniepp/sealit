package internal

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

type File struct {
	values *yaml.Node
	Sealit *Metadata `yaml:"sealit,omitempty"`
}

type Metadata struct {
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace"`
	SealedAt  string `yaml:"sealedAt"`
	Cert      string `yaml:"cert"`
}

func NewValueFile(d []byte) File {
	var f File

	if err := yaml.Unmarshal(d, &f); err != nil {
		fmt.Printf("error: %v", err)
	}

	var n yaml.Node

	if err := yaml.Unmarshal(d, &n); err != nil {
		fmt.Printf("error: %v", err)
	}

	f.values = &n

	if len(f.values.Content) > 1 {
		fmt.Print("error: sealing yaml files with more then one document is not supported")
	}

	return f
}

func (f *File) ApplyFuncToValues(manipulator func(*yaml.Node, *yaml.Node)) {
	walkAndApply(f.values.Content[0], manipulator)
}

func (f *File) Export() []byte {
	d, err := yaml.Marshal(f.values)

	if err != nil {
		fmt.Printf("error: %v", err)
	}

	return d
}

func walkAndApply(node *yaml.Node, manipulator func(*yaml.Node, *yaml.Node)) {
	for i := 0; i < len(node.Content); i = i + 2 {
		key := node.Content[i]
		value := node.Content[i+1]
		// Only walk through non sealit elements
		if key.Value != "sealit" {
			if value.Kind == yaml.ScalarNode {
				manipulator(key, value)
			} else if value.Kind == yaml.SequenceNode {
				for _, childNode := range value.Content {
					if childNode.Kind == yaml.ScalarNode {
						manipulator(key, childNode)
					} else {
						walkAndApply(childNode, manipulator)
					}
				}
			} else {
				walkAndApply(value, manipulator)
			}
		}
	}
}

// Update MetaData
func (f *File) updateMetadata(metadata *Metadata) {
	// Search for sealit element an check if present
	for i := 0; i < len(f.values.Content[0].Content); i = i + 2 {
		if f.values.Content[0].Content[i].Value == "sealit" {
			var node yaml.Node
			nodeData, _ := yaml.Marshal(File{
				Sealit: metadata,
			})
			yaml.Unmarshal(nodeData, &node)
			f.values.Content[0].Content[i+1] = node.Content[0].Content[1]
			return
		}
	}
	// If not add new placeholder element
	var node yaml.Node
	nodeData, _ := yaml.Marshal(File{
		Sealit: metadata,
	})
	yaml.Unmarshal(nodeData, &node)
	f.values.Content[0].Content = append(f.values.Content[0].Content, node.Content[0].Content...)
}
