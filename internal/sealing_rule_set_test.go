package internal

import (
	"reflect"
	"testing"
)

func TestGetSource(t *testing.T) {
	c := &Cert{
		Sources: &Sources{
			Path: "Path",
		},
	}
	src, _ := c.getSource()
	srcKey := reflect.ValueOf(src).String()

	if srcKey != "Path" {
		t.Errorf("Priority was incorrect, got: \n%s\n, want: \n%s\n.", srcKey, "Path")
	}
}

func TestNoSources(t *testing.T) {
	c := &Cert{}
	_, err := c.getSource()

	if err == nil {
		t.Error("Expected an error but got non")
	}
}
