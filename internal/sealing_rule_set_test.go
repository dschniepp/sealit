package internal

import (
	"reflect"
	"testing"
)

func TestGetSource(t *testing.T) {
	cs := &CertSources{
		Path: "Path",
	}
	src, _ := cs.getCertSource()
	srcKey := reflect.ValueOf(src).String()

	if srcKey != "Path" {
		t.Errorf("Priority was incorrect, got: \n%s\n, want: \n%s\n.", srcKey, "Path")
	}
}

func TestNoSources(t *testing.T) {
	cs := &CertSources{}
	_, err := cs.getCertSource()

	if err == nil {
		t.Error("Expected an error but got non")
	}
}
