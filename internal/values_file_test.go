package internal

import (
	"fmt"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

var untransformedData = []byte(`env:
    username: john
    password: secret
#asdasd
env2:
    filters_password:
      - test4
      - test3
      - model: test
    password: secret
    pin: 1234
    threads: 1
    alpha: test!
env3: test
`)

var transformedData = []byte(`env:
    username: ENC:john
    password: ENC:secret
#asdasd
env2:
    filters_password:
      - ENC:test4
      - ENC:test3
      - model: ENC:test
    password: ENC:secret
    pin: ENC:1234
    threads: ENC:1
    alpha: ENC:test!
env3: ENC:test
`)

var transformedDataWithSealit = []byte(`env:
    username: ENC:john
    password: ENC:secret
#asdasd
sealit:
    name: mysecret
    namespace: default
    sealedAt: "2020-05-03T23:37:44+02:00"
    cert: |
      -----BEGIN CERTIFICATE-----
      MIIErTCCApWgAwIBAgIQMHGob1Phf42JplkkNYqZqDANBgkqhkiG9w0BAQsFADAA
      MB4XDTIwMDUwMzEzMzEzNFoXDTMwMDUwMTEzMzEzNFowADCCAiIwDQYJKoZIhvcN
      AQEBBQADggIPADCCAgoCggIBAMPwgiIxjYwkTm72FMSurQcdZORaekky1aOnXIFS
      xUDGvqHeADfzINhJkJOpqcXesHs1SvbXmLA9IqcwLw0gxSAF8Al11PaxHil3NNe5
      uy8z6HPBeXn6Rfibn0/gwbhI0Kbob+enyTyap2tg5PfOVe+riaMdIY7MMUOwDV99
      Ic+W34zh9uYPuBulUIx/4HOqn3JuudUsziYy+Hp5Od4MU4SL7O3kaF31Rj6bRd15
      r/HK/kGBMWotydAz1Btyr+oD13alnC5fk5erm/FuXXvat/2b8bvQ/tGiud8Yb+zl
      rnvcQYARKVNLSXt0ZTuV5rG5XC8xJU398kZ3sLMnmVoONnS7id9kqfvm+baCEwfx
      +TfaBzMJf0s6C9S+JMNO50u0xLRdmnR2CxYTt2UUTcDNNUkGy1PjUf4uK8+iT6Z3
      /TzYNoOiz7jWhsaO5dFDugU8AFu+3tEFro4Mu73Qqij2qL7DW9UzvnCKHSHCouEC
      2QW9ZwBAW0kg7wfcwZyJOTiK8YMh3bTLwqYTKWmrjj9Fb+d8X/AMk+/Z5x9/P/f6
      z9vRgHRB8dzBtkISCsXVpLKQGAKsyBOvZFpLTHrtzYqlF8Qtn1KRiI1bVxBohiJR
      eihSVIM5Qk7HGdSxOh03NuTCHeXfXXyy5aV1YoTmoDM7US9XD/wqoto053pbyAAB
      SAmpAgMBAAGjIzAhMA4GA1UdDwEB/wQEAwIAATAPBgNVHRMBAf8EBTADAQH/MA0G
      CSqGSIb3DQEBCwUAA4ICAQAmFSalLWqfsUPRiaejvmKvW43P6AeSL338IxyYsC/M
      S+bFNskONObL6LMmks3zrowKvZRCf+ZQgxyZH2GBcrxboc2A8fHlhf2TGC5NmluS
      66y+ZvzTJ4ti/Ai3mJMx2jvnIB0pXcWMaj/6beI26jXPY2jNf+Yg6VSqzLANhvEl
      kM9OYfSmJubm+2yWpgmprHpsJSq+G7PZnHZjD3IQZaYje5ynYhRi6BEhnE3bfDbB
      z2v56f5mVYMU/3TnV1F3zQirRZvk0M5DUXPxg2KAdeU1ptmCFcTVBOXD/dCJ57te
      AcXsB2fMCMqg7e2BTQq4Pw5etc3ZVCtsx5c1JuusSjMaYmSvN11MEL+vg21X2qnp
      mcyK7pIJWE8Oyh//RJP3ZhLO7OWU0ou6zCdUuv0AvlzOqDWG7UpfUUJQPkZ9d0XA
      Oh5sQhD+kozsstzcfd+BZG9nH4FZ54C8a0eB6l0RhGHe6OJNix+Yb8fBgMcGOXUR
      iAqqn0uCELD45lBI7BtYn7tsuy1HEYj4xIptIaZZOYOa8fXgDai7H19jp60yWOkx
      JZ7g4eY3uKcwc1V8R7EK0GHGth5opiPvf4HJFLhL+vpf7vgzlPvvTDBoAeXWMUZF
      EJlxWQG/yjFs9ayMWRMPsg0GpwsqYd+aAlYumvyrE9vSZVuwc3mw6wa9kc6TlAi5
      AA==
      -----END CERTIFICATE-----
`)

func TestImportExport(t *testing.T) {
	f := NewValueFile(untransformedData)

	d := f.Export()

	if !reflect.DeepEqual(d, untransformedData) {
		t.Errorf("Sealed yaml was incorrect, got: \n%s\n, want: \n%s\n.", d, untransformedData)
	}
}

func TestTransformingOfValues(t *testing.T) {
	f := NewValueFile(untransformedData)

	f.ApplyFuncToValues(func(key *yaml.Node, value *yaml.Node) {
		value.SetString(fmt.Sprintf("ENC:%s", value.Value))
	})

	d := f.Export()

	if !reflect.DeepEqual(d, transformedData) {
		t.Errorf("Sealed yaml was incorrect, got: \n%s\n, want: \n%s\n.", d, transformedData)
	}
}

func TestUpdateMetaOnNewFile(t *testing.T) {
	// f := NewValueFile(tr{})

	// f.UpdateMetadata(&Metadata{
	// 	Name: "Daniel",
	// })

	// ex := f.Export()

	// ioutil.WriteFile("test.yaml", ex, 0644)

	//t.Logf("%v")
	// if !reflect.DeepEqual(d, transformedData) {
	// 	t.Errorf("Sealed yaml was incorrect, got: \n%s\n, want: \n%s\n.", d, transformedData)
	// }
}

func TestUpdateMeta(t *testing.T) {
	// f := NewValueFile(transformedDataWithSealit)

	// f.UpdateMetadata(&Metadata{
	// 	Name: "Daniel",
	// })

	// ex := f.Export()

	// ioutil.WriteFile("test.yaml", ex, 0644)

	//t.Logf("%v")
	// if !reflect.DeepEqual(d, transformedData) {
	// 	t.Errorf("Sealed yaml was incorrect, got: \n%s\n, want: \n%s\n.", d, transformedData)
	// }
}

// func TestLoadSealitData(t *testing.T) {
// 	f := NewValueFile(transformedDataWithSealit)

// 	if f.Sealit.Name != "mysecret" {
// 		t.Errorf("Name was incorrect, got: \n%s\n, want: \n%s\n.", f.Sealit.Name, "mysecret")
// 	}

// 	if f.Sealit.Namespace != "default" {
// 		t.Errorf("Namespace was incorrect, got: \n%s\n, want: \n%s\n.", f.Sealit.Namespace, "default")
// 	}

// 	if f.Sealit.SealedAt != "2020-05-03T23:37:44+02:00" {
// 		t.Errorf("SealedAt date was incorrect, got: \n%s\n, want: \n%s\n.", f.Sealit.SealedAt, "2020-05-03T23:37:44+02:00")
// 	}

// 	if !reflect.DeepEqual(f.Sealit.Cert, []byte("")) {
// 		t.Error("Cert was not set.")
// 	}
// }
