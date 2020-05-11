# sealit

> __Heads Ups__ __sealit__ is still in development and some features are missing.

__sealit__ is a CLI which provides an opinionated way of doing GitOps based on Bitnami's _"Sealed Secrets" for Kubernetes_ and _Helm Charts_.

## Getting started

1. Download the latest release from https://github.com/dschniepp/sealit/releases.
2. Install sealed secrets via `helm` on your K8s cluster https://github.com/helm/charts/tree/master/stable/sealed-secrets
3. Run `sealit init` next to your environment specific values.yaml of your helm chart
4. Change the configuration file `.sealit.yaml` according to your needs
5. Run `sealit seal` to encrypt all secrets. Review if your secrets are encrypted otherwise tweak your config file again.
6. Create a `SealedSecret` resource (`sealit template`) inside your Helm Chart and reference the secrets from the `values.yaml` similar to `{{ .Values.env.your_secret | trimPrefix "ENC:" }}`
7. Now you can securely commit your secrets and deploy your application based on your git repository, to Kubernetes

In the [`example`](example) folder you can find a working solution and structure for using _sealit_, _Sealed Secrets_ and _Helm Charts_.

## Commands

### `sealit help`

`sealit help` shows an overview over all commands and flags.

### `sealit init`

`sealit init` creates a sample `.sealit.yaml` configuration file.

### `sealit seal`

`sealit seal` seals all files according to the rules defined in the `.sealit.yaml`.

### `sealit template`

`sealit template` echos a SealedSecret Kubernetes resource, with parameter `file` the output will be saved at the referenced location.

### `sealit verify`

`sealit seal` verifies of all secrets in the respective files are sealed according to the rules defined in the `.sealit.yaml`.
This command can be used in the githooks, to prevent committing not encrypted files.

## Configuration

The default name of the configuration files is `.sealit.yaml`. 
The filename can be overwritten by setting the `--config` flag.
A sample configuration file can be created via `sealit init`.

```yaml
sealing_rules:
  - file_regex: \.dev\.yaml$ # Regex pattern for which files this rules are applied
    name: secret # Name of the future secret
    namespace: default # Namespace of the future secret
    encrypt_regex: (password|pin)$ # Regex of the key names which should be encrypted
    cert:
        url: https://example.org
        path: cert.pem
        controller:
            context: KubeContextName
            name: sealed-secrets
            namespace: kube-system
        maxAge: 720h0m0s
```

### Cert locations and age

The public cert can be fetched from different locations.
Independent from the way of fetching the cert the `maxAge` is provided.

#### Maximum cert age

`maxAge` is used to check the age of the cert based on the `Valid after` date.
In case the cert is older or the `--fetch-cert` flag is provided, a new cert is fetched.
Otherwise the cert from the meta field within the `values.yaml` file is used for the encryption.

#### Local cert file

```yaml
sealing_rules:
  - ...
    cert:
        ...
        path: "cert.pem"
        maxAge: 720h0m0s
```

#### Remote cert file

```yaml
sealing_rules:
  - ...
    cert:
        ...
        url: https://localhost:8080/cert.pem
        maxAge: 720h0m0s
```

#### Remote cert from Kubernetes

```yaml
sealing_rules:
  - ...
    cert:
        ...
        controller:
            context: KubeContextName
            name: sealed-secrets
            namespace: kube-system
        maxAge: 720h0m0s
```

## Prevent committing not encrypted files

Create a `pre-commit` hook in git which runs `sealit verify`.

## Limitations and scope

`sealit` is an alternative cli to `kubeseal` which is part of Bitnami's [_Sealed Secrets_](https://github.com/bitnami-labs/sealed-secrets).
Therefore __sealit__ requires the _Sealed Secret_ controller already installed on the cluster, this can be done via the [helm chart](https://github.com/helm/charts/tree/master/stable/sealed-secrets).
The crypto part as well as the sealing principles are from _Sealed Secrets_.

## Development

For development `git`, >= `go1.14`, `make`, access to a K8s cluster and `Helm` is required.

Clone the repository via `git clone https://github.com/dschniepp/sealit.git` to continue with one of the following steps.

### Run sealit

`make run`

### Run tests

`make test`

### Build application

Locally the application can be build via `make build` and will populate the binary to the `dist` folder.

Releases on GitHub are build and published via _goreleaser_ and a _GitHub Actions_.

## Contribute

Thank you for considering contributing to the __sealit__! Before contributing, please be sure to read the [Contribution Guide](CONTRIBUTING.md).

## Code of Conduct

In order to ensure that the community is welcoming to all, please review and abide by the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

If you discover a vulnerabilities within __sealit__, please send an e-mail to Daniel Schniepp via [d.schniepp@indale.com](mailto:d.schniepp@indale.com)

## Credits

Thanks to the awesome work of the people behind [_SOPS_](https://github.com/mozilla/sops) and [_Sealed Secrets_](https://github.com/bitnami-labs/sealed-secrets). 
__sealit__ is heavily influenced by there ideas.

## License

__sealit__ is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).