# sealit

> __Heads Ups__ sealit is still in development and some features are missing.

`sealit` is a CLI which provides an opinionated way of doing GitOps based on Bitnami's _"Sealed Secrets" for Kubernetes_ and _Helm Charts_.
The [`example`](example) folder demonstrates how everything plays together.

## Getting started

1. Download or clone `sealit` from github and build the application
2. Install sealed secrets via `helm` on your K8s cluster https://github.com/helm/charts/tree/master/stable/sealed-secrets
    `helm upgrade -i --namespace kube-system sealit stable/sealed-secrets`
3. Run `sealit init` next to your environment specific values.yaml of your helm chart.

## Commands

### `sealit help`

`sealit help` shows an overview over all commands and flags.

### `sealit init`

`sealit init` creates a sample `.sealit.yaml` configuration file.

### `sealit seal`

`sealit seal` seals all files according to the rules defined in the `.sealit.yaml`.

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
            name: secret-controller
            namespace: sealed-secret-namespace
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
            name: secret-controller
            namespace: sealed-secret-namespace
        maxAge: 720h0m0s
```

## Prevent committing not encrypted files

Create a `pre-commit` hook in git which runs `sealit verify`.

## Limitations and scope

`sealit` is an alternative cli to `kubeseal` with is part of Bitnami's [_Sealed Secrets_](https://github.com/bitnami-labs/sealed-secrets).
Therefore `sealit` requires the _Sealed Secret_ controller already installed on the cluster, this can be done via the [helm chart](https://github.com/helm/charts/tree/master/stable/sealed-secrets).
The crypto part as well as the sealing principles are from _Sealed Secrets_.

## Development

### Run tests

### Build application

## Contribute

## Credits

Thanks to the awesome work of the people behind [SOPS](https://github.com/mozilla/sops) and [_Sealed Secrets_](https://github.com/bitnami-labs/sealed-secrets). 
`sealit` is heavily influenced by there ideas.

## License

`sealit` is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).