# sealit

> __Heads Ups__ sealit is still in development and some features are missing.

Opinionated CLI tool for Bitnami's `"Sealed Secrets" for Kubernetes`.
`sealit` is used for GitOps based on `Sealed Secrets` and `Helm`.
The [`example`](example) demonstrates how everything plays together.

## Getting started

1. Download `sealit` from github and build the application
2. Install sealed secrets via `helm` on your K8s cluster https://github.com/helm/charts/tree/master/stable/sealed-secrets
    `helm upgrade -i --namespace kube-system sealit stable/sealed-secrets`
3. Create a `.sealit.yaml` file next to the environment specific values.yaml of your helm charts

## Commands

### `sealit init`

### `sealit seal`

### `sealit verify`

### `sealit unseal`

> To be implemented

### `sealit cert`

> To be implemented

## Configuration

### Prevent committing not encrypted files to git

Create a `pre-commit` hook in git which runs `sealit verify`.

> The tool is inspired by `sops` and `sealed secrets`.

## TODO:

- Add verbose mode
- Create resealing code ..
- Add docs
- Release beta