# Helm sealit example

This is a example setup based on the `sample-chart`. 
In case you use an chart from a registry you can omit the chart related folder.
But as you need to overwrite the charts `values.yaml` you would need to create a new file with the properties for overwriting the exiting values.
In this example we have two files, for each environment one.
Beside that we have a `.sealit.yaml` which contains the configuration.

The environment variables will be mapped to a ConfigMap and a SealSecrets resource.

## Dev

`helm update -i sample ./sample-chart -f values.dev.yaml`

## Prod

`helm update -i sample ./sample-chart -f values.prod.yaml`