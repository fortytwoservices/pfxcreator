# PFX Creator

This operator takes the tls-combined.pem from a Cert-manager certificate and creates a passwordless PFX file for further use.

# Why?

Cert-manager currently only supports creating pkcs12/pfx files with password protection. This solves that.

In addition to that, external secrets push secrets only supports pushing passwordless pkcs12/pfx certificate files.

# Prerequisites

The Kubernetes secret created by your Cert-manager certificate generation must have the following label for the operator to reconcile it:

```pfxcreator: "true"```

# How to use

You need to use the ```additionalOutPutFormats``` with your cert-manager controller to output a tls-combined.pem key in your tls secrets after certificate generation.

The operator will parse the combined PEM in your tls secret, as long as it has the correct label and create a passwordless PFX for you. That PFX will be added as a separate key, ```tls.pfx``` in the existing secret.

The new key can be pushed to your certificate store using PushSecret and the External Secrets Operator.