package controllers

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azcertificates"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

type SecretReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

func (r *SecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("secret", req.NamespacedName)

	secret := &corev1.Secret{}
	if err := r.Get(ctx, req.NamespacedName, secret); err != nil {
		log.Error(err, "Failed to fetch the Secret")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if _, ok := secret.Data["tls-combined.pem"]; !ok {
		log.Info("Secret does not contain 'tls-combined.pem'")
		return ctrl.Result{}, nil
	}

	log.Info("Found 'tls-combined.pem'")
	certs, key, err := decodePEM(secret.Data["tls-combined.pem"])
	if err != nil {
		log.Error(err, "Failed to decode PEM or parse components")
		return ctrl.Result{}, err
	}

	pfxFile, err := createPKCS12(certs, key)
	if err != nil {
		log.Error(err, "Failed to create PKCS#12 file")
		return ctrl.Result{}, err
	}
	defer os.Remove(pfxFile) // cleanup temp files
	vaultName := os.Getenv("KEY_VAULT_NAME") // get name from env variable KEY_VAULT_NAME
	if vaultName == "" {
		vaultName = "default-key-vault-name" // fallback to some value if not set
	}
	certName := fmt.Sprintf("%s-apim", req.NamespacedName.Name) // set secret name as cert name
	if err := uploadToAzureKeyVault(ctx, pfxFile, vaultName, certName); err != nil {
		log.Error(err, "Failed to upload certificate to Azure Key Vault")
		return ctrl.Result{}, err
	}

	log.Info("Certificate uploaded to Azure Key Vault successfully")
	return ctrl.Result{}, nil
}

func createPKCS12(certs []*x509.Certificate, key interface{}) (string, error) {
	keyFile, err := ioutil.TempFile("", "key-*.pem")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file for key: %w", err)
	}
	defer func() {
		keyFile.Close()
		os.Remove(keyFile.Name())
	}()

	certFile, err := ioutil.TempFile("", "cert-*.pem")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file for cert: %w", err)
	}
	defer func() {
		certFile.Close()
		os.Remove(certFile.Name())
	}()

	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("key is not of type *rsa.PrivateKey")
	}

	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}); err != nil {
		return "", fmt.Errorf("failed to write key to PEM: %w", err)
	}
	for _, cert := range certs {
		if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return "", fmt.Errorf("failed to write cert to PEM: %w", err)
		}
	}

	keyFile.Sync()
	certFile.Sync()

	outputFileName := certFile.Name() + ".pfx"
	cmd := exec.Command("openssl", "pkcs12", "-export", "-out", outputFileName, "-inkey", keyFile.Name(), "-in", certFile.Name(), "-passout", "pass:")
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("OpenSSL command failed: %w", err)
	}

	return outputFileName, nil
}

func uploadToAzureKeyVault(ctx context.Context, pfxFile, vaultName, certName string) error {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("failed to create credential: %v", err)
	}

	keyVaultURL := fmt.Sprintf("https://%s.vault.azure.net", vaultName) // build key vault uri

	client, err := azcertificates.NewClient(keyVaultURL, cred, nil)
	if err != nil {
		return fmt.Errorf("failed to create Key Vault client: %v", err)
	}

	pfxData, err := ioutil.ReadFile(pfxFile)
	if err != nil {
		return fmt.Errorf("failed to read PFX file: %v", err)
	}
	pfxBase64 := base64.StdEncoding.EncodeToString(pfxData)

	// Create the certificate
	params := azcertificates.ImportCertificateParameters{
		Base64EncodedCertificate: &pfxBase64,
	}

	_, err = client.ImportCertificate(ctx, certName, params, nil)
	if err != nil {
		return fmt.Errorf("failed to import certificate: %v", err)
	}

	return nil
}

func decodePEM(combinedPEM []byte) ([]*x509.Certificate, interface{}, error) {
	var certs []*x509.Certificate
	var key interface{}
	for {
		block, rest := pem.Decode(combinedPEM)
		if block == nil {
			return nil, nil, fmt.Errorf("failed to parse PEM block")
		}
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse certificate: %v", err)
			}
			certs = append(certs, cert)
		case "RSA PRIVATE KEY", "PRIVATE KEY":
			var err error
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to parse private key: %v", err)
				}
			}
		}
		combinedPEM = rest
		if len(rest) == 0 {
			break
		}
	}
	if len(certs) == 0 || key == nil {
		return nil, nil, fmt.Errorf("certificate or key missing in PEM")
	}
	return certs, key, nil
}

func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.Log = ctrl.Log.WithName("controllers").WithName("Secret")

	labelSelector := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return obj.GetLabels()["pfxcreator"] == "true"
	})

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		WithEventFilter(labelSelector).
		Complete(r)
}
