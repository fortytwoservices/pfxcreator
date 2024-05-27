package controllers

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// SecretReconciler reconciles a Secret object
type SecretReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

func (r *SecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("secret", req.NamespacedName)

	log.Info("Attempting to fetch the Secret")
	secret := &corev1.Secret{}
	err := r.Get(ctx, req.NamespacedName, secret)
	if err != nil {
		log.Error(err, "Failed to fetch the Secret")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	log.Info("Secret fetched successfully")

	if _, exists := secret.Data["tls.pfx"]; exists {
		log.Info("Secret already contains 'tls.pfx', skipping processing")
		return ctrl.Result{}, nil
	}

	if combinedPEM, ok := secret.Data["tls-combined.pem"]; !ok {
		log.Info("Secret does not contain 'tls-combined.pem'")
		return ctrl.Result{}, nil
	} else {
		log.Info("Found 'tls-combined.pem'")

		certs, key, err := decodePEM(combinedPEM)
		if err != nil {
			log.Error(err, "Failed to decode PEM or parse components")
			return ctrl.Result{}, err
		}
		log.Info("PEM decoded, and components parsed successfully")

		if err = createPKCS12(certs, key, "output.pfx"); err != nil {
			log.Error(err, "Failed to create PKCS#12 file using OpenSSL")
			return ctrl.Result{}, err
		}

		// Read and encode the PFX file
		pfxData, err := ioutil.ReadFile("output.pfx")
		if err != nil {
			log.Error(err, "Failed to read the PFX file")
			return ctrl.Result{}, err
		}
		pfxDataBase64 := base64.StdEncoding.EncodeToString(pfxData)

		if secret.Data == nil {
			secret.Data = make(map[string][]byte)
		}
		secret.Data["tls.pfx"] = []byte(pfxDataBase64)

		log.Info("Attempting to update the Secret with new tls.pfx")
		if err = r.Update(ctx, secret); err != nil {
			log.Error(err, "Failed to update Secret with tls.pfx")
			return ctrl.Result{}, err
		}
		log.Info("Secret updated successfully with new tls.pfx")
	}

	return ctrl.Result{}, nil
}

func createPKCS12(certs []*x509.Certificate, key interface{}, outputFileName string) error {
	// Write the key and certificates to temporary files
	keyFile, err := ioutil.TempFile("", "key-*.pem")
	if err != nil {
		return fmt.Errorf("failed to create temp file for key: %w", err)
	}
	defer os.Remove(keyFile.Name()) // Clean up file after return
	defer keyFile.Close()

	certFile, err := ioutil.TempFile("", "cert-*.pem")
	if err != nil {
		return fmt.Errorf("failed to create temp file for cert: %w", err)
	}
	defer os.Remove(certFile.Name()) // Clean up file after return
	defer certFile.Close()

	// Ensure the key file is written securely
	if err := keyFile.Chmod(0600); err != nil {
		return fmt.Errorf("failed to set key file permissions: %w", err)
	}

	privateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("key is not of type *rsa.PrivateKey")
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}); err != nil {
		return fmt.Errorf("failed to write key to PEM: %w", err)
	}

	// Encode all certificates in the chain to the cert file
	for _, cert := range certs {
		if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
			return fmt.Errorf("failed to write cert to PEM: %w", err)
		}
	}

	// Flush files to ensure all data is written
	if err := keyFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync key file: %w", err)
	}
	if err := certFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync cert file: %w", err)
	}

	// Generate PKCS#12 file using OpenSSL
	cmd := exec.Command("openssl", "pkcs12", "-export", "-out", outputFileName, "-inkey", keyFile.Name(), "-in", certFile.Name(), "-passout", "pass:")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("OpenSSL command failed: %w", err)
	}

	log.Println("PKCS#12 file created successfully:", outputFileName)
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


// SetupWithManager sets up the controller with the Manager.
func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
    r.Log = ctrl.Log.WithName("controllers").WithName("Secret")

    // Define label selector
    labelSelector := predicate.NewPredicateFuncs(func(obj client.Object) bool {
        return obj.GetLabels()["pfxcreator"] == "true"
    })

    return ctrl.NewControllerManagedBy(mgr).
        For(&corev1.Secret{}).
        WithEventFilter(labelSelector).
        Complete(r)
}