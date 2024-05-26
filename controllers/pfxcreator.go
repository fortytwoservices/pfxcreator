package controllers

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"software.sslmate.com/src/go-pkcs12"
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

	// Check if tls.pfx already exists
	if _, exists := secret.Data["tls.pfx"]; exists {
		log.Info("Secret already contains 'tls.pfx', skipping processing")
		return ctrl.Result{}, nil
	}

	if combinedPEM, ok := secret.Data["tls-combined.pem"]; !ok {
		log.Info("Secret does not contain 'tls-combined.pem'")
		return ctrl.Result{}, nil
	} else {
		log.Info("Found 'tls-combined.pem'")

		cert, key, err := decodePEM(combinedPEM)
		if err != nil {
			log.Error(err, "Failed to decode PEM or parse components")
			return ctrl.Result{}, err
		}
		log.Info("PEM decoded, and components parsed successfully")

		pfxData, err := pkcs12.Encode(rand.Reader, key, cert, nil, "")
		if err != nil {
			log.Error(err, "Failed to create PKCS#12 file")
			return ctrl.Result{}, err
		}
		log.Info("PKCS#12 file created successfully")

		pfxDataBase64 := base64.StdEncoding.EncodeToString(pfxData)
		log.Info("Encoded PKCS#12 data to base64 successfully")

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

func decodePEM(combinedPEM []byte) (*x509.Certificate, interface{}, error) {
	var cert *x509.Certificate
	var key interface{}
	for {
		block, rest := pem.Decode(combinedPEM)
		if block == nil {
			return nil, nil, fmt.Errorf("failed to parse PEM block")
		}
		switch block.Type {
		case "CERTIFICATE":
			cert, _ = x509.ParseCertificate(block.Bytes)
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
	if cert == nil || key == nil {
		return nil, nil, fmt.Errorf("certificate or key missing in PEM")
	}
	return cert, key, nil
}
