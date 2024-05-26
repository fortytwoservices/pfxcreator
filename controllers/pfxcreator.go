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

    // Fetch the Secret instance
    secret := &corev1.Secret{}
    err := r.Get(ctx, req.NamespacedName, secret)
    if err != nil {
        log.Error(err, "unable to fetch Secret")
        return ctrl.Result{}, client.IgnoreNotFound(err)
    }

    // Check for the tls-combined.pem in the secret and decode it from Base64
    combinedPEMBase64, ok := secret.Data["tls-combined.pem"]
    if !ok {
        log.Info("Secret does not contain 'tls-combined.pem'")
        return ctrl.Result{}, nil
    }

    combinedPEM, err := base64.StdEncoding.DecodeString(string(combinedPEMBase64))
    if err != nil {
        log.Error(err, "Failed to decode base64 content of 'tls-combined.pem'")
        return ctrl.Result{}, err
    }

    // Decode and parse the PEM file to get the certificate and private key
    cert, key, err := decodePEM(combinedPEM)
    if err != nil {
        log.Error(err, "failed to decode PEM or parse components")
        return ctrl.Result{}, err
    }

    // Generate the PKCS#12 file without a password
    pfxData, err := pkcs12.Encode(rand.Reader, key, cert, nil, "")
    if err != nil {
        log.Error(err, "Failed to create PKCS#12 file")
        return ctrl.Result{}, err
    }

    // Update the secret with the new tls.pfx key
    if secret.Data == nil {
        secret.Data = make(map[string][]byte)
    }
    secret.Data["tls.pfx"] = pfxData

    err = r.Update(ctx, secret)
    if err != nil {
        log.Error(err, "Failed to update Secret with tls.pfx")
        return ctrl.Result{}, err
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