package bootstrap

// attestation_bootstrap.go extends the TLS bootstrap flow to perform node attestation
// when a node identity key is present on disk.
//
// The integration point is requestNodeCertificateWithAttestation, which wraps
// requestNodeCertificate. Call sites in bootstrap.go are updated to call this
// wrapper when attestation config is available.

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509/pkix"
	"fmt"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/certificate/csr"
	keyutil "k8s.io/client-go/util/keyutil"
	"k8s.io/klog/v2"

	clientset "k8s.io/client-go/kubernetes"
)

// requestNodeCertificateWithAttestation runs the full attested bootstrap flow:
//  1. Attempt attestation (collect measurements, request challenge, sign, submit document)
//  2. If the identity key is absent, fall back to the legacy token path
//  3. Build and submit a CSR with AttestationRef pointing to the document
//
// cfg may be nil, in which case this is equivalent to requestNodeCertificate.
func requestNodeCertificateWithAttestation(
	ctx context.Context,
	client clientset.Interface,
	privateKeyData []byte,
	nodeName types.NodeName,
	cfg *AttestationConfig,
) (certData []byte, err error) {
	var attestationRef string

	if cfg != nil {
		result, err := PerformAttestation(ctx, client, *cfg)
		if err != nil {
			return nil, fmt.Errorf("attestation: %w", err)
		}
		if result != nil {
			attestationRef = result.DocumentName
			klog.V(2).Infof("attestation: document %s ready; embedding AttestationRef in CSR", attestationRef)
		}
	}

	subject := &pkix.Name{
		Organization: []string{"system:nodes"},
		CommonName:   "system:node:" + string(nodeName),
	}

	privateKey, err := keyutil.ParsePrivateKeyPEM(privateKeyData)
	if err != nil {
		return nil, fmt.Errorf("invalid private key for certificate request: %v", err)
	}
	csrData, err := certutil.MakeCSR(privateKey, subject, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to generate certificate request: %v", err)
	}

	usages := []certificatesv1.KeyUsage{
		certificatesv1.UsageDigitalSignature,
		certificatesv1.UsageClientAuth,
	}
	if _, ok := privateKey.(*rsa.PrivateKey); ok {
		usages = append(usages, certificatesv1.UsageKeyEncipherment)
	}

	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}

	name, err := digestedName(signer.Public(), subject, usages)
	if err != nil {
		return nil, err
	}

	// Choose the signer name: attested CSRs use a distinct signer name so that
	// policy can distinguish attested from token-only bootstraps.
	signerName := certificatesv1.KubeAPIServerClientKubeletSignerName
	if attestationRef != "" {
		signerName = "kubernetes.io/kube-apiserver-client-kubelet-attested"
	}

	// Build the CSR object with the AttestationRef field set.
	reqName, reqUID, err := requestCertificateWithRef(
		ctx, client, csrData, name, signerName, attestationRef, usages, privateKey,
	)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, 3600*time.Second)
	defer cancel()

	klog.FromContext(ctx).V(2).Info("Waiting for client certificate to be issued")
	return csr.WaitForCertificate(ctx, client, reqName, types.UID(reqUID))
}

// requestCertificateWithRef submits a CertificateSigningRequest with the given
// attestationRef. When attestationRef is empty the behaviour is identical to
// csr.RequestCertificate.
func requestCertificateWithRef(
	ctx context.Context,
	client clientset.Interface,
	csrData []byte,
	name, signerName, attestationRef string,
	usages []certificatesv1.KeyUsage,
	privateKey interface{},
) (reqName, reqUID string, err error) {
	csr := &certificatesv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request:    csrData,
			SignerName: signerName,
			Usages:     usages,
		},
	}
	if attestationRef != "" {
		csr.Spec.AttestationRef = attestationRef
	}

	created, err := client.CertificatesV1().CertificateSigningRequests().Create(ctx, csr, metav1.CreateOptions{})
	if err != nil {
		return "", "", fmt.Errorf("create CSR: %w", err)
	}
	return created.Name, string(created.UID), nil
}

