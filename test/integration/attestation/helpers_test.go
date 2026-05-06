//go:build integration
// +build integration

/*
Copyright 2025 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package attestation_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	jose "gopkg.in/go-jose/go-jose.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	attestationv1alpha1 "k8s.io/kubernetes/staging/src/k8s.io/api/attestation/v1alpha1"
)

// generateTestEnrollment builds a NodeIdentityEnrollment for the given node
// name using the provided PEM-encoded public key.
func generateTestEnrollment(nodeName, pubKeyPEM string) *attestationv1alpha1.NodeIdentityEnrollment {
	expiry := metav1.NewTime(time.Now().Add(30 * time.Minute))
	return &attestationv1alpha1.NodeIdentityEnrollment{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "attestation.kubernetes.io/v1alpha1",
			Kind:       "NodeIdentityEnrollment",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: nodeName,
		},
		Spec: attestationv1alpha1.NodeIdentityEnrollmentSpec{
			AttestationMode:    attestationv1alpha1.AttestationModeSoftware,
			ProvisioningSource: "integration-test",
			SoftwareIdentity: &attestationv1alpha1.SoftwareIdentitySpec{
				PublicKey: pubKeyPEM,
			},
			BootstrapExpiry: &expiry,
		},
	}
}

// measurementsHash returns the hex-encoded SHA-256 of the canonical JSON
// encoding of m.  Self-contained — does not import the main verifier code.
func measurementsHash(m attestationv1alpha1.NodeMeasurements) string {
	data, err := json.Marshal(m)
	if err != nil {
		// Should not happen with a well-formed struct.
		panic(fmt.Sprintf("measurementsHash: json.Marshal: %v", err))
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// signTestPayload creates a compact JWS signed with priv containing the
// standard attestation claims.
func signTestPayload(t *testing.T, priv *ecdsa.PrivateKey, nodeName, nonce, measHash string) string {
	t.Helper()

	claims := map[string]interface{}{
		"iss":               "kubernetes.io/node-identity/v1alpha1",
		"sub":               "system:node:" + nodeName,
		"iat":               time.Now().Unix(),
		"exp":               time.Now().Add(5 * time.Minute).Unix(),
		"nonce":             nonce,
		"measurements_hash": measHash,
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("signTestPayload: json.Marshal: %v", err)
	}

	sig, err := jose.NewSigner(
		jose.NewSigningKey(jose.ES256, priv),
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("signTestPayload: NewSigner: %v", err)
	}

	jws, err := sig.Sign(payload)
	if err != nil {
		t.Fatalf("signTestPayload: Sign: %v", err)
	}

	compact, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("signTestPayload: CompactSerialize: %v", err)
	}
	return compact
}

// publicKeyPEM marshals the public portion of priv to PKIX PEM format.
func publicKeyPEM(t *testing.T, priv *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("publicKeyPEM: MarshalPKIXPublicKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// pemCSR generates a minimal PEM-encoded PKCS#10 certificate request for the
// given commonName.  Used in tests that need a syntactically valid CSR (e.g.
// the AttestationRef round-trip test) but do not care about the key material.
func pemCSR(t *testing.T, commonName string) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("pemCSR: GenerateKey: %v", err)
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"system:nodes"},
		},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		t.Fatalf("pemCSR: CreateCertificateRequest: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}
