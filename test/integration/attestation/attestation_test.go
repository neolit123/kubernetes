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

// Package attestation_test contains integration tests for the software
// attestation path.  Tests cover the full API-layer round-trip: enrollment
// creation, challenge issuance and nonce population, document submission,
// CSR AttestationRef field, and rejection behaviour at the API layer for
// documents with invalid JWS signatures.
//
// Tests start a real kube-apiserver (no kubeadm required) using the shared
// etcd instance provided by test/integration/framework.
//
// Full verifier logic (signature checking, nonce matching, measurements
// hashing) is unit-tested in
// pkg/controller/certificates/approver/attestation_verifier_test.go.
package attestation_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	certv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic"
	clientset "k8s.io/client-go/kubernetes"

	kubeapiservertesting "k8s.io/kubernetes/cmd/kube-apiserver/app/testing"
	"k8s.io/kubernetes/test/integration/framework"
	attestationv1alpha1 "k8s.io/kubernetes/staging/src/k8s.io/api/attestation/v1alpha1"
)

// GroupVersionResources for the attestation API group.
var (
	enrollmentGVR = schema.GroupVersionResource{
		Group:    "attestation.kubernetes.io",
		Version:  "v1alpha1",
		Resource: "nodeidentityenrollments",
	}
	challengeGVR = schema.GroupVersionResource{
		Group:    "attestation.kubernetes.io",
		Version:  "v1alpha1",
		Resource: "nodeattestationchallenges",
	}
	documentGVR = schema.GroupVersionResource{
		Group:    "attestation.kubernetes.io",
		Version:  "v1alpha1",
		Resource: "nodeattestationdocuments",
	}
)

// TestMain runs all integration tests with the shared etcd instance.
func TestMain(m *testing.M) {
	framework.EtcdMain(m.Run)
}

// startServer starts a kube-apiserver with the NodeAttestation feature gate
// and runtime-config enabled, returning a dynamic client, a standard
// clientset, and a teardown function.
func startServer(t *testing.T) (dynamic.Interface, clientset.Interface, func()) {
	t.Helper()
	s := kubeapiservertesting.StartTestServerOrDie(t, nil, []string{
		"--feature-gates=NodeAttestation=true",
		"--runtime-config=attestation.kubernetes.io/v1alpha1=true",
	}, framework.SharedEtcd())

	dynClient, err := dynamic.NewForConfig(s.ClientConfig)
	if err != nil {
		s.TearDownFn()
		t.Fatalf("dynamic.NewForConfig: %v", err)
	}
	client, err := clientset.NewForConfig(s.ClientConfig)
	if err != nil {
		s.TearDownFn()
		t.Fatalf("clientset.NewForConfig: %v", err)
	}
	return dynClient, client, s.TearDownFn
}

// toUnstructured converts any JSON-serialisable object to an
// *unstructured.Unstructured suitable for the dynamic client.
func toUnstructured(t *testing.T, obj interface{}) *unstructured.Unstructured {
	t.Helper()
	data, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("toUnstructured: json.Marshal: %v", err)
	}
	u := &unstructured.Unstructured{}
	if err := json.Unmarshal(data, u); err != nil {
		t.Fatalf("toUnstructured: json.Unmarshal: %v", err)
	}
	return u
}

// waitForNonce polls the challenge until Status.Nonce is non-empty and
// returns the nonce.
func waitForNonce(t *testing.T, ctx context.Context, dynClient dynamic.Interface, name string) string {
	t.Helper()
	var nonce string
	err := wait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 15*time.Second, true, func(ctx context.Context) (bool, error) {
		got, err := dynClient.Resource(challengeGVR).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		nonce, _, _ = unstructured.NestedString(got.Object, "status", "nonce")
		return nonce != "", nil
	})
	if err != nil {
		t.Fatalf("waitForNonce: challenge %q: %v", name, err)
	}
	return nonce
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestEnrollmentCreateAndRead verifies that a NodeIdentityEnrollment with
// software attestation mode can be created and all spec fields round-trip.
func TestEnrollmentCreateAndRead(t *testing.T) {
	ctx := context.Background()
	dynClient, _, teardown := startServer(t)
	defer teardown()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubPEM := publicKeyPEM(t, priv)

	enr := generateTestEnrollment("test-node-enroll", pubPEM)
	created, err := dynClient.Resource(enrollmentGVR).Create(ctx, toUnstructured(t, enr), metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Create NodeIdentityEnrollment: %v", err)
	}

	got, err := dynClient.Resource(enrollmentGVR).Get(ctx, created.GetName(), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get NodeIdentityEnrollment: %v", err)
	}

	mode, _, _ := unstructured.NestedString(got.Object, "spec", "attestationMode")
	if mode != string(attestationv1alpha1.AttestationModeSoftware) {
		t.Errorf("spec.attestationMode: got %q, want %q", mode, attestationv1alpha1.AttestationModeSoftware)
	}

	pubKeyGot, _, _ := unstructured.NestedString(got.Object, "spec", "softwareIdentity", "publicKey")
	if pubKeyGot != pubPEM {
		t.Errorf("spec.softwareIdentity.publicKey does not round-trip correctly")
	}

	src, _, _ := unstructured.NestedString(got.Object, "spec", "provisioningSource")
	if src != "integration-test" {
		t.Errorf("spec.provisioningSource: got %q, want %q", src, "integration-test")
	}
}

// TestChallengeNoncePopulated verifies that when a NodeAttestationChallenge is
// created the API server (or admission/strategy) populates Status.Nonce and
// Status.ExpiresAt.
func TestChallengeNoncePopulated(t *testing.T) {
	ctx := context.Background()
	dynClient, _, teardown := startServer(t)
	defer teardown()

	ch := &attestationv1alpha1.NodeAttestationChallenge{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "attestation.kubernetes.io/v1alpha1",
			Kind:       "NodeAttestationChallenge",
		},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "challenge-nonce-",
		},
		Spec: attestationv1alpha1.NodeAttestationChallengeSpec{
			NodeName: "test-node-challenge",
			TTL:      metav1.Duration{Duration: 5 * time.Minute},
		},
	}

	created, err := dynClient.Resource(challengeGVR).Create(ctx, toUnstructured(t, ch), metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Create NodeAttestationChallenge: %v", err)
	}

	nonce := waitForNonce(t, ctx, dynClient, created.GetName())
	t.Logf("Got nonce (len=%d): %s", len(nonce), nonce)

	// ExpiresAt should also be set.
	got, err := dynClient.Resource(challengeGVR).Get(ctx, created.GetName(), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get NodeAttestationChallenge: %v", err)
	}
	expiresAt, _, _ := unstructured.NestedString(got.Object, "status", "expiresAt")
	if expiresAt == "" {
		t.Errorf("status.expiresAt should be set after nonce is populated")
	}
}

// TestDocumentRoundTrip verifies the full software attestation path:
//  1. Create enrollment with a generated ECDSA key pair.
//  2. Create a challenge and retrieve its nonce from Status.
//  3. Create a NodeAttestationDocument with a valid JWS and correct
//     measurements_hash claim.
//  4. Verify the document can be read back with all spec fields intact.
func TestDocumentRoundTrip(t *testing.T) {
	ctx := context.Background()
	dynClient, _, teardown := startServer(t)
	defer teardown()

	const nodeName = "test-node-doc"

	// 1. Create enrollment.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubPEM := publicKeyPEM(t, priv)

	enr := generateTestEnrollment(nodeName, pubPEM)
	if _, err := dynClient.Resource(enrollmentGVR).Create(ctx, toUnstructured(t, enr), metav1.CreateOptions{}); err != nil {
		t.Fatalf("Create enrollment: %v", err)
	}

	// 2. Create challenge and wait for nonce.
	ch := &attestationv1alpha1.NodeAttestationChallenge{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "attestation.kubernetes.io/v1alpha1",
			Kind:       "NodeAttestationChallenge",
		},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("%s-", nodeName),
		},
		Spec: attestationv1alpha1.NodeAttestationChallengeSpec{
			NodeName: nodeName,
			TTL:      metav1.Duration{Duration: 5 * time.Minute},
		},
	}
	createdCh, err := dynClient.Resource(challengeGVR).Create(ctx, toUnstructured(t, ch), metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Create challenge: %v", err)
	}
	nonce := waitForNonce(t, ctx, dynClient, createdCh.GetName())

	// 3. Sign and submit document.
	measurements := attestationv1alpha1.NodeMeasurements{
		KubeletHash: "abc123deadbeef",
	}
	measHash := measurementsHash(measurements)
	jws := signTestPayload(t, priv, nodeName, nonce, measHash)

	doc := &attestationv1alpha1.NodeAttestationDocument{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "attestation.kubernetes.io/v1alpha1",
			Kind:       "NodeAttestationDocument",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-%s", nodeName, createdCh.GetName()),
		},
		Spec: attestationv1alpha1.NodeAttestationDocumentSpec{
			NodeName:        nodeName,
			ChallengeRef:    createdCh.GetName(),
			AttestationMode: attestationv1alpha1.AttestationModeSoftware,
			Measurements:    measurements,
			SignedPayload:   jws,
		},
	}

	createdDoc, err := dynClient.Resource(documentGVR).Create(ctx, toUnstructured(t, doc), metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Create NodeAttestationDocument: %v", err)
	}

	// 4. Read back and verify spec fields.
	gotDoc, err := dynClient.Resource(documentGVR).Get(ctx, createdDoc.GetName(), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get NodeAttestationDocument: %v", err)
	}

	gotNodeName, _, _ := unstructured.NestedString(gotDoc.Object, "spec", "nodeName")
	if gotNodeName != nodeName {
		t.Errorf("spec.nodeName: got %q, want %q", gotNodeName, nodeName)
	}

	gotMode, _, _ := unstructured.NestedString(gotDoc.Object, "spec", "attestationMode")
	if gotMode != string(attestationv1alpha1.AttestationModeSoftware) {
		t.Errorf("spec.attestationMode: got %q, want %q", gotMode, attestationv1alpha1.AttestationModeSoftware)
	}

	gotChallRef, _, _ := unstructured.NestedString(gotDoc.Object, "spec", "challengeRef")
	if gotChallRef != createdCh.GetName() {
		t.Errorf("spec.challengeRef: got %q, want %q", gotChallRef, createdCh.GetName())
	}

	gotPayload, _, _ := unstructured.NestedString(gotDoc.Object, "spec", "signedPayload")
	if gotPayload != jws {
		t.Errorf("spec.signedPayload does not round-trip")
	}
}

// TestDocumentInvalidSignatureAPIAccept verifies that a NodeAttestationDocument
// signed with the wrong key is accepted by the API layer (the API server does
// not verify signatures; that is the verifier controller's responsibility).
// The test also confirms the document can be read back and the status.phase
// is NOT "Verified" in the absence of a running verifier.
func TestDocumentInvalidSignatureAPIAccept(t *testing.T) {
	ctx := context.Background()
	dynClient, _, teardown := startServer(t)
	defer teardown()

	const nodeName = "test-node-badsig"

	// Enrollment key (correct).
	enrollmentPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	// A different key (wrong — used to sign the document).
	wrongPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey (wrong): %v", err)
	}

	pubPEM := publicKeyPEM(t, enrollmentPriv)
	enr := generateTestEnrollment(nodeName, pubPEM)
	if _, err := dynClient.Resource(enrollmentGVR).Create(ctx, toUnstructured(t, enr), metav1.CreateOptions{}); err != nil {
		t.Fatalf("Create enrollment: %v", err)
	}

	ch := &attestationv1alpha1.NodeAttestationChallenge{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "attestation.kubernetes.io/v1alpha1",
			Kind:       "NodeAttestationChallenge",
		},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("%s-", nodeName),
		},
		Spec: attestationv1alpha1.NodeAttestationChallengeSpec{
			NodeName: nodeName,
		},
	}
	createdCh, err := dynClient.Resource(challengeGVR).Create(ctx, toUnstructured(t, ch), metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Create challenge: %v", err)
	}

	measurements := attestationv1alpha1.NodeMeasurements{KubeletHash: "badhash"}
	measHash := measurementsHash(measurements)
	// Sign with the WRONG key — the verifier would reject this but the API layer should not.
	jws := signTestPayload(t, wrongPriv, nodeName, "fabricated-nonce", measHash)

	doc := &attestationv1alpha1.NodeAttestationDocument{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "attestation.kubernetes.io/v1alpha1",
			Kind:       "NodeAttestationDocument",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: fmt.Sprintf("%s-%s", nodeName, createdCh.GetName()),
		},
		Spec: attestationv1alpha1.NodeAttestationDocumentSpec{
			NodeName:        nodeName,
			ChallengeRef:    createdCh.GetName(),
			AttestationMode: attestationv1alpha1.AttestationModeSoftware,
			Measurements:    measurements,
			SignedPayload:   jws,
		},
	}

	// API layer must accept the document; the verifier runs out-of-band.
	createdDoc, err := dynClient.Resource(documentGVR).Create(ctx, toUnstructured(t, doc), metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Create document with wrong-key signature: API layer should accept it but got error: %v", err)
	}

	gotDoc, err := dynClient.Resource(documentGVR).Get(ctx, createdDoc.GetName(), metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get document: %v", err)
	}

	phase, _, _ := unstructured.NestedString(gotDoc.Object, "status", "phase")
	// Without a running verifier the phase should NOT be "Verified".
	if phase == string(attestationv1alpha1.AttestationPhaseVerified) {
		t.Errorf("status.phase should not be %q without a running verifier; document has invalid signature",
			attestationv1alpha1.AttestationPhaseVerified)
	}
	t.Logf("Document status.phase (no verifier running): %q", phase)
}

// TestCSRAttestationRefRoundTrip verifies that the AttestationRef field on a
// CertificateSigningRequest is persisted and retrieved unchanged.
func TestCSRAttestationRefRoundTrip(t *testing.T) {
	ctx := context.Background()
	_, client, teardown := startServer(t)
	defer teardown()

	const nodeName = "system:node:worker-1"
	const refName = "worker-1-doc-abc123"

	csr := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-csr-attestation-",
		},
		Spec: certv1.CertificateSigningRequestSpec{
			Request:        pemCSR(t, nodeName),
			SignerName:     certv1.KubeAPIServerClientKubeletSignerName,
			Usages:         []certv1.KeyUsage{certv1.UsageClientAuth},
			AttestationRef: refName,
		},
	}

	created, err := client.CertificatesV1().CertificateSigningRequests().Create(ctx, csr, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("Create CertificateSigningRequest: %v", err)
	}

	got, err := client.CertificatesV1().CertificateSigningRequests().Get(ctx, created.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get CertificateSigningRequest: %v", err)
	}

	if got.Spec.AttestationRef != refName {
		t.Errorf("Spec.AttestationRef: got %q, want %q", got.Spec.AttestationRef, refName)
	}
}
