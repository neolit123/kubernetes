package approver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	jose "gopkg.in/go-jose/go-jose.v2"
	attestationv1alpha1 "k8s.io/api/attestation/v1alpha1"
)

// generateTestKeyPair generates an ECDSA P-256 key pair for testing.
func generateTestKeyPair(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return priv, string(pemBytes)
}

// signJWS creates a compact JWS signed with the given private key.
func signJWS(t *testing.T, priv *ecdsa.PrivateKey, claims jwsClaims) string {
	t.Helper()
	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	jws, err := sig.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize: %v", err)
	}
	return compact
}

func testMeasurementsHash(t *testing.T, m attestationv1alpha1.NodeMeasurements) string {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("json.Marshal measurements: %v", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestVerifyJWSAndExtractClaims_ValidSignature(t *testing.T) {
	priv, pubPEM := generateTestKeyPair(t)
	measurements := attestationv1alpha1.NodeMeasurements{KubeletHash: "abc123"}
	hash := testMeasurementsHash(t, measurements)

	claims := jwsClaims{
		Issuer:           "kubernetes.io/node-identity/v1alpha1",
		Subject:          "system:node:worker-1",
		IssuedAt:         time.Now().Unix(),
		ExpiresAt:        time.Now().Add(5 * time.Minute).Unix(),
		Nonce:            "dGVzdG5vbmNl",
		MeasurementsHash: hash,
	}
	jws := signJWS(t, priv, claims)

	got, err := verifyJWSAndExtractClaims(jws, pubPEM)
	if err != nil {
		t.Fatalf("verifyJWSAndExtractClaims: %v", err)
	}
	if got.Nonce != claims.Nonce {
		t.Errorf("nonce: got %q want %q", got.Nonce, claims.Nonce)
	}
	if got.MeasurementsHash != hash {
		t.Errorf("measurements_hash: got %q want %q", got.MeasurementsHash, hash)
	}
}

func TestVerifyJWSAndExtractClaims_WrongKey(t *testing.T) {
	priv, _ := generateTestKeyPair(t)
	_, otherPubPEM := generateTestKeyPair(t) // different key

	claims := jwsClaims{
		Issuer:    "kubernetes.io/node-identity/v1alpha1",
		Subject:   "system:node:worker-1",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		Nonce:     "dGVzdA==",
	}
	jws := signJWS(t, priv, claims)

	_, err := verifyJWSAndExtractClaims(jws, otherPubPEM)
	if err == nil {
		t.Fatal("expected error for wrong key, got nil")
	}
}

func TestVerifyJWSAndExtractClaims_Expired(t *testing.T) {
	priv, pubPEM := generateTestKeyPair(t)

	claims := jwsClaims{
		Issuer:    "kubernetes.io/node-identity/v1alpha1",
		Subject:   "system:node:worker-1",
		IssuedAt:  time.Now().Add(-10 * time.Minute).Unix(),
		ExpiresAt: time.Now().Add(-1 * time.Minute).Unix(), // expired
		Nonce:     "dGVzdA==",
	}
	jws := signJWS(t, priv, claims)

	_, err := verifyJWSAndExtractClaims(jws, pubPEM)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
}

func TestVerifyJWSAndExtractClaims_WrongIssuer(t *testing.T) {
	priv, pubPEM := generateTestKeyPair(t)

	claims := jwsClaims{
		Issuer:    "attacker.io/evil",
		Subject:   "system:node:worker-1",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		Nonce:     "dGVzdA==",
	}
	jws := signJWS(t, priv, claims)

	_, err := verifyJWSAndExtractClaims(jws, pubPEM)
	if err == nil {
		t.Fatal("expected error for wrong issuer, got nil")
	}
}

func TestMeasurementsHash_Deterministic(t *testing.T) {
	m := attestationv1alpha1.NodeMeasurements{
		KubeletHash:   "deadbeef",
		OSImageID:     "ami-12345",
		KernelVersion: "6.1.0",
	}

	h1, err := measurementsHash(m)
	if err != nil {
		t.Fatalf("measurementsHash: %v", err)
	}
	h2, err := measurementsHash(m)
	if err != nil {
		t.Fatalf("measurementsHash second call: %v", err)
	}
	if h1 != h2 {
		t.Errorf("measurementsHash is not deterministic: %q != %q", h1, h2)
	}
}

func TestMeasurementsHash_DistinctForDifferentMeasurements(t *testing.T) {
	m1 := attestationv1alpha1.NodeMeasurements{KubeletHash: "aaa"}
	m2 := attestationv1alpha1.NodeMeasurements{KubeletHash: "bbb"}

	h1, _ := measurementsHash(m1)
	h2, _ := measurementsHash(m2)
	if h1 == h2 {
		t.Error("different measurements produced the same hash")
	}
}

func TestVerifyMeasurements_Match(t *testing.T) {
	reported := attestationv1alpha1.NodeMeasurements{
		KubeletHash: "abc",
		OSImageID:   "ami-1",
	}
	expected := attestationv1alpha1.NodeMeasurements{
		KubeletHash: "abc",
		OSImageID:   "ami-1",
	}
	if err := verifyMeasurements(reported, expected, nil); err != nil {
		t.Errorf("expected match, got error: %v", err)
	}
}

func TestVerifyMeasurements_KubeletMismatch(t *testing.T) {
	reported := attestationv1alpha1.NodeMeasurements{KubeletHash: "aaa"}
	expected := attestationv1alpha1.NodeMeasurements{KubeletHash: "bbb"}
	if err := verifyMeasurements(reported, expected, nil); err == nil {
		t.Error("expected error for kubelet hash mismatch, got nil")
	}
}

func TestVerifyMeasurements_EmptyExpectedPassesAll(t *testing.T) {
	// Empty expected means "not set" — the outer caller decides policy, not this function.
	reported := attestationv1alpha1.NodeMeasurements{KubeletHash: "anything"}
	expected := attestationv1alpha1.NodeMeasurements{} // all empty
	if err := verifyMeasurements(reported, expected, nil); err != nil {
		t.Errorf("empty expected should pass all fields: %v", err)
	}
}

func TestVerifySLSAProvenance_AllowedPrefix(t *testing.T) {
	policy := &attestationv1alpha1.SoftwareAttestationPolicy{
		SLSAProvenanceAllowedPrefixes: []string{"oci://registry.example.com/"},
	}
	m := attestationv1alpha1.NodeMeasurements{
		SLSAProvenanceURI: "oci://registry.example.com/kubelet@sha256:abc123",
	}
	// Should not return an SSRF error (fetch not yet implemented, returns nil).
	if err := verifySLSAProvenance(nil, m, policy); err != nil {
		t.Errorf("allowed prefix should not error: %v", err)
	}
}

func TestVerifySLSAProvenance_BlockedPrefix(t *testing.T) {
	policy := &attestationv1alpha1.SoftwareAttestationPolicy{
		SLSAProvenanceAllowedPrefixes: []string{"oci://registry.example.com/"},
	}
	m := attestationv1alpha1.NodeMeasurements{
		SLSAProvenanceURI: "http://169.254.169.254/latest/meta-data/",
	}
	if err := verifySLSAProvenance(nil, m, policy); err == nil {
		t.Error("expected SSRF block, got nil")
	}
}

func TestVerifySLSAProvenance_OCIWithoutDigest(t *testing.T) {
	policy := &attestationv1alpha1.SoftwareAttestationPolicy{
		SLSAProvenanceAllowedPrefixes: []string{"oci://registry.example.com/"},
	}
	m := attestationv1alpha1.NodeMeasurements{
		// No @sha256: digest — should be rejected.
		SLSAProvenanceURI: "oci://registry.example.com/kubelet:latest",
	}
	if err := verifySLSAProvenance(nil, m, policy); err == nil {
		t.Error("expected error for OCI URI without digest, got nil")
	}
}
