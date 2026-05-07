package approver

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	jose "gopkg.in/go-jose/go-jose.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	attestationv1alpha1 "k8s.io/api/attestation/v1alpha1"
	capi "k8s.io/api/certificates/v1"
	clientset "k8s.io/client-go/kubernetes"
)

const (
	// SoftwareVerifierIdentity is the VerifiedBy value stamped by the built-in software verifier.
	SoftwareVerifierIdentity = "kubernetes.io/software-verifier"

	// maxChallengeTTL is the server-side cap on NodeAttestationChallenge TTL.
	maxChallengeTTL = 10 * time.Minute
)

// AttestationVerifier verifies a NodeAttestationDocument before a CSR is approved.
// Implementations are registered per AttestationMode in AttestationVerifierRegistry.
type AttestationVerifier interface {
	// Verify checks the attestation document for the given CSR.
	// Returns nil if attestation is valid and the CSR should be approved.
	Verify(ctx context.Context, csr *capi.CertificateSigningRequest, doc *attestationv1alpha1.NodeAttestationDocument) error

	// Mode returns the AttestationMode this verifier handles.
	Mode() attestationv1alpha1.AttestationMode
}

// AttestationVerifierRegistry maps AttestationMode values to their verifier.
// The software verifier is always registered. Hardware verifiers are external
// controllers that stamp NodeAttestationDocument.Status rather than registering here.
type AttestationVerifierRegistry struct {
	verifiers map[attestationv1alpha1.AttestationMode]AttestationVerifier
}

// NewAttestationVerifierRegistry returns a registry pre-populated with the built-in verifiers.
func NewAttestationVerifierRegistry(client clientset.Interface, policy *attestationv1alpha1.SoftwareAttestationPolicy) *AttestationVerifierRegistry {
	r := &AttestationVerifierRegistry{
		verifiers: make(map[attestationv1alpha1.AttestationMode]AttestationVerifier),
	}
	r.Register(&softwareAttestationVerifier{client: client, policy: policy})
	return r
}

// Register adds a verifier. Safe to call at startup only (not concurrent).
func (r *AttestationVerifierRegistry) Register(v AttestationVerifier) {
	r.verifiers[v.Mode()] = v
}

// Lookup returns the built-in verifier for the given mode, or nil if no
// built-in verifier handles it (hardware documents use the external controller path).
func (r *AttestationVerifierRegistry) Lookup(mode attestationv1alpha1.AttestationMode) AttestationVerifier {
	return r.verifiers[mode]
}

// jwsClaims are the claims expected inside a NodeAttestationDocument SignedPayload.
type jwsClaims struct {
	Issuer           string `json:"iss"`
	Subject          string `json:"sub"`
	IssuedAt         int64  `json:"iat"`
	ExpiresAt        int64  `json:"exp"`
	Nonce            string `json:"nonce"`
	MeasurementsHash string `json:"measurements_hash"`
	NodeIP           string `json:"node_ip,omitempty"`
}

// softwareAttestationVerifier is the built-in PSI verifier.
type softwareAttestationVerifier struct {
	client clientset.Interface
	policy *attestationv1alpha1.SoftwareAttestationPolicy
}

func (v *softwareAttestationVerifier) Mode() attestationv1alpha1.AttestationMode {
	return attestationv1alpha1.AttestationModeSoftware
}

func (v *softwareAttestationVerifier) Verify(
	ctx context.Context,
	csr *capi.CertificateSigningRequest,
	doc *attestationv1alpha1.NodeAttestationDocument,
) error {
	// 1. Fetch NodeIdentityEnrollment for this node.
	// TODO: use an informer cache in production; direct GET is fine for alpha.
	enrollment, err := v.client.AttestationV1alpha1().
		NodeIdentityEnrollments().Get(ctx, doc.Spec.NodeName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("enrollment not found for node %s: %w", doc.Spec.NodeName, err)
	}

	// 2. Validate mode consistency — node must not have chosen a different mode.
	if doc.Spec.AttestationMode != enrollment.Spec.AttestationMode {
		return fmt.Errorf("mode mismatch: document claims %q but enrollment requires %q",
			doc.Spec.AttestationMode, enrollment.Spec.AttestationMode)
	}

	// 3. Check bootstrap expiry (enforced only while enrollment is Pending).
	if enrollment.Status.Phase == attestationv1alpha1.EnrollmentPhasePending &&
		enrollment.Spec.BootstrapExpiry != nil &&
		time.Now().After(enrollment.Spec.BootstrapExpiry.Time) {
		return fmt.Errorf("enrollment for node %s has expired", doc.Spec.NodeName)
	}

	// 4. Verify JWS signature using the enrolled public key.
	if enrollment.Spec.SoftwareIdentity == nil {
		return fmt.Errorf("enrollment for node %s has no SoftwareIdentity", doc.Spec.NodeName)
	}
	claims, err := verifyJWSAndExtractClaims(doc.Spec.SignedPayload, enrollment.Spec.SoftwareIdentity.PublicKey)
	if err != nil {
		return fmt.Errorf("attestation signature invalid: %w", err)
	}

	// 5. Verify nonce against challenge; cross-check NodeName binding.
	// Delete the challenge immediately after use — it is single-use.
	challenge, err := v.client.AttestationV1alpha1().
		NodeAttestationChallenges().Get(ctx, doc.Spec.ChallengeRef, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("challenge %q not found: %w", doc.Spec.ChallengeRef, err)
	}
	if challenge.Spec.NodeName != doc.Spec.NodeName {
		return fmt.Errorf("challenge node name mismatch: challenge issued for %q but document claims %q",
			challenge.Spec.NodeName, doc.Spec.NodeName)
	}
	if time.Now().After(challenge.Status.ExpiresAt.Time) {
		return fmt.Errorf("challenge nonce expired at %s", challenge.Status.ExpiresAt.Time)
	}
	if claims.Nonce != challenge.Status.Nonce {
		return fmt.Errorf("nonce mismatch in signed payload")
	}
	// Delete challenge — must not be reused for a second bootstrap attempt.
	if derr := v.client.AttestationV1alpha1().
		NodeAttestationChallenges().Delete(ctx, challenge.Name, metav1.DeleteOptions{}); derr != nil {
		klog.Warningf("attestation: failed to delete used challenge %s: %v", challenge.Name, derr)
	}

	// 5a. Verify node_ip binding if the enrollment specifies an expected IP.
	if enrollment.Spec.ExpectedNodeIP != "" {
		if claims.NodeIP == "" {
			return fmt.Errorf("enrollment requires node_ip claim but signed payload contains none")
		}
		if claims.NodeIP != enrollment.Spec.ExpectedNodeIP {
			return fmt.Errorf("node_ip mismatch: enrollment expects %q but JWS claims %q",
				enrollment.Spec.ExpectedNodeIP, claims.NodeIP)
		}
	}

	// 6. Cross-check measurements_hash binding.
	// The hash in the JWS payload must equal sha256(canonical JSON of Measurements).
	expectedHash, err := measurementsHash(doc.Spec.Measurements)
	if err != nil {
		return fmt.Errorf("cannot hash measurements: %w", err)
	}
	if claims.MeasurementsHash != expectedHash {
		return fmt.Errorf("measurements_hash mismatch: JWS claims %q but Measurements hash to %q",
			claims.MeasurementsHash, expectedHash)
	}

	// 7. Verify binary measurements against expected values.
	if enrollment.Spec.ExpectedMeasurements != nil {
		if err := verifyMeasurements(doc.Spec.Measurements, *enrollment.Spec.ExpectedMeasurements, v.policy); err != nil {
			return fmt.Errorf("measurement mismatch: %w", err)
		}
	} else {
		policy := MeasurementPolicyRequire
		if v.policy != nil {
			policy = string(v.policy.MeasurementPolicy)
		}
		switch policy {
		case MeasurementPolicyTOFU:
			if err := recordMeasurements(ctx, v.client, enrollment, doc.Spec.Measurements); err != nil {
				klog.Warningf("attestation: failed to record TOFU measurements for %s: %v", doc.Spec.NodeName, err)
			}
		case MeasurementPolicyIgnore:
			// No measurement check.
		default: // "require"
			return fmt.Errorf("no expected measurements set and MeasurementPolicy is %q", policy)
		}
	}

	// 8. Optionally verify SLSA provenance.
	if v.policy != nil && v.policy.VerifySLSAProvenance && doc.Spec.Measurements.SLSAProvenanceURI != "" {
		if err := verifySLSAProvenance(ctx, doc.Spec.Measurements, v.policy); err != nil {
			return fmt.Errorf("SLSA provenance verification failed: %w", err)
		}
	}

	return nil
}

const (
	MeasurementPolicyRequire = "require"
	MeasurementPolicyTOFU    = "tofu"
	MeasurementPolicyIgnore  = "ignore"
)

// verifyJWSAndExtractClaims verifies the compact JWS signature using pemPublicKey
// and returns the parsed claims on success.
func verifyJWSAndExtractClaims(compactJWS, pemPublicKey string) (*jwsClaims, error) {
	block, _ := pem.Decode([]byte(pemPublicKey))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM public key")
	}

	// Parse the public key — support EC (P-256) only for alpha.
	// Ed25519 support requires go-jose v3+ or a separate parser.
	pub, err := parseECPublicKeyFromDER(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	jws, err := jose.ParseSigned(compactJWS)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWS: %w", err)
	}

	payload, err := jws.Verify(pub)
	if err != nil {
		return nil, fmt.Errorf("JWS signature verification failed: %w", err)
	}

	var claims jwsClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWS claims: %w", err)
	}

	// Verify standard time claims.
	now := time.Now().Unix()
	if claims.ExpiresAt > 0 && now > claims.ExpiresAt {
		return nil, fmt.Errorf("JWS token has expired")
	}
	if claims.IssuedAt > 0 && now < claims.IssuedAt-30 {
		return nil, fmt.Errorf("JWS token issued in the future (clock skew too large)")
	}
	if claims.Issuer != "kubernetes.io/node-identity/v1alpha1" {
		return nil, fmt.Errorf("unexpected JWS issuer: %q", claims.Issuer)
	}

	return &claims, nil
}

// measurementsHash returns the hex-encoded SHA-256 of the canonical JSON encoding
// of the NodeMeasurements struct. This is the value the JWS measurements_hash claim
// must equal.
func measurementsHash(m attestationv1alpha1.NodeMeasurements) (string, error) {
	// Sort keys deterministically by marshalling to JSON.
	// Go's encoding/json produces sorted keys for structs (field declaration order),
	// which is stable and canonical for our purposes.
	data, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("json marshal: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// verifyMeasurements checks that the reported measurements match the expected values
// according to the software attestation policy.
func verifyMeasurements(
	reported attestationv1alpha1.NodeMeasurements,
	expected attestationv1alpha1.NodeMeasurements,
	policy *attestationv1alpha1.SoftwareAttestationPolicy,
) error {
	if expected.KubeletHash != "" && reported.KubeletHash != expected.KubeletHash {
		return fmt.Errorf("kubelet hash mismatch: expected %s got %s",
			expected.KubeletHash, reported.KubeletHash)
	}
	if expected.OSImageID != "" && reported.OSImageID != expected.OSImageID {
		return fmt.Errorf("OS image ID mismatch: expected %s got %s",
			expected.OSImageID, reported.OSImageID)
	}
	if expected.KernelVersion != "" && reported.KernelVersion != expected.KernelVersion {
		return fmt.Errorf("kernel version mismatch: expected %s got %s",
			expected.KernelVersion, reported.KernelVersion)
	}
	return nil
}

// recordMeasurements writes the first-seen measurements into the enrollment status
// under the TOFU policy. Subsequent bootstraps will verify against these values.
func recordMeasurements(
	ctx context.Context,
	client clientset.Interface,
	enrollment *attestationv1alpha1.NodeIdentityEnrollment,
	measurements attestationv1alpha1.NodeMeasurements,
) error {
	updated := enrollment.DeepCopy()
	updated.Spec.ExpectedMeasurements = measurements.DeepCopy()
	_, err := client.AttestationV1alpha1().
		NodeIdentityEnrollments().Update(ctx, updated, metav1.UpdateOptions{})
	return err
}

// verifySLSAProvenance fetches and verifies SLSA build provenance for the kubelet binary.
// The URI must match an entry in policy.SLSAProvenanceAllowedPrefixes (SSRF mitigation).
func verifySLSAProvenance(
	ctx context.Context,
	measurements attestationv1alpha1.NodeMeasurements,
	policy *attestationv1alpha1.SoftwareAttestationPolicy,
) error {
	uri := measurements.SLSAProvenanceURI
	if uri == "" {
		return nil
	}

	// SSRF mitigation: URI must match an allowed prefix.
	if len(policy.SLSAProvenanceAllowedPrefixes) > 0 {
		allowed := false
		for _, prefix := range policy.SLSAProvenanceAllowedPrefixes {
			if strings.HasPrefix(uri, prefix) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("SLSA provenance URI %q does not match any allowed prefix", uri)
		}
	}

	// URI must include an OCI digest to prevent TOCTOU/redirect attacks.
	if strings.Contains(uri, "oci://") && !strings.Contains(uri, "@sha256:") {
		return fmt.Errorf("SLSA provenance OCI URI must include a digest (@sha256:...)")
	}

	// TODO(alpha): implement actual OCI/Rekor fetch and provenance verification.
	// For now we validate the URI structure and allowlist only.
	klog.V(4).Infof("attestation: SLSA provenance URI validated (fetch not yet implemented): %s", uri)
	return nil
}

// parseECPublicKeyFromDER parses a DER-encoded PKIX EC public key.
func parseECPublicKeyFromDER(der []byte) (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("x509.ParsePKIXPublicKey: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ECDSA (got %T)", pub)
	}
	return ecPub, nil
}

// extractNonceFromJWS extracts the base64-encoded nonce from a compact JWS
// without full signature verification (used for pre-checks).
func extractNonceFromJWS(compactJWS string) (string, error) {
	parts := strings.Split(compactJWS, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid compact JWS: expected 3 parts")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to base64-decode JWS payload: %w", err)
	}
	var claims struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("failed to unmarshal JWS payload: %w", err)
	}
	return claims.Nonce, nil
}
