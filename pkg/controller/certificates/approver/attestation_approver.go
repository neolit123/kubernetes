package approver

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	capi "k8s.io/api/certificates/v1"
	clientset "k8s.io/client-go/kubernetes"
	attestationv1alpha1 "k8s.io/api/attestation/v1alpha1"
)

// errRequeue is a sentinel returned when the CSR approver should re-enqueue
// the CSR rather than deny it (external verifier not yet done).
var errRequeue = fmt.Errorf("attestation pending: requeue")

// attestedNodeClientSubresource is the CSR subresource that permits attested bootstrap.
const attestedNodeClientSubresource = "attestednodeclient"

// NewAttestationCSRApprovingController creates a CSR approving controller that
// handles attested kubelet client certificate requests in addition to the
// standard SAR-based approvals. It wraps the base sarApprover.
//
// policy is the cluster NodeAttestationPolicy. verifierRegistry contains the
// built-in software verifier (hardware verifiers are external controllers).
func NewAttestationCSRApprovingController(
	ctx context.Context,
	client clientset.Interface,
	policy *attestationv1alpha1.NodeAttestationPolicySpec,
	verifierRegistry *AttestationVerifierRegistry,
) *attestationApprover {
	trustedVerifiers := sets.NewString("kubernetes.io/software-verifier")
	if policy != nil {
		trustedVerifiers.Insert(policy.TrustedAttestationVerifiers...)
	}
	return &attestationApprover{
		client:           client,
		policy:           policy,
		verifierRegistry: verifierRegistry,
		trustedVerifiers: trustedVerifiers,
	}
}

// attestationApprover checks AttestationRef on CSRs and runs the appropriate verifier.
type attestationApprover struct {
	client           clientset.Interface
	policy           *attestationv1alpha1.NodeAttestationPolicySpec
	verifierRegistry *AttestationVerifierRegistry
	trustedVerifiers sets.String
}

// HandleAttestedCSR is called from the main sarApprover.handle when the CSR has
// an AttestationRef set. It returns nil to allow approval, errRequeue to defer,
// or a non-nil error to deny.
func (a *attestationApprover) HandleAttestedCSR(
	ctx context.Context,
	csr *capi.CertificateSigningRequest,
) error {
	if csr.Spec.AttestationRef == "" {
		return a.handleNoAttestationRef(ctx, csr)
	}

	doc, err := a.client.AttestationV1alpha1().
		NodeAttestationDocuments().Get(ctx, csr.Spec.AttestationRef, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("attestation: cannot fetch NodeAttestationDocument %q: %w",
			csr.Spec.AttestationRef, err)
	}

	// Fast path: a built-in verifier handles this mode inline.
	if v := a.verifierRegistry.Lookup(doc.Spec.AttestationMode); v != nil {
		if err := v.Verify(ctx, csr, doc); err != nil {
			return fmt.Errorf("attestation verification failed: %w", err)
		}
		// Transition enrollment to Active after successful attested verification.
		if err := a.transitionEnrollmentActive(ctx, doc.Spec.NodeName); err != nil {
			klog.Warningf("attestation: failed to transition enrollment for %s to Active: %v",
				doc.Spec.NodeName, err)
		}
		return nil
	}

	// Slow path: wait for an external controller to stamp Status.Phase.
	return a.waitForExternalVerifier(ctx, csr, doc)
}

// handleNoAttestationRef handles CSRs that arrive without an AttestationRef.
// If the node has an enrollment, deny immediately (enrolled nodes must attest).
// If not, allow in permissive mode or deny in enforced mode.
func (a *attestationApprover) handleNoAttestationRef(ctx context.Context, csr *capi.CertificateSigningRequest) error {
	nodeName := extractNodeName(csr)
	if nodeName == "" {
		// Not a node CSR; not our concern.
		return nil
	}

	_, err := a.client.AttestationV1alpha1().
		NodeIdentityEnrollments().Get(ctx, nodeName, metav1.GetOptions{})
	if err == nil {
		// Enrollment exists — node must attest regardless of enforcement mode.
		return fmt.Errorf("attestation: node %s has a NodeIdentityEnrollment but CSR has no AttestationRef; "+
			"re-bootstrap with attestation enabled", nodeName)
	}

	// No enrollment found.
	enforcementMode := "permissive"
	if a.policy != nil && a.policy.EnforcementMode != "" {
		enforcementMode = a.policy.EnforcementMode
	}
	if enforcementMode == "enforced" {
		return fmt.Errorf("attestation: node %s has no NodeIdentityEnrollment and enforcementMode is %q; "+
			"create an enrollment before joining", nodeName, enforcementMode)
	}

	// permissive mode — no enrollment, allow legacy token path with a warning.
	klog.Warningf("attestation: node %s has no enrollment; proceeding via legacy token path (permissive mode)", nodeName)
	return nil
}

// waitForExternalVerifier handles the slow path for hardware/custom modes.
func (a *attestationApprover) waitForExternalVerifier(
	ctx context.Context,
	csr *capi.CertificateSigningRequest,
	doc *attestationv1alpha1.NodeAttestationDocument,
) error {
	switch doc.Status.Phase {
	case attestationv1alpha1.AttestationPhaseVerified:
		if !a.trustedVerifiers.Has(doc.Status.VerifiedBy) {
			return fmt.Errorf("attestation: untrusted verifier %q stamped document %s; "+
				"add it to NodeAttestationPolicy.TrustedAttestationVerifiers",
				doc.Status.VerifiedBy, doc.Name)
		}
		if err := a.transitionEnrollmentActive(ctx, doc.Spec.NodeName); err != nil {
			klog.Warningf("attestation: failed to transition enrollment for %s to Active: %v",
				doc.Spec.NodeName, err)
		}
		return nil

	case attestationv1alpha1.AttestationPhaseFailed:
		reason := ""
		for _, c := range doc.Status.Conditions {
			if c.Type == "Failed" {
				reason = c.Message
			}
		}
		return fmt.Errorf("attestation failed by %s: %s", doc.Status.VerifiedBy, reason)

	default: // Pending
		// Check if the challenge TTL has expired.
		challenge, err := a.client.AttestationV1alpha1().
			NodeAttestationChallenges().Get(ctx, doc.Spec.ChallengeRef, metav1.GetOptions{})
		if err != nil || time.Now().After(challenge.Status.ExpiresAt.Time) {
			return fmt.Errorf("attestation timed out: no verifier claimed document %s within the challenge TTL", doc.Name)
		}
		// Challenge still live — requeue and wait.
		return errRequeue
	}
}

// transitionEnrollmentActive updates the enrollment phase to Active and records
// the bootstrap time. Called after the attestation document is verified.
func (a *attestationApprover) transitionEnrollmentActive(ctx context.Context, nodeName string) error {
	enrollment, err := a.client.AttestationV1alpha1().
		NodeIdentityEnrollments().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if enrollment.Status.Phase == attestationv1alpha1.EnrollmentPhaseActive {
		return nil // already Active
	}
	updated := enrollment.DeepCopy()
	updated.Status.Phase = attestationv1alpha1.EnrollmentPhaseActive
	now := metav1.Now()
	updated.Status.LastBootstrapTime = &now
	_, err = a.client.AttestationV1alpha1().
		NodeIdentityEnrollments().UpdateStatus(ctx, updated, metav1.UpdateOptions{})
	return err
}

// extractNodeName extracts the node name from a kubelet client cert CSR username.
// CSR username for a node is "system:node:<name>".
func extractNodeName(csr *capi.CertificateSigningRequest) string {
	const prefix = "system:node:"
	if len(csr.Spec.Username) > len(prefix) &&
		csr.Spec.Username[:len(prefix)] == prefix {
		return csr.Spec.Username[len(prefix):]
	}
	return ""
}
