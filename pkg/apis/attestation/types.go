package attestation

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// AttestationMode identifies which verifier processes a NodeAttestationDocument.
type AttestationMode string

const (
	// AttestationModeSoftware uses the built-in PSI verifier in KCM:
	// provisioned keypair + binary hash verification.
	AttestationModeSoftware AttestationMode = "software"

	// AttestationModeHardware defers to an external verifier controller that
	// performs platform-specific verification (TPM, vTPM, cloud identity).
	AttestationModeHardware AttestationMode = "hardware"

	// AttestationModeNull accepts any document and records measurements without
	// verification. For development and CI only; blocked in production by admission.
	AttestationModeNull AttestationMode = "null"
)

// EnrollmentPhase is the lifecycle phase of a NodeIdentityEnrollment.
type EnrollmentPhase string

const (
	EnrollmentPhasePending EnrollmentPhase = "Pending"
	EnrollmentPhaseActive  EnrollmentPhase = "Active"
	EnrollmentPhaseExpired EnrollmentPhase = "Expired"
)

// AttestationPhase is the verification state of a NodeAttestationDocument.
type AttestationPhase string

const (
	AttestationPhasePending  AttestationPhase = "Pending"
	AttestationPhaseVerified AttestationPhase = "Verified"
	AttestationPhaseFailed   AttestationPhase = "Failed"
)

// MeasurementPolicy controls how the software verifier handles binary measurements.
type MeasurementPolicy string

const (
	// MeasurementPolicyRequire requires ExpectedMeasurements to be set on the
	// enrollment and the reported measurements to match exactly.
	MeasurementPolicyRequire MeasurementPolicy = "require"

	// MeasurementPolicyTOFU records measurements from the first bootstrap and
	// uses them as the expected value for all subsequent bootstraps.
	MeasurementPolicyTOFU MeasurementPolicy = "tofu"

	// MeasurementPolicyIgnore skips measurement comparison entirely.
	MeasurementPolicyIgnore MeasurementPolicy = "ignore"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodeIdentityEnrollment registers a node's expected identity prior to bootstrapping.
// Created by the provisioning system (kubeadm, CAPI, kOps, etc.) before the node joins.
// Named after the node it covers. Cluster-scoped.
type NodeIdentityEnrollment struct {
	metav1.TypeMeta
	// +optional
	metav1.ObjectMeta

	Spec   NodeIdentityEnrollmentSpec
	Status NodeIdentityEnrollmentStatus
}

// NodeIdentityEnrollmentSpec defines the expected identity and measurements for a node.
type NodeIdentityEnrollmentSpec struct {
	// AttestationMode is the verification type expected for this node.
	// "software" uses PSI; "hardware" defers to an external verifier controller.
	AttestationMode AttestationMode

	// SoftwareIdentity holds the provisioned public key for software-mode nodes.
	// Required when AttestationMode is "software".
	// +optional
	SoftwareIdentity *SoftwareIdentitySpec

	// HardwareIdentity holds platform-specific identity constraints for hardware-mode nodes.
	// Required when AttestationMode is "hardware".
	// +optional
	HardwareIdentity *HardwareIdentitySpec

	// ExpectedMeasurements constrains the binary hashes the verifier accepts.
	// +optional
	ExpectedMeasurements *NodeMeasurements

	// ProvisioningSource records how this enrollment was created for audit.
	// +optional
	ProvisioningSource string

	// BootstrapExpiry is the deadline for the node's first successful bootstrap.
	// +optional
	BootstrapExpiry *metav1.Time
}

// SoftwareIdentitySpec holds the provisioned public key for PSI attestation.
type SoftwareIdentitySpec struct {
	// PublicKey is the PEM-encoded ECDSA P-256 or Ed25519 public key generated
	// at provisioning time.
	PublicKey string
}

// HardwareIdentitySpec holds platform-specific identity constraints for hardware attestation.
type HardwareIdentitySpec struct {
	// Extensions holds platform-specific identity constraints in reverse-DNS key format.
	// +optional
	Extensions map[string]string
}

// NodeMeasurements describes the software stack evidence for a node.
type NodeMeasurements struct {
	// KubeletHash is the SHA-256 hex digest of the kubelet binary.
	KubeletHash string

	// ContainerRuntimeHash is the SHA-256 hex digest of the CRI binary.
	// +optional
	ContainerRuntimeHash string

	// OSImageID is the cloud/OS image identifier from which this node was booted.
	// +optional
	OSImageID string

	// KernelVersion is the running kernel version string (uname -r).
	// +optional
	KernelVersion string

	// IMALog is a subset of the Linux IMA measurement log (ASCII format).
	// +optional
	IMALog []byte

	// SLSAProvenanceURI is a reference to an OCI artifact or Rekor entry
	// containing SLSA provenance for the kubelet binary.
	// +optional
	SLSAProvenanceURI string

	// Extensions holds platform-specific measurements in reverse-DNS key format.
	// +optional
	Extensions map[string]string
}

// NodeIdentityEnrollmentStatus reflects the current lifecycle phase of an enrollment.
type NodeIdentityEnrollmentStatus struct {
	// Phase is the enrollment lifecycle state.
	// +optional
	Phase EnrollmentPhase

	// LastBootstrapTime records the most recent successful attested bootstrap.
	// +optional
	LastBootstrapTime *metav1.Time

	// NodeUID is the UID of the Node object once created.
	// +optional
	NodeUID types.UID
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodeIdentityEnrollmentList is a list of NodeIdentityEnrollment objects.
type NodeIdentityEnrollmentList struct {
	metav1.TypeMeta
	// +optional
	metav1.ListMeta
	Items []NodeIdentityEnrollment
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodeAttestationChallenge is a short-lived nonce issued to a node before it submits
// a NodeAttestationDocument. Cluster-scoped.
type NodeAttestationChallenge struct {
	metav1.TypeMeta
	// +optional
	metav1.ObjectMeta

	Spec   NodeAttestationChallengeSpec
	Status NodeAttestationChallengeStatus
}

// NodeAttestationChallengeSpec describes the challenge request.
type NodeAttestationChallengeSpec struct {
	// NodeName is the node requesting the challenge.
	NodeName string

	// TTL is the requested validity window.
	// +optional
	TTL metav1.Duration
}

// NodeAttestationChallengeStatus is populated by the API server on creation.
type NodeAttestationChallengeStatus struct {
	// Nonce is base64-encoded cryptographically random data (32 bytes).
	// +optional
	Nonce string

	// ExpiresAt is when this nonce must no longer be accepted.
	// +optional
	ExpiresAt metav1.Time
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodeAttestationChallengeList is a list of NodeAttestationChallenge objects.
type NodeAttestationChallengeList struct {
	metav1.TypeMeta
	// +optional
	metav1.ListMeta
	Items []NodeAttestationChallenge
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodeAttestationDocument is the proof packet submitted by a kubelet during TLS bootstrap
// or certificate rotation. Cluster-scoped.
type NodeAttestationDocument struct {
	metav1.TypeMeta
	// +optional
	metav1.ObjectMeta

	Spec   NodeAttestationDocumentSpec
	Status NodeAttestationDocumentStatus
}

// NodeAttestationDocumentSpec contains the evidence submitted by the node.
type NodeAttestationDocumentSpec struct {
	// NodeName is the node submitting the attestation.
	NodeName string

	// ChallengeRef references the NodeAttestationChallenge this document answers.
	ChallengeRef string

	// AttestationMode identifies which verifier should process this document.
	AttestationMode AttestationMode

	// Measurements is the software stack evidence collected by the kubelet.
	Measurements NodeMeasurements

	// SignedPayload is a compact JWS containing the nonce and measurements hash.
	SignedPayload string
}

// NodeAttestationDocumentStatus is stamped by the verifier.
type NodeAttestationDocumentStatus struct {
	// Phase is the verification lifecycle state: "Pending", "Verified", or "Failed".
	// +optional
	Phase AttestationPhase

	// VerifiedBy identifies the verifier that processed this document.
	// +optional
	VerifiedBy string

	// Conditions provides structured status for the document.
	// +optional
	Conditions []metav1.Condition
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodeAttestationDocumentList is a list of NodeAttestationDocument objects.
type NodeAttestationDocumentList struct {
	metav1.TypeMeta
	// +optional
	metav1.ListMeta
	Items []NodeAttestationDocument
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodeAttestationPolicy is a cluster-scoped singleton (conventional name: "cluster")
// that configures the attestation framework.
type NodeAttestationPolicy struct {
	metav1.TypeMeta
	// +optional
	metav1.ObjectMeta

	Spec NodeAttestationPolicySpec
}

// NodeAttestationPolicySpec configures cluster-wide attestation behaviour.
type NodeAttestationPolicySpec struct {
	// DefaultMode is the attestation mode applied to new enrollments.
	// +optional
	DefaultMode AttestationMode

	// EnforcementMode controls CSR handling for nodes with no enrollment.
	// +optional
	EnforcementMode string

	// TrustedAttestationVerifiers is an allowlist of verifier identity strings.
	// +optional
	TrustedAttestationVerifiers []string

	// SoftwarePolicy configures the built-in PSI verifier.
	// +optional
	SoftwarePolicy *SoftwareAttestationPolicy
}

// SoftwareAttestationPolicy configures the built-in software (PSI) verifier in KCM.
type SoftwareAttestationPolicy struct {
	// MeasurementPolicy controls how the verifier handles binary measurements.
	// +optional
	MeasurementPolicy MeasurementPolicy

	// VerifySLSAProvenance enables fetching and verifying SLSA build provenance.
	// +optional
	VerifySLSAProvenance bool

	// SLSAProvenanceAllowedPrefixes restricts the URI schemes and registry hosts.
	// +optional
	SLSAProvenanceAllowedPrefixes []string

	// SLSAExpectedSubjectIdentity, if set, requires the SLSA provenance subject
	// identity to match.
	// +optional
	SLSAExpectedSubjectIdentity string
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodeAttestationPolicyList is a list of NodeAttestationPolicy objects.
type NodeAttestationPolicyList struct {
	metav1.TypeMeta
	// +optional
	metav1.ListMeta
	Items []NodeAttestationPolicy
}
