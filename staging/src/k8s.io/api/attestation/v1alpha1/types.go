package v1alpha1

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
	// Useful for initial rollout when expected values are not yet known.
	MeasurementPolicyTOFU MeasurementPolicy = "tofu"

	// MeasurementPolicyIgnore skips measurement comparison entirely.
	// Use only in environments where binary integrity is enforced out-of-band.
	MeasurementPolicyIgnore MeasurementPolicy = "ignore"
)

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:prerelease-lifecycle-gen:introduced=1.37

// NodeIdentityEnrollment registers a node's expected identity prior to bootstrapping.
// Created by the provisioning system (kubeadm, CAPI, kOps, etc.) before the node joins.
// Named after the node it covers. Cluster-scoped.
type NodeIdentityEnrollment struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NodeIdentityEnrollmentSpec   `json:"spec,omitempty"`
	Status NodeIdentityEnrollmentStatus `json:"status,omitempty"`
}

// NodeIdentityEnrollmentSpec defines the expected identity and measurements for a node.
type NodeIdentityEnrollmentSpec struct {
	// attestationMode is the verification type expected for this node.
	// "software" uses PSI; "hardware" defers to an external verifier controller.
	// +default="software"
	AttestationMode AttestationMode `json:"attestationMode"`

	// softwareIdentity holds the provisioned public key for software-mode nodes.
	// Required when attestationMode is "software".
	// +optional
	SoftwareIdentity *SoftwareIdentitySpec `json:"softwareIdentity,omitempty"`

	// hardwareIdentity holds platform-specific identity constraints for hardware-mode nodes.
	// Required when attestationMode is "hardware".
	// +optional
	HardwareIdentity *HardwareIdentitySpec `json:"hardwareIdentity,omitempty"`

	// expectedMeasurements constrains the binary hashes the verifier accepts.
	// If unset, behaviour depends on NodeAttestationPolicy.SoftwarePolicy.MeasurementPolicy.
	// +optional
	ExpectedMeasurements *NodeMeasurements `json:"expectedMeasurements,omitempty"`

	// provisioningSource records how this enrollment was created for audit.
	// Examples: "kubeadm", "capi", "kops", "manual".
	// +optional
	ProvisioningSource string `json:"provisioningSource,omitempty"`

	// bootstrapExpiry is the deadline for the node's first successful bootstrap.
	// Enforced only in the Pending phase. Once the enrollment reaches Active,
	// this field is ignored — Active enrollments persist for the Node lifetime.
	// +optional
	BootstrapExpiry *metav1.Time `json:"bootstrapExpiry,omitempty"`

	// expectedNodeIP is the IP address the node is expected to bootstrap from.
	// When set, the verifier rejects attestation documents whose signed payload
	// carries a different node_ip claim. Protects against cross-node replay of
	// stolen attestation documents.
	// +optional
	ExpectedNodeIP string `json:"expectedNodeIP,omitempty"`
}

// SoftwareIdentitySpec holds the provisioned public key for PSI attestation.
type SoftwareIdentitySpec struct {
	// publicKey is the PEM-encoded ECDSA P-256 or Ed25519 public key generated
	// at provisioning time. The corresponding private key resides on the node at
	// the path configured by KubeletConfiguration.NodeIdentityKeyFile and is
	// never transmitted to the cluster.
	PublicKey string `json:"publicKey"`
}

// HardwareIdentitySpec holds platform-specific identity constraints for hardware attestation.
// All hardware-specific fields use the Extensions map with reverse-DNS keys so that
// platform-specific verifiers can extend the schema without API changes.
type HardwareIdentitySpec struct {
	// extensions holds platform-specific identity constraints in reverse-DNS key format.
	// Examples:
	//   "cloud.google.com/instance-id":  "1234567890"
	//   "cloud.google.com/project-id":   "my-project"
	//   "azure.microsoft.com/vm-id":     "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
	//   "tpm.trusted-computing.org/ek-cert-fingerprint": "<sha256-hex>"
	// +optional
	Extensions map[string]string `json:"extensions,omitempty"`
}

// NodeMeasurements describes the software stack evidence for a node.
// Used in NodeIdentityEnrollmentSpec.ExpectedMeasurements (what should run)
// and NodeAttestationDocumentSpec.Measurements (what is running).
type NodeMeasurements struct {
	// kubeletHash is the SHA-256 hex digest of the kubelet binary (sha256sum /proc/self/exe).
	KubeletHash string `json:"kubeletHash"`

	// osImageID is the cloud/OS image identifier from which this node was booted.
	// Examples: AMI ID, GCE image name, cloud-init image hash.
	// +optional
	OSImageID string `json:"osImageID,omitempty"`

	// kernelVersion is the running kernel version string (uname -r).
	// +optional
	KernelVersion string `json:"kernelVersion,omitempty"`

	// slsaProvenanceURI is a reference to an OCI artifact or Rekor entry
	// containing SLSA provenance for the kubelet binary.
	// Must match an entry in NodeAttestationPolicy.SoftwarePolicy.SLSAProvenanceAllowedPrefixes.
	// +optional
	SLSAProvenanceURI string `json:"slsaProvenanceURI,omitempty"`
}

// NodeIdentityEnrollmentStatus reflects the current lifecycle phase of an enrollment.
type NodeIdentityEnrollmentStatus struct {
	// phase is the enrollment lifecycle state.
	//
	// Transitions:
	//   Pending → Active:  Set by KCM after a NodeAttestationDocument for this node
	//                      reaches Verified and the corresponding CSR is approved.
	//                      A CSR approved via the legacy token path does NOT trigger
	//                      this transition.
	//   Pending → Expired: Set by attestationcleaner after BootstrapExpiry without
	//                      the enrollment reaching Active.
	//   Active  → (none):  Active enrollments persist for the Node object lifetime.
	// +optional
	Phase EnrollmentPhase `json:"phase,omitempty"`

	// lastBootstrapTime records the most recent successful attested bootstrap.
	// Not updated for legacy token-path CSR approvals.
	// +optional
	LastBootstrapTime *metav1.Time `json:"lastBootstrapTime,omitempty"`

	// nodeUID is the UID of the Node object once created.
	// +optional
	NodeUID types.UID `json:"nodeUID,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodeIdentityEnrollmentList is a list of NodeIdentityEnrollment objects.
type NodeIdentityEnrollmentList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NodeIdentityEnrollment `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:prerelease-lifecycle-gen:introduced=1.37

// NodeAttestationChallenge is a short-lived nonce issued to a node before it submits
// a NodeAttestationDocument. Prevents replay of captured attestation proofs.
// Cluster-scoped. Deleted by the verifier on first use; also reaped by attestationcleaner on TTL expiry.
type NodeAttestationChallenge struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NodeAttestationChallengeSpec   `json:"spec,omitempty"`
	Status NodeAttestationChallengeStatus `json:"status,omitempty"`
}

// NodeAttestationChallengeSpec describes the challenge request.
type NodeAttestationChallengeSpec struct {
	// nodeName is the node requesting the challenge.
	NodeName string `json:"nodeName"`

	// ttl is the requested validity window.
	// The API server clamps this to a server-side maximum (default 10 minutes).
	// Values above the cap are silently reduced. Default: 5 minutes.
	// +optional
	TTL metav1.Duration `json:"ttl,omitempty"`
}

// NodeAttestationChallengeStatus is populated by the API server on creation.
type NodeAttestationChallengeStatus struct {
	// nonce is base64-encoded cryptographically random data (32 bytes).
	// The node must sign this value in its NodeAttestationDocument.
	// +optional
	Nonce string `json:"nonce,omitempty"`

	// expiresAt is when this nonce must no longer be accepted.
	// Informational: computed as creationTimestamp + effective TTL.
	// +optional
	ExpiresAt metav1.Time `json:"expiresAt,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodeAttestationChallengeList is a list of NodeAttestationChallenge objects.
type NodeAttestationChallengeList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NodeAttestationChallenge `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:prerelease-lifecycle-gen:introduced=1.37

// NodeAttestationDocument is the proof packet submitted by a kubelet during TLS bootstrap
// or certificate rotation. It contains the signed nonce, software measurements, and
// the JWS payload signed with the node's identity key.
//
// Named <node-name>-<nonce-suffix> to allow concurrent bootstrap retries.
// Cluster-scoped. Deleted by attestationcleaner after the associated CSR reaches a
// terminal state, or after a configurable retention window (default 24h) for audit.
type NodeAttestationDocument struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NodeAttestationDocumentSpec   `json:"spec,omitempty"`
	Status NodeAttestationDocumentStatus `json:"status,omitempty"`
}

// NodeAttestationDocumentSpec contains the evidence submitted by the node.
type NodeAttestationDocumentSpec struct {
	// nodeName is the node submitting the attestation.
	NodeName string `json:"nodeName"`

	// challengeRef references the NodeAttestationChallenge this document answers.
	// The nonce from the challenge must be included in SignedPayload.
	ChallengeRef string `json:"challengeRef"`

	// attestationMode identifies which verifier should process this document.
	// Must match the AttestationMode in the node's NodeIdentityEnrollment.
	AttestationMode AttestationMode `json:"attestationMode"`

	// measurements is the software stack evidence collected by the kubelet.
	// For hardware modes this may be empty or contain supplemental evidence.
	Measurements NodeMeasurements `json:"measurements,omitempty"`

	// signedPayload is a compact JWS (JSON Web Signature) containing:
	//   iss, sub (system:node:<node-name>), iat, exp, nonce, measurements_hash.
	// Signed with the node identity private key (software mode) or the platform
	// attestation key (hardware modes).
	// The verifier cross-checks sha256(canonical(Measurements)) == measurements_hash claim.
	SignedPayload string `json:"signedPayload"`
}

// NodeAttestationDocumentStatus is stamped by the verifier (built-in or external controller).
type NodeAttestationDocumentStatus struct {
	// phase is the verification lifecycle state: "Pending", "Verified", or "Failed".
	// The CSR approver acts only when Phase is terminal.
	// +optional
	Phase AttestationPhase `json:"phase,omitempty"`

	// verifiedBy identifies the verifier that processed this document.
	// For built-in software verifier: "kubernetes.io/software-verifier".
	// For external controllers: the controller's self-reported identity.
	// Used by the CSR approver to enforce the TrustedAttestationVerifiers allowlist.
	// +optional
	VerifiedBy string `json:"verifiedBy,omitempty"`

	// conditions provides structured status for the document.
	// Condition type "Verified" is the canonical signal for the CSR approver.
	// Condition type "Failed" carries the failure reason in its Message field.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodeAttestationDocumentList is a list of NodeAttestationDocument objects.
type NodeAttestationDocumentList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NodeAttestationDocument `json:"items"`
}

// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +k8s:prerelease-lifecycle-gen:introduced=1.37

// NodeAttestationPolicy is a cluster-scoped singleton (conventional name: "cluster")
// that configures the attestation framework: default mode, enforcement strictness,
// trusted verifier allowlist, and software verifier policy.
//
// Created by kubeadm init from an inline document in the kubeadm config file.
// Read by kubeadm join (via bootstrap token) to determine cluster attestation policy.
type NodeAttestationPolicy struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec NodeAttestationPolicySpec `json:"spec,omitempty"`
}

// NodeAttestationPolicySpec configures cluster-wide attestation behaviour.
type NodeAttestationPolicySpec struct {
	// defaultMode is the attestation mode applied to new enrollments.
	// "software" | "hardware". Empty string disables attestation.
	// +default="software"
	// +optional
	DefaultMode AttestationMode `json:"defaultMode,omitempty"`

	// enforcementMode controls CSR handling for nodes with no enrollment.
	//
	// "permissive": CSRs from nodes with no enrollment proceed via the legacy token
	//              path with a warning. CSRs from enrolled nodes without AttestationRef
	//              are denied regardless of this setting.
	// "enforced":  All CSRs without a valid AttestationRef are denied.
	//
	// +default="permissive"
	// +optional
	EnforcementMode string `json:"enforcementMode,omitempty"`

	// trustedAttestationVerifiers is an allowlist of verifier identity strings.
	// Only NodeAttestationDocuments stamped by a listed verifier are accepted.
	// Built-in software verifier identity: "kubernetes.io/software-verifier".
	// If empty, only the built-in software verifier is trusted.
	// +optional
	TrustedAttestationVerifiers []string `json:"trustedAttestationVerifiers,omitempty"`

	// softwarePolicy configures the built-in PSI verifier.
	// +optional
	SoftwarePolicy *SoftwareAttestationPolicy `json:"softwarePolicy,omitempty"`
}

// SoftwareAttestationPolicy configures the built-in software (PSI) verifier in KCM.
type SoftwareAttestationPolicy struct {
	// measurementPolicy controls how the verifier handles binary measurements.
	// "require": ExpectedMeasurements must be set and match reported measurements.
	// "tofu":    Record measurements on first bootstrap; require match thereafter.
	// "ignore":  Skip measurement comparison entirely.
	// +default="require"
	// +optional
	MeasurementPolicy MeasurementPolicy `json:"measurementPolicy,omitempty"`

	// verifySLSAProvenance enables fetching and verifying SLSA build provenance
	// for the kubelet binary using SLSAProvenanceURI from Measurements.
	// +default=false
	// +optional
	VerifySLSAProvenance bool `json:"verifySLSAProvenance,omitempty"`

	// slsaProvenanceAllowedPrefixes restricts the URI schemes and registry hosts
	// from which provenance may be fetched. Prevents SSRF via node-supplied URIs.
	// Example: ["oci://registry.example.com/", "https://rekor.sigstore.dev/"]
	// +optional
	SLSAProvenanceAllowedPrefixes []string `json:"slsaProvenanceAllowedPrefixes,omitempty"`

	// slsaExpectedSubjectIdentity, if set, requires the SLSA provenance subject
	// identity to match (e.g. signer email or OIDC issuer). Prevents provenance
	// substitution from a different build pipeline with the same binary hash.
	// +optional
	SLSAExpectedSubjectIdentity string `json:"slsaExpectedSubjectIdentity,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// NodeAttestationPolicyList is a list of NodeAttestationPolicy objects.
type NodeAttestationPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NodeAttestationPolicy `json:"items"`
}
