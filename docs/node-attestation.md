# Node Attestation for Kubernetes: A Unified Framework
## Design Proposal — WG Node Identity Companion Document

**Author:** Draft for WG Node Identity discussion
**Date:** 2026-05-06
**Status:** Draft / Discussion
**Relates to:** WG Node Identity Charter, KEP-266, KEP-1205, KEP-740

---

## Summary

This document proposes a unified **Node Attestation** framework for Kubernetes, controlled by a single `NodeAttestation` feature gate. The framework:

1. Ships a built-in **software attestation** verifier (Provisioned Software Identity, PSI) that works on any platform without hardware requirements — this is the default
2. Defines a **pluggable verifier interface** so hardware attestation providers (TPM, vTPM, cloud instance identity) can integrate without changes to Kubernetes core, by deploying an external verifier controller
3. Uses a single consistent API surface (`attestation.kubernetes.io/v1alpha1`) regardless of attestation mode, so clusters can transition from software to hardware attestation by configuration change alone

The feature gate `NodeAttestation` enables the entire framework. Which verifier runs is a configuration and deployment concern, not a gate concern.

The built-in software mechanism is called **Provisioned Software Identity (PSI)**.

---

## Motivation

### The problem with TOFU bootstrap tokens

The current kubelet TLS bootstrap (KEP-266) is Trust-On-First-Use: a shared bearer token authenticates the kubelet's initial CSR. Anyone who obtains the token can impersonate any node. The SIG Security STRIDE analysis (STRIDE-SPOOF-4/5) confirmed this is an exploitable threat, not a theoretical one.

Hardware attestation (TPM) solves this definitively: the attestation is rooted in silicon that cannot be forged. However:

- TPM enrollment requires infrastructure that many environments lack (bare-metal without UEFI TPM, old cloud VMs, on-prem edge)
- Even on platforms with TPMs, integration requires per-platform verifier plugins that will take years to reach GA
- There is a multi-year gap during which clusters have no better alternative than bootstrap tokens

### What software attestation can realistically achieve

Software attestation cannot match hardware attestation's guarantees. Its threat model is different:

| Threat | Hardware TPM | Software PSI |
|---|---|---|
| Attacker intercepts bootstrap token and replays | Blocked (TPM signature required) | Blocked (provisioned key required) |
| Attacker gains read access to node disk | Blocked (TPM key not extractable) | **Vulnerable** (key extraction possible) |
| Unexpected binary running as kubelet | Blocked (PCR measurements) | Blocked (binary hash verified) |
| Supply chain compromise of kubelet binary | Partially blocked | Blocked (sigstore/SLSA provenance) |
| Node impersonation without physical/root access | Blocked | Blocked |
| TOFU bootstrap token reuse across nodes | Blocked | Blocked |

Software attestation closes the common attack vectors (token theft, node impersonation without node access) while acknowledging that a root-level compromise of the node itself can bypass it. This is an honest and useful security improvement over TOFU tokens for the majority of real-world deployments.

---

## Goals

- Single `NodeAttestation` feature gate that enables the entire attestation framework
- Built-in software verifier (PSI) as the universal default — works on every platform with zero infrastructure requirements
- Pluggable verifier interface so hardware providers (TPM, vTPM, cloud identity) integrate without changes to Kubernetes core
- Single API surface (`attestation.kubernetes.io/v1alpha1`) for all attestation modes; switching from software to hardware is a config change, not an API change
- Anti-replay mechanism (nonce-based) for all verifier types
- Fit within the existing CSR approval flow in `pkg/controller/certificates/approver/`
- If attestation is configured for a node (an enrollment exists), a failed or timed-out attestation always results in CSR denial — there is no silent fallback to token-based approval

## Non-Goals

- Matching TPM-level guarantees in the software path (explicitly weaker; documented in threat model)
- Implementing hardware verifiers in-tree (hardware verifiers are external controllers; this document defines the interface they must satisfy)
- Workload/pod identity
- Encrypting in-cluster traffic
- Removing bootstrap token support — bootstrap tokens remain the mechanism for nodes where attestation is explicitly not configured (no enrollment, permissive migration mode). They are not a fallback for failed attestation.

---

## Proposal: Provisioned Software Identity (PSI)

### Core Concept

At node provisioning time (kubeadm join, CAPI machine create, etc.), the provisioning tool generates a **per-node identity keypair**. The public key is registered in the cluster as a `NodeIdentityEnrollment` object. The private key is written to the node's filesystem in a protected location (e.g., `/var/lib/kubelet/pki/node-identity.key`, mode 0600, owned by root).

When the kubelet bootstraps, it:

1. Collects software measurements of itself and key dependencies
2. Obtains a nonce from the API server (anti-replay)
3. Constructs a signed `NodeAttestationDocument`
4. Submits both the CSR and the attestation document

The KCM attestation verifier:

1. Looks up the `NodeIdentityEnrollment` for the node
2. Verifies the attestation document signature
3. Verifies the binary hashes against expected values
4. Checks the nonce (freshness)
5. If all checks pass, approves the CSR

### Why a provisioned key rather than ephemeral bootstrap?

The provisioned key binds the node identity to the act of provisioning. An attacker who obtains the bootstrap token but was not the provisioning system does not have the private key. This is the key security improvement over TOFU: the token and the key are independent secrets that must both be present on the correct node.

The private key is not hardware-protected, but it is:

- Generated locally on the node (never transmitted)
- Protected by OS DAC (root-only)
- Optionally protected by Linux kernel keyring or SELinux policy
- Tied to the node's expected software stack via the attestation document

---

## API Design

### New API Group: `attestation.kubernetes.io/v1alpha1`

The following objects are all defined in `staging/src/k8s.io/api/attestation/v1alpha1/types.go`.

---

### `NodeIdentityEnrollment`

**The guest list entry.** Created *before* a node joins, by the provisioning system (`kubeadm join`, CAPI, kOps, etc.). Tells the cluster: "I'm expecting a machine called worker-42, and it should present this public key (software mode) or these hardware characteristics (hardware mode)." One per node, named after the node. The verifier won't trust a node that has no enrollment — there is no walk-in admission.

Cluster-scoped. Transitions through phases: `Pending` (node not yet joined) → `Active` (node has bootstrapped) → `Expired` (bootstrap window closed without a join).

```go
// NodeIdentityEnrollment registers a node's identity public key and expected
// software measurements prior to the node bootstrapping.
type NodeIdentityEnrollment struct {
	metav1.TypeMeta
	metav1.ObjectMeta // Name = node name

	Spec   NodeIdentityEnrollmentSpec
	Status NodeIdentityEnrollmentStatus
}

type NodeIdentityEnrollmentSpec struct {
	// AttestationMode describes the expected attestation type.
	// "software" uses PSI; "hardware" defers to an external verifier controller.
	// +default="software"
	AttestationMode AttestationMode

	// SoftwareIdentity is populated when AttestationMode is "software".
	// Holds the provisioned public key used to verify the node's signed documents.
	// +optional
	SoftwareIdentity *SoftwareIdentitySpec

	// HardwareIdentity is populated when AttestationMode is "hardware".
	// Holds platform-specific constraints that the external verifier enforces.
	// The fields are intentionally open — each verifier interprets them according
	// to its platform (TPM EK cert fingerprint, cloud instance ID, project, zone…).
	// +optional
	HardwareIdentity *HardwareIdentitySpec

	// ExpectedMeasurements, if set, constrains the binary hashes the
	// verifier will accept. If unset, the verifier records measurements
	// on first use (TOFU for measurements, but not for identity).
	// +optional
	ExpectedMeasurements *NodeMeasurements

	// ProvisioningSource records how this enrollment was created (kubeadm,
	// CAPI, kOps, manual) for audit purposes.
	ProvisioningSource string

	// BootstrapExpiry is when this enrollment becomes invalid if the node has
	// not yet completed its first bootstrap. Applies only in the "Pending" phase.
	// Provisioning tools should set a short window (e.g. 1 hour). Once the
	// enrollment transitions to "Active", this field is no longer enforced —
	// Active enrollments persist for the lifetime of the Node object.
	// +optional
	BootstrapExpiry *metav1.Time
}

type SoftwareIdentitySpec struct {
	// PublicKey is the PEM-encoded ECDSA P-256 or Ed25519 public key generated
	// during provisioning. The corresponding private key lives on the node at
	// /var/lib/kubelet/pki/node-identity.key and is never transmitted.
	PublicKey string
}

type HardwareIdentitySpec struct {
	// Extensions holds platform-specific identity constraints in reverse-DNS
	// key format. All hardware-specific fields live here so that platform
	// verifiers can extend the schema without API changes. Examples:
	//   "cloud.google.com/instance-id":  "1234567890"
	//   "cloud.google.com/project-id":   "my-project"
	//   "azure.microsoft.com/vm-id":     "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
	//   "tpm.trusted-computing.org/ek-cert-fingerprint": "<sha256-hex>"
	// +optional
	Extensions map[string]string
}

type NodeIdentityEnrollmentStatus struct {
	// Phase is "Pending", "Active", or "Expired".
	//
	// Transitions:
	//   Pending → Active:  Set by the KCM CSR approver only after a
	//                      NodeAttestationDocument for this node reaches
	//                      Phase=Verified and the corresponding CSR is approved.
	//                      A CSR approved via the legacy token path (no AttestationRef,
	//                      permissive mode) does NOT transition the enrollment to Active
	//                      — the enrollment stays Pending until the node re-bootstraps
	//                      with attestation.
	//   Pending → Expired: Set by attestationcleaner after BootstrapExpiry passes
	//                      without the enrollment reaching Active.
	//   Active  → (none):  Active enrollments are not demoted; they persist for the
	//                      lifetime of the Node object.
	Phase EnrollmentPhase

	// LastBootstrapTime records when the node last successfully bootstrapped
	// via the attestation path (not the legacy token path).
	// +optional
	LastBootstrapTime *metav1.Time

	// NodeUID is the UID of the Node object once created.
	// +optional
	NodeUID types.UID
}
```

---

### `NodeMeasurements` (embedded struct)

**The software fingerprint.** A struct (not a standalone API object) that describes what software is actually running on the node: kubelet binary hash, container runtime hash, OS image ID, kernel version, optional IMA log, optional SLSA provenance reference, and a free-form `Extensions` map for hardware or platform-specific evidence.

Used in two places: in `NodeIdentityEnrollment.Spec.ExpectedMeasurements` (what the build system says *should* be running) and in `NodeAttestationDocument.Spec.Measurements` (what the node reports *is* running). The verifier diffs the two. Named `NodeMeasurements` rather than `SoftwareMeasurements` because hardware verifiers also use the `Extensions` map to carry platform-specific evidence (TPM EK cert fingerprint, cloud instance ID, etc.).

```go
type NodeMeasurements struct {
	// KubeletHash is the SHA-256 hex digest of the kubelet binary.
	// Computed as: sha256sum /proc/self/exe
	KubeletHash string

	// ContainerRuntimeHash is the SHA-256 hex digest of the CRI binary
	// (e.g., /usr/bin/containerd or /usr/bin/crio).
	// +optional
	ContainerRuntimeHash string

	// OSImageID is the cloud/OS image identifier from which this node was
	// booted (e.g., AMI ID, GCE image name, cloud-init image hash).
	// +optional
	OSImageID string

	// KernelVersion is the running kernel version string (uname -r).
	// +optional
	KernelVersion string

	// IMALog is a subset of the Linux IMA measurement log (ASCII format).
	// Present only if IMA is enabled on the node. The verifier SHOULD
	// validate this against the expected PCR 10 value if a TPM is also
	// present; otherwise it is recorded for audit.
	// +optional
	IMALog []byte

	// SLSAProvenanceURI is a reference to an OCI artifact or Rekor entry
	// containing the SLSA provenance for the kubelet binary.
	// The verifier fetches and validates this if set.
	// +optional
	SLSAProvenanceURI string

	// Extensions is a map for platform-specific measurements that do not
	// fit the above fields. Keys are reverse-DNS names.
	// +optional
	Extensions map[string]string
}
```

---

### `NodeAttestationChallenge`

**The one-time code.** Before a node can prove its identity, it asks the cluster for a fresh random number — a nonce. The node must sign this nonce as part of its proof packet. This prevents replay attacks: a valid proof captured from a previous bootstrap cannot be reused because the nonce it was signed against has already expired (5-minute TTL, deleted after use).

Short-lived, cluster-scoped. Created by the kubelet (using its bootstrap token) at the start of each bootstrap or rotation attempt.

```go
type NodeAttestationChallenge struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   NodeAttestationChallengeSpec
	Status NodeAttestationChallengeStatus
}

type NodeAttestationChallengeSpec struct {
	// NodeName is the node requesting a challenge.
	NodeName string

	// TTL is the requested validity window. Default: 5 minutes.
	// The API server clamps this to a server-side maximum (default: 10 minutes),
	// so clients cannot request arbitrarily long challenge windows. Values above
	// the cap are silently reduced to the cap. This prevents a long-lived nonce
	// from remaining valid long enough for an attacker to use a captured payload.
	// +default="5m"
	TTL metav1.Duration
}

type NodeAttestationChallengeStatus struct {
	// Nonce is the random challenge value the kubelet must sign.
	// Base64-encoded 32 bytes of cryptographically random data.
	Nonce string

	// ExpiresAt is when this nonce must no longer be accepted.
	ExpiresAt metav1.Time
}
```

---

### Extension: `CertificateSigningRequestSpec.AttestationRef`

**The pointer from CSR to proof.** Not a new object — a new field on the existing `CertificateSigningRequest`. When the kubelet submits its CSR it also sets this field to point at the `NodeAttestationDocument` it just submitted. The CSR approver follows the reference to find the proof before deciding whether to approve.

The existing CSR type is extended with a reference to the attestation evidence, rather than embedding the evidence directly (keeping the CSR lean).

`NodeAttestationDocument` is cluster-scoped and the CSR approver already knows to look in `attestation.kubernetes.io/v1alpha1`, so a plain string (the document name) is sufficient. Using `*corev1.ObjectReference` would add six unused fields (`Namespace`, `UID`, `APIVersion`, `ResourceVersion`, `FieldPath`, `Kind`) to every CSR object.

```go
// In CertificateSigningRequestSpec:

// attestationRef, if set, is the name of the NodeAttestationDocument the
// kubelet submitted to prove its identity. The CSR approver looks up this
// cluster-scoped document before deciding whether to approve.
// Only meaningful for kubelet client certificate CSRs.
// +optional
AttestationRef string `json:"attestationRef,omitempty"`
```

---

### `NodeAttestationDocument`

**The proof packet.** Submitted by the kubelet just before its CSR. Contains everything the verifier needs to decide whether to trust the node: the signed nonce (answering the challenge), the software measurements (kubelet hash, OS version, etc.), and the signature made with the node's private key. The verifier — built-in for software mode, an external controller for hardware mode — reads this object and stamps its `Status.Phase` as `Verified` or `Failed`. The CSR approver acts only once a terminal phase is set; it never acts while the document is still `Pending`.

Cluster-scoped. Named `<node-name>-<nonce-suffix>` to allow concurrent bootstrap retries without name collision. Deleted by `attestationcleaner` after the associated CSR reaches a terminal state (retained up to 24h for audit).

```go
// +genclient
// +genclient:nonNamespaced
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:scope=Cluster
type NodeAttestationDocument struct {
	metav1.TypeMeta
	metav1.ObjectMeta

	Spec   NodeAttestationDocumentSpec
	Status NodeAttestationDocumentStatus
}

type NodeAttestationDocumentSpec struct {
	// NodeName is the node submitting the attestation.
	NodeName string

	// ChallengeRef is the name of the NodeAttestationChallenge this document
	// answers. The nonce from that challenge must be included in SignedPayload.
	ChallengeRef string `json:"challengeRef"`

	// AttestationMode identifies which verifier should process this document.
	// Built-in: "software". External verifiers declare the modes they handle.
	AttestationMode AttestationMode

	// Measurements is the software stack evidence collected by the kubelet.
	// For hardware modes, this may be empty or contain supplemental data.
	Measurements NodeMeasurements

	// SignedPayload is a JWS (JSON Web Signature) compact serialization
	// containing: nonce, node name, measurements hash, timestamp.
	// Signed with the node identity private key (software mode) or the
	// platform attestation key (hardware modes).
	// Verifiers extract the public key from NodeIdentityEnrollment.
	SignedPayload string
}

type NodeAttestationDocumentStatus struct {
	// Phase is the lifecycle state: "Pending", "Verified", "Failed".
	// Set by the verifier (built-in or external controller).
	// The CSR approver acts only when Phase is terminal.
	Phase AttestationPhase

	// VerifiedBy identifies the verifier that processed this document.
	// For the built-in software verifier: "kubernetes.io/software-verifier".
	// Used by the CSR approver to enforce TrustedAttestationVerifiers.
	// +optional
	VerifiedBy string

	// Conditions provides structured status for the document.
	// Condition type "Verified" is the canonical approval signal.
	// Condition type "Failed" carries the failure reason in its Message field.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition
}
```

---

### `NodeAttestationPolicy`

**The cluster-wide rulebook.** A singleton object (conventional name: `cluster`) that tells the cluster how attestation should work: which mode nodes should use (`software` or `hardware`), how strictly binary hashes are enforced, whether the cluster is in migration mode (`permissive`) or fully enforcing (`enforced`). Created by `kubeadm init` and read by every subsequent `kubeadm join`. Lives in `attestation.kubernetes.io/v1alpha1` rather than inside kubeadm's own API types so it can evolve independently as the framework matures.

```go
// NodeAttestationPolicy is a cluster-scoped singleton in the
// attestation.kubernetes.io/v1alpha1 API group. Conventional name: "cluster".
//
// staging/src/k8s.io/api/attestation/v1alpha1/types.go
type NodeAttestationPolicy struct {
	metav1.TypeMeta
	metav1.ObjectMeta // conventional name: "cluster"

	Spec NodeAttestationPolicySpec
}

type NodeAttestationPolicySpec struct {
	// DefaultMode is the fallback mode for nodes that do not specify one.
	// "software" | "hardware". Omit or leave empty to disable attestation.
	// +default="software"
	DefaultMode string

	// EnforcementMode controls how the CSR approver handles CSRs from nodes
	// that have no NodeIdentityEnrollment (i.e., not yet migrated to attestation).
	//
	// "permissive": CSRs with no enrollment are approved via the existing token
	//               path with a warning event. CSRs that HAVE an enrollment but
	//               fail attestation are still denied — permissive mode is not a
	//               fallback for failed attestation, only for absent enrollment.
	// "enforced":   CSRs with no enrollment are denied; all nodes must attest.
	//               A CSR that arrives without AttestationRef but the node has an
	//               enrollment is immediately denied (no grace period).
	//
	// +default="permissive"
	EnforcementMode string

	// TrustedAttestationVerifiers is an allowlist of verifier identity strings
	// that KCM's CSR approver trusts when reading NodeAttestationDocument.Status.VerifiedBy.
	// Only documents stamped by a verifier in this list are treated as Verified.
	// Prevents a compromised external controller from self-certifying documents.
	// For the built-in software verifier the entry is "kubernetes.io/software-verifier".
	// +optional
	TrustedAttestationVerifiers []string

	// SoftwarePolicy configures the built-in software (PSI) verifier in KCM.
	// +optional
	SoftwarePolicy *SoftwareAttestationPolicy
}

type SoftwareAttestationPolicy struct {
	// measurementPolicy controls how the verifier handles binary measurements.
	//
	// "require" (default): ExpectedMeasurements must be pre-seeded (by the build
	//                      system or provisioning tool) and the reported measurements
	//                      must match exactly. Nodes with no ExpectedMeasurements fail.
	// "tofu":              Trust-On-First-Use — record measurements from the first
	//                      bootstrap and require them to match on all subsequent ones.
	//                      Acceptable for initial rollout when expected values are
	//                      not yet known; move to "require" once the fleet is stable.
	// "ignore":            Skip measurement comparison entirely. Use only when binary
	//                      integrity is enforced out-of-band.
	//
	// +default="require"
	MeasurementPolicy MeasurementPolicy

	// verifySLSAProvenance fetches and verifies SLSA provenance for the kubelet
	// binary from the SLSAProvenanceURI field in Measurements.
	// +default=false
	VerifySLSAProvenance bool

	// slsaProvenanceAllowedPrefixes, if non-empty, restricts the URI schemes and
	// registry hosts from which provenance can be fetched. Prevents SSRF attacks
	// where a node supplies a URI pointing to an internal metadata service.
	// Example: ["oci://registry.example.com/", "https://rekor.sigstore.dev/"]
	// +optional
	SLSAProvenanceAllowedPrefixes []string

	// slsaExpectedSubjectIdentity, if set, requires that the SLSA provenance
	// attestation's subject identity matches this value (e.g. signer email or
	// OIDC issuer). Prevents provenance substitution from a different build
	// pipeline that produces a binary with the same hash.
	// +optional
	SLSAExpectedSubjectIdentity string
}
```

---

### SignedPayload structure (JWS claims)

```json
{
  "iss": "kubernetes.io/node-identity/v1alpha1",
  "sub": "system:node:<node-name>",
  "iat": 1714981200,
  "exp": 1714981500,
  "nonce": "<base64-nonce-from-challenge>",
  "measurements_hash": "<sha256 of canonical JSON of Measurements struct>"
}
```

The full `Measurements` struct is submitted as a separate top-level field in
`NodeAttestationDocumentSpec.Measurements`. The `measurements_hash` in the JWS
binds the signed payload to that struct — the verifier recomputes the hash from
the struct body and rejects any mismatch. Individual measurement fields (kubelet
hash, OS image ID, etc.) are **not** repeated as separate JWS claims.

Signing algorithm: **ES256** (ECDSA P-256) or **EdDSA** (Ed25519). RSA is not supported — key sizes are too large for on-disk security without hardware sealing.

---

## Verifier Plugin Model

The `NodeAttestation` feature gate enables the framework. Which verifier processes a given `NodeAttestationDocument` is determined by `AttestationMode` in the document spec, not by the feature gate.

### Built-in verifier (software mode)

KCM ships one built-in verifier that handles `AttestationMode: "software"`. It runs in-process in the `csrapproving` controller and does not require any external deployment. This is the default when no hardware verifier is present.

### External verifier controllers (hardware and custom modes)

Hardware providers (TPM, vTPM, cloud instance identity) implement attestation as an independent Kubernetes controller that:

1. Watches `NodeAttestationDocument` objects filtered by `spec.attestationMode`
2. Performs platform-specific verification (TPM quote validation, cloud identity document check, etc.)
3. Updates `status.phase` and `status.conditions` on the document (`Verified` or `Failed`)
4. Does not need to be compiled into Kubernetes core

The CSR approver in KCM watches `NodeAttestationDocument.Status` and acts only when `Phase` reaches a terminal state. This makes external verifiers first-class participants without requiring any in-tree changes beyond the API types.

```
kubelet              API server           External hardware verifier    KCM csrapproving
  |                      |                           |                        |
  |-- POST NodeAttestationChallenge(nodeName) ------>|                        |
  |<-- challenge.status.nonce --------------------- |                        |
  |                      |                           |                        |
  |-- POST NodeAttestationDocument(mode=hardware) -->|                        |
  |                      |<-- watches mode=hardware docs                      |
  |                      |-- verify hardware evidence -->                     |
  |                      |<-- PATCH status.phase=Verified --|                 |
  |                      |                           |                        |
  |-- POST CSR (AttestationRef=doc-name) ----------->|                        |
  |                      |-- watches CSR + doc -----------------------------> |
  |                      |                               checks phase=Verified|
  |                      |<-- PATCH CSR Approved ----------------------------|
```

For the built-in software verifier, the KCM controller performs the full verify-and-approve in one pass without an intermediate status update (the document transitions directly to `Verified` within the same reconcile loop).

### Verifier registration in KCM

KCM maintains a registry of built-in verifiers, populated at startup:

```go
// AttestationVerifierRegistry maps AttestationMode to the verifier that
// handles it. The software verifier is always registered. Additional
// verifiers can be registered by out-of-tree KCM builds (e.g., cloud
// provider KCM forks) or the external controller model described above.
type AttestationVerifierRegistry struct {
    mu        sync.RWMutex
    verifiers map[AttestationMode]AttestationVerifier
}

func (r *AttestationVerifierRegistry) Register(v AttestationVerifier) {
    r.mu.Lock()
    defer r.mu.Unlock()
    r.verifiers[v.Mode()] = v
}

// Lookup returns the registered verifier for the given mode, or nil if
// no built-in verifier handles it (in which case the CSR approver defers
// to the external controller model and waits for status.phase).
func (r *AttestationVerifierRegistry) Lookup(mode AttestationMode) AttestationVerifier {
    r.mu.RLock()
    defer r.mu.RUnlock()
    return r.verifiers[mode]
}
```

The CSR approver logic becomes:

```go
func (a *sarApprover) handleAttestedCSR(ctx context.Context,
    csr *capi.CertificateSigningRequest,
    doc *attestationv1alpha1.NodeAttestationDocument) error {

    // Fast path: a built-in verifier handles this mode.
    if v := verifierRegistry.Lookup(doc.Spec.AttestationMode); v != nil {
        return v.Verify(ctx, csr, doc)
    }

    // Slow path: wait for an external controller to set status.phase.
    switch doc.Status.Phase {
    case AttestationPhaseVerified:
        // Verify the stamping controller is in the trusted allowlist (from KCM config).
        // Prevents a compromised or rogue controller from self-certifying documents.
        if !a.trustedVerifiers.Contains(doc.Status.VerifiedBy) {
            return fmt.Errorf("untrusted verifier %q set Phase=Verified on document %s; "+
                "add it to NodeAttestationPolicy.TrustedAttestationVerifiers to allow",
                doc.Status.VerifiedBy, doc.Name)
        }
        return nil
    case AttestationPhaseFailed:
        reason := ""
        for _, c := range doc.Status.Conditions {
            if c.Type == "Failed" {
                reason = c.Message
                break
            }
        }
        return fmt.Errorf("attestation failed by external verifier %s: %s",
            doc.Status.VerifiedBy, reason)
    default:
        // Pending — check whether the challenge TTL has expired.
        // If the challenge is expired and no verifier has claimed the document,
        // deny rather than requeue: there is no fallback to token approval.
        challenge, err := v.client.AttestationV1alpha1().
            NodeAttestationChallenges().Get(ctx, doc.Spec.ChallengeRef, metav1.GetOptions{})
        if err != nil || time.Now().After(challenge.Status.ExpiresAt.Time) {
            return fmt.Errorf("attestation timed out: no verifier claimed document %s within the challenge TTL", doc.Name)
        }
        // Challenge still live — requeue; the CSR approver will retry when the
        // document status changes (via informer watch).
        return errRequeue
    }
}
```

### `AttestationMode` values

| Mode | Handled by | Description |
|---|---|---|
| `software` | Built-in (KCM) | PSI: provisioned keypair + binary hashes. Default. |
| `hardware` | External controller | Any hardware-backed mechanism: TPM, vTPM, cloud identity |
| `null` | Built-in (KCM, dev/test only) | Accepts any document; records measurements; never use in production |
| _(absent)_ | — | Attestation disabled; CSR follows the legacy token path |

The mode is intentionally coarse-grained. `"hardware"` is not a routing key to a specific platform — it is the kubelet's declaration that it is submitting hardware-backed evidence. Which hardware verifier controller claims and processes the document is determined by the controller itself, using the evidence in `SignedPayload` and the `Extensions` map in `NodeMeasurements`. For example:

- A GCE verifier watches `hardware` documents where `Extensions["cloud.google.com/instance-id"]` is set
- A TPM verifier watches `hardware` documents where `Extensions["tpm.trusted-computing.org/ek-cert"]` is present
- An Azure verifier watches `hardware` documents where `Extensions["azure.microsoft.com/vm-id"]` is set

This keeps the kubelet and the API surface agnostic to platform. Swapping hardware verifier controllers requires no change to kubelet config or API types.

**Multi-verifier conflict.** If two external controllers both watch `hardware` documents (e.g., a generic TPM controller and a GCE-specific controller are both deployed), they may race to PATCH `status.phase`. The contract is: use server-side apply with a distinct field manager name per controller, and treat a document that already has a terminal `phase` as already claimed — do not overwrite it. The first controller to write `Verified` or `Failed` wins. Controllers SHOULD filter by the `Extensions` keys they recognize (e.g., only process documents where `Extensions["cloud.google.com/instance-id"]` is set) to avoid unnecessary races.

---

## Component Changes

### kubeadm

**`kubeadm init`:**

`kubeadm init` has to solve a bootstrapping problem that `kubeadm join` does not: the API server is not yet running when the control plane kubelet needs to bootstrap, so the normal "create enrollment → start kubelet" sequence cannot be followed directly. The proposed init sequence is:

1. **Generate the node identity keypair** before any Kubernetes component starts, the same way kubeadm already generates the CA and apiserver serving certs. Key written to `/var/lib/kubelet/pki/node-identity.key` (mode 0600).

2. **Start the control plane static pods** (API server, etcd, controller-manager, scheduler) as usual. No change to this phase.

3. **Wait for the local API server to become healthy** — kubeadm already has this wait loop (`waitForAPIServer`). Once healthy, perform the attestation-specific post-init steps:

   a. **POST the `NodeIdentityEnrollment`** for the control plane node, using the local admin kubeconfig (which has full cluster-admin rights). The enrollment carries the public key generated in step 1, `AttestationMode` from the `NodeAttestationPolicy` document supplied in the kubeadm config, and a short `Expiry` (e.g., 10 minutes — enough for the kubelet to complete its first CSR).

   b. **Apply RBAC** for the attestation API group. Three new ClusterRole/ClusterRoleBinding pairs, analogous to the existing `kubeadm:node-autoapprove-bootstrap` and `kubeadm:get-nodes` objects:
      - `kubeadm:attestation-bootstrap` — grants bootstrap token users `create` on `nodeidentityenrollments` and `nodeattestationchallenges`, and `get` on `nodeattestationpolicies`. This is how joining nodes create their enrollment and challenge.
      - `kubeadm:attestation-node` — grants `system:nodes` group `get`/`watch` on `nodeattestationchallenges` (their own only, enforced by node authorizer), and `create`/`update` on `nodeattestationdocuments`. This covers the kubelet's runtime access after initial bootstrap.
      - `kubeadm:attestation-nodeclient` — grants `system:bootstrappers` group `create` on `certificatesigningrequests` with subresource `attestednodeclient`, so that the first attested CSR is auto-approved. Analogous to the existing `kubeadm:node-autoapprove-bootstrap` binding for the `nodeclient` subresource.

4. **The control plane kubelet** then performs its normal TLS bootstrap. Because the `NodeIdentityEnrollment` is already present in the API server, the kubelet's `RequestNodeCertificate` call will take the attestation path and attach an `AttestationRef` to its CSR. The KCM software verifier approves it.

The net result is that `kubeadm init` front-loads the enrollment creation (using local admin credentials) while `kubeadm join` creates its own enrollment (using a bootstrap token), but the kubelet-side flow and the KCM approval path are identical for both cases.

**`kubeadm join`:**

1. Fetches the cluster CA and reads `NodeAttestationPolicy` from the API server using the cluster-join bootstrap token
2. Generates a new ECDSA P-256 or Ed25519 keypair; writes both files to disk immediately (`/var/lib/kubelet/pki/node-identity.key` mode 0600, `/var/lib/kubelet/pki/node-identity.pub` mode 0644)
3. If no `NodeIdentityEnrollment` already exists for this node name: requests a short-lived, **node-scoped enrollment token** from the API server. This token carries only `create` permission on `NodeIdentityEnrollments` scoped to this specific node name — it cannot create enrollments for other nodes and cannot be reused. Uses this token to create the enrollment with the public key from step 2, `AttestationMode` from `NodeAttestationPolicy`, and `BootstrapExpiry` = now + 1 hour. If an enrollment already exists (pre-created by provisioning system), step 3 is skipped entirely.
4. Calls the standard kubelet bootstrap flow (kubeconfig + cert generation); the kubelet reads the private key written in step 2 and attests during its first CSR

**Enrollment creation — security tradeoff:**

With the flow above the node creates its own enrollment. An admin does not need to do anything extra. However, this means the node registers its own public key using the bootstrap token — an attacker with the token could register a key they control and pass attestation. This is still better than today (token alone was sufficient), but it is not the strongest possible model.

The stronger model is **pre-created enrollment**: the provisioning system (CAPI, Karpenter, kOps) creates the `NodeIdentityEnrollment` *before* the VM exists, generating the keypair itself and injecting the private key into the VM image or via a secure channel. The node can then only prove it received the intended key — it cannot substitute a different one. When `kubeadm join` detects an existing enrollment for the node name, it skips step 3 and uses the pre-created enrollment as-is.

| Who creates the enrollment | Who controls the key | Requires admin action per node |
|---|---|---|
| `kubeadm join` (current default) | The joining node | No |
| Provisioning system (CAPI/Karpenter/kOps) | The provisioning system | No (automated) |
| Admin pre-creates manually | The admin | Yes |

For autoscaling groups where many nodes share a common image, the provisioning system approach is both more secure and more practical. See Open Question 4.

The bootstrap token is now used only to:
- Fetch the cluster CA and `NodeAttestationPolicy`
- Create the `NodeIdentityEnrollment`
- NOT to approve the CSR — the attestation document approves the CSR

**Node name binding.** The `NodeIdentityEnrollment` name and the JWS `sub` claim must exactly match the node name the kubelet will register with. kubeadm derives this from `--node-name` if set, otherwise from the system hostname. If `--hostname-override` is passed to the kubelet independently, it must match what kubeadm used — a mismatch causes the verifier lookup to fail (enrollment not found).

**Node attestation adds no new fields to kubeadm's own API types.**

`ClusterConfiguration` and `JoinConfiguration` are unchanged. Embedding alpha structs inline would couple kubeadm's stable API to a WIP (`v1alpha1`) group — the same problem kubeadm already solved for `KubeletConfiguration` and `KubeProxyConfiguration`.

The feature is activated entirely by including a `NodeAttestationPolicy` document in the kubeadm config file's multi-document YAML. If no such document is present the attestation flow is never triggered:

- **kubeadm init** detects the `NodeAttestationPolicy` document in the config file, applies it to the cluster after the API server is healthy (same phase as `kube-proxy`/`CoreDNS` ConfigMaps), and generates a per-node identity keypair.
- **kubeadm join** reads the `NodeAttestationPolicy` from the cluster via the scoped bootstrap token before generating the node keypair. If no policy exists in the cluster, join proceeds on the legacy token-only path.

#### `NodeAttestationPolicy` in kubeadm config

The full `NodeAttestationPolicy` struct is defined in the [API Design section](#nodeattestationpolicy).

A kubeadm config file with node attestation enabled:

```yaml
---
apiVersion: kubeadm.k8s.io/v1beta4
kind: ClusterConfiguration
# No attestation fields here — feature is activated by the document below.
# ... other fields ...
---
apiVersion: attestation.kubernetes.io/v1alpha1
kind: NodeAttestationPolicy
metadata:
  name: cluster
spec:
  defaultMode: software
  softwarePolicy:
    measurementPolicy: require
    verifySLSAProvenance: false
```

`kubeadm init` applies the `NodeAttestationPolicy` document after the API server becomes healthy. `kubeadm join` reads it via the bootstrap token before generating the keypair.

### kubelet — `pkg/kubelet/certificate/bootstrap/`

**New file: `pkg/kubelet/certificate/bootstrap/attestation.go`**

Responsibilities:
1. Detect and read the node identity private key (`/var/lib/kubelet/pki/node-identity.key`)
2. Collect `NodeMeasurements`:
   - Hash own binary: `sha256sum /proc/self/exe`
   - Hash CRI socket owner binary (via `/proc/$(pidof containerd)/exe` or config)
   - Read `os-release` for OS image ID
   - Read `/proc/version` for kernel version
   - Read IMA measurement log from `/sys/kernel/security/ima/ascii_runtime_measurements` if available
   - Read SLSA provenance from OCI registry if configured
3. Request a `NodeAttestationChallenge` from the API server
4. Construct and sign the `NodeAttestationDocument` JWS payload
5. Submit the `NodeAttestationDocument` to the API server
6. Add `AttestationRef` to the CSR before submission

**Modified: `pkg/kubelet/certificate/bootstrap/bootstrap.go`**

The `RequestNodeCertificate` function is extended: if a node identity key is present on disk, attestation is performed before the CSR is submitted. If the key is absent, the kubelet falls back to the legacy token-only path silently — no configuration field controls this; key presence is the sole activation signal.

**New kubelet config field (`KubeletConfiguration`):**

```go
// NodeIdentityKeyFile is the path to the ECDSA/Ed25519 private key used
// for software attestation. Defaults to /var/lib/kubelet/pki/node-identity.key.
// Attestation is activated solely by the presence of this key file on disk —
// no separate mode field is needed. If the file is absent, the kubelet falls
// back to the legacy token-only path silently.
// +optional
NodeIdentityKeyFile string
```

### kube-controller-manager — `pkg/controller/certificates/approver/`

**New file: `pkg/controller/certificates/approver/attestation_verifier.go`**

Defines the verifier interface (shared with hardware attestation path):

```go
// AttestationVerifier verifies a NodeAttestationDocument before a CSR is approved.
// Implementations are registered per AttestationMode.
type AttestationVerifier interface {
	// Verify checks the attestation document for the given CSR.
	// It returns nil if attestation is valid and the CSR should be approved.
	Verify(ctx context.Context, csr *capi.CertificateSigningRequest, doc *attestationv1alpha1.NodeAttestationDocument) error

	// Mode returns the AttestationMode this verifier handles.
	Mode() string
}
```

**Software verifier implementation:**

```go
type softwareAttestationVerifier struct {
	client clientset.Interface
	policy *SoftwareAttestationPolicy
}

func (v *softwareAttestationVerifier) Verify(ctx context.Context,
	csr *capi.CertificateSigningRequest,
	doc *attestationv1alpha1.NodeAttestationDocument) error {

	// 1. Fetch NodeIdentityEnrollment for this node
	enrollment, err := v.client.AttestationV1alpha1().
		NodeIdentityEnrollments().Get(ctx, doc.Spec.NodeName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("enrollment not found for node %s: %w", doc.Spec.NodeName, err)
	}

	// 2. Validate mode consistency — reject if the node chose a different mode
	// than the enrollment specifies. Prevents mode confusion attacks.
	if doc.Spec.AttestationMode != enrollment.Spec.AttestationMode {
		return fmt.Errorf("mode mismatch: document claims %q but enrollment requires %q",
			doc.Spec.AttestationMode, enrollment.Spec.AttestationMode)
	}

	// 3. Check bootstrap expiry (only enforced while enrollment is Pending)
	if enrollment.Status.Phase == EnrollmentPhasePending &&
		enrollment.Spec.BootstrapExpiry != nil &&
		time.Now().After(enrollment.Spec.BootstrapExpiry.Time) {
		return fmt.Errorf("enrollment for node %s has expired", doc.Spec.NodeName)
	}

	// 4. Verify JWS signature using enrollment public key
	if enrollment.Spec.SoftwareIdentity == nil {
		return fmt.Errorf("enrollment for node %s has no SoftwareIdentity", doc.Spec.NodeName)
	}
	if err := verifyJWS(doc.Spec.SignedPayload, enrollment.Spec.SoftwareIdentity.PublicKey); err != nil {
		return fmt.Errorf("attestation signature invalid: %w", err)
	}

	// 5. Verify nonce against challenge; cross-check NodeName binding.
	// Challenge is deleted immediately after verification — single-use.
	challenge, err := v.client.AttestationV1alpha1().
		NodeAttestationChallenges().Get(ctx, doc.Spec.ChallengeRef, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("challenge not found: %w", err)
	}
	if challenge.Spec.NodeName != doc.Spec.NodeName {
		return fmt.Errorf("challenge node name mismatch: challenge issued for %q but document claims %q",
			challenge.Spec.NodeName, doc.Spec.NodeName)
	}
	if time.Now().After(challenge.Status.ExpiresAt.Time) {
		return fmt.Errorf("challenge nonce expired")
	}
	if !nonceMatches(doc.Spec.SignedPayload, challenge.Status.Nonce) {
		return fmt.Errorf("nonce mismatch")
	}
	// Delete the challenge immediately — it must never be reused.
	if derr := v.client.AttestationV1alpha1().
		NodeAttestationChallenges().Delete(ctx, challenge.Name, metav1.DeleteOptions{}); derr != nil {
		klog.Warningf("failed to delete used challenge %s: %v", challenge.Name, derr)
	}

	// 6. Cross-check measurements_hash binding: the hash in the JWS payload must
	// equal sha256(canonical JSON of doc.Spec.Measurements). This prevents a node
	// from submitting a signed payload with one measurement set while the document
	// body carries a different, potentially forged, measurement struct.
	measHash, err := extractMeasurementsHash(doc.Spec.SignedPayload)
	if err != nil {
		return fmt.Errorf("cannot extract measurements_hash from JWS: %w", err)
	}
	if expected := sha256CanonicalJSON(doc.Spec.Measurements); measHash != expected {
		return fmt.Errorf("measurements_hash mismatch: JWS claims %s but Measurements hash to %s",
			measHash, expected)
	}

	// 7. Verify binary measurements per MeasurementPolicy.
	if enrollment.Spec.ExpectedMeasurements != nil {
		if err := verifyMeasurements(doc.Spec.Measurements,
			*enrollment.Spec.ExpectedMeasurements, v.policy); err != nil {
			return fmt.Errorf("measurement mismatch: %w", err)
		}
	} else {
		switch v.policy.MeasurementPolicy {
		case MeasurementPolicyTOFU:
			recordMeasurements(ctx, v.client, enrollment, doc.Spec.Measurements)
		case MeasurementPolicyIgnore:
			// no-op
		default: // "require"
			return fmt.Errorf("no expected measurements set and MeasurementPolicy is %q", v.policy.MeasurementPolicy)
		}
	}

	// 8. Optionally verify SLSA provenance.
	// SLSAProvenanceURI is validated against the allowlist in SoftwareAttestationPolicy
	// before any network fetch to prevent SSRF attacks.
	if v.policy.VerifySLSAProvenance && doc.Spec.Measurements.SLSAProvenanceURI != "" {
		if err := verifySLSAProvenance(ctx, doc.Spec.Measurements, v.policy); err != nil {
			return fmt.Errorf("SLSA provenance verification failed: %w", err)
		}
	}

	return nil
}
```

**Modified: `pkg/controller/certificates/approver/sarapprove.go`**

The `handle` function is extended to check for `AttestationRef` on the CSR. If present, it calls the registered verifier before proceeding to the SAR check. If the verifier fails, the CSR is denied (not just unapproved).

**CSR behavior when `AttestationRef` is absent but an enrollment exists:**

If a CSR arrives with no `AttestationRef` field set, the approver looks up whether a `NodeIdentityEnrollment` exists for the requesting node:

- **Enrollment exists + `enforced` mode:** CSR is immediately denied. The node is enrolled and must attest; presenting no evidence is not a valid alternative. No grace period, no fallback. The denial message indicates the node should re-bootstrap with attestation.
- **Enrollment exists + `permissive` mode:** CSR is also denied. `permissive` mode allows the legacy token path only for nodes with *no enrollment at all*. Once enrolled, a node must use the attestation path.
- **No enrollment + `permissive` mode:** CSR proceeds via the legacy token path (existing behavior) with a warning event logged.
- **No enrollment + `enforced` mode:** CSR is denied; all nodes must be enrolled before joining.

The existing `recognizers()` function gains a new recognizer:

```go
{
	recognize:  isAttestedNodeClientCert,
	permission: authorization.ResourceAttributes{
		Group:       "certificates.k8s.io",
		Resource:    "certificatesigningrequests",
		Verb:        "create",
		Subresource: "attestednodeclient", // new subresource
		Version:     "*",
	},
	successMessage: "Auto approving kubelet client certificate after attestation verification.",
},
```

The new signer name for attested bootstrap CSRs is `kubernetes.io/kube-apiserver-client-kubelet-attested`, a distinct name from the existing token-based signer. This allows policy to require attestation on clusters that enforce it.

### API Server

- Serves the new `attestation.kubernetes.io/v1alpha1` API group, **gated behind the `NodeAttestation` feature gate** — the group is not registered when the gate is off
- Enforces RBAC: only system bootstrap users (authenticated with a bootstrap token) can create `NodeIdentityEnrollments` and `NodeAttestationChallenges`; only the node itself can read its own challenge after bootstrap
- Restricts `list` on `NodeAttestationChallenges` — nodes may only `get` their own challenge, not enumerate all live challenges (prevents nonce harvesting by a compromised node)
- Clamps `NodeAttestationChallenge.Spec.TTL` to the server-configured maximum (default 10 minutes) at write time via an admission webhook or strategy defaulting
- Validates `NodeIdentityEnrollment.Spec.AttestationMode` at admission: `"null"` mode is rejected unless the cluster-level `NodeAttestationPolicy` explicitly permits it (i.e., `allowNullMode: true` in the policy). This prevents enrollments that bypass all verification from being created in production clusters
- Auto-deletes `NodeAttestationChallenges` after TTL (via a garbage-collection controller, similar to `tokencleaner`)
- Auto-expires `NodeIdentityEnrollments` via `tokencleaner`-style controller

### New controller: `attestationcleaner`

A new controller in KCM, analogous to `pkg/controller/bootstrap/tokencleaner.go`, that:

- Deletes expired `NodeAttestationChallenges`
- Transitions `NodeIdentityEnrollments` to `Expired` phase after `BootstrapExpiry` passes without a successful bootstrap (phase never leaving `Pending`)
- Deletes `NodeAttestationDocument` objects once their associated CSR reaches a terminal state (`Approved` or `Denied`), or after a configurable retention window (default 24h) for audit purposes
- Optionally deletes `Active` enrollments for nodes that have been deleted from the cluster (opt-in; disabled by default to avoid accidental data loss during node churn)

---

## Threat Model

### T1: Bootstrap token theft (PARTIALLY MITIGATED)

An attacker who obtains the bootstrap token cannot complete attestation without the node identity private key **if** the enrollment was pre-created by the provisioning system. In that case, the attacker's `create` call for `NodeIdentityEnrollment` fails (already exists), and they cannot sign a valid document for the pre-enrolled key.

In the default `kubeadm join` flow (node creates its own enrollment), token theft plus active exploitation during the bootstrap window is sufficient — see T6.

**Residual risk:** If the attacker also obtains the private key (root access to the node before it has been provisioned), they can impersonate the node regardless of enrollment model. This is substantially harder than token theft alone.

### T2: Node identity key theft (PARTIALLY MITIGATED)

If an attacker gains root access to the node and extracts `/var/lib/kubelet/pki/node-identity.key`, they can impersonate that node indefinitely — until the enrollment is revoked or expires.

**Mitigation:** Short enrollment expiry (default 1 hour). Once the node has bootstrapped, the enrollment is marked `Active` and the private key's only remaining use is certificate rotation. Operators can configure KCM to reject attestation documents from already-active nodes (requiring re-enrollment to rotate credentials).

**Recommendation:** On platforms where a TPM or Linux kernel keyring is available, the private key should be sealed/protected by that mechanism. The software verifier works with either a filesystem key or a TPM-sealed key — this is an orthogonal concern.

### T3: Measurement forgery (PARTIALLY MITIGATED)

An attacker with root access to the node can replace the kubelet binary and forge the measurement hash. There is no hardware seal preventing this in the pure software path.

**Mitigation:** If `MeasurementPolicy: "require"`, the expected hash is populated by the build/provisioning system and not derived from the node itself. An attacker replacing the binary would fail hash verification. However, an attacker who also controls the provisioning path can update the expected hash.

**Mitigation (deeper):** SLSA provenance verification (`VerifySLSAProvenance = true`) adds an independent, external check via the Rekor transparency log. The kubelet binary must be in the build transparency log with a valid SLSA provenance chain. This is not bypassable without a supply-chain compromise of the build pipeline.

### T4: Replay attack (MITIGATED)

Nonces from `NodeAttestationChallenge` are single-use with a 5-minute TTL. The challenge is deleted after use. Replaying a captured attestation document after the nonce expires fails verification.

### T5: Race condition — multiple nodes sharing an enrollment (MITIGATED)

`NodeIdentityEnrollment` is 1:1 with a node (named after the node). The enrollment transitions to `Active` on first successful bootstrap. Subsequent bootstrap attempts with the same enrollment for a different node identity fail (node name mismatch in the JWS subject).

### T6: Enrollment spoofing (PARTIALLY MITIGATED)

An attacker who obtains a bootstrap token can create a `NodeIdentityEnrollment` with a public key they control, then submit a valid attestation document signed with the matching private key. This attack is only possible in the default `kubeadm join` flow where the joining node creates its own enrollment — it requires active exploitation during the bootstrap window, not just passive token theft.

**Residual risk in the default flow:** Because the joining node creates its own enrollment, bootstrap token theft is still sufficient for an attacker to impersonate a node (by registering their own key before the legitimate node does). This is better than today (token alone sufficed, no timing requirement), but it is not eliminated.

**Stronger model (pre-created enrollment):** When the provisioning system creates the `NodeIdentityEnrollment` before the node exists, the attacker cannot register a different key — the enrollment is already present and the joining node's `create` call would fail with a conflict. `kubeadm join` detects an existing enrollment and skips key creation. This model eliminates T6 entirely.

**Default hardening in kubeadm:** `kubeadm join` uses a short-lived, node-scoped bootstrap token that carries only `create` permission on `NodeIdentityEnrollments` for the specific node name. This token is distinct from the cluster-join token and cannot be reused to enroll a different node. See the enrollment creation tradeoff table in the kubeadm section.

### T7: Mode confusion — node selects its own verifier (MITIGATED by design)

If a joining node could declare `AttestationMode: "hardware"` while the cluster policy is `"software"`, it could route its document to a non-existent or weaker verifier. If no hardware verifier controller is deployed, the document would sit `Pending` until the external verifier timeout fires and the CSR is denied. However, the risk exists if any code path silently falls back to token-based approval on timeout — which this design explicitly prohibits.

**Mitigation:** The attestation mode is determined exclusively by the server-side `NodeAttestationPolicy`, not by anything the joining node supplies. `JoinConfiguration` does not expose a mode override. The KCM verifier additionally cross-checks that `NodeAttestationDocument.Spec.AttestationMode` matches `NodeIdentityEnrollment.Spec.AttestationMode` — a mismatch is an immediate failure, not a fallback.

### T8: Software supply chain compromise (PARTIALLY MITIGATED with SLSA)

If the kubelet binary is backdoored before distribution, the compromised binary runs on all nodes. The SLSA provenance check verifies the build provenance in a transparency log — a backdoored binary built outside the official pipeline will not have a valid provenance entry. This is only as strong as the build pipeline and the transparency log's inclusion guarantee.

---

## Comparison: Software PSI vs. Hardware TPM Attestation

| Property | Software PSI | Hardware TPM |
|---|---|---|
| Key extraction resistance | OS-level (root can extract) | Hardware-level (never extractable) |
| Measurement forgery resistance | Policy-enforced + SLSA | Hardware PCR sealing |
| Replay resistance | Nonce-based (5 min TTL) | TPM quote with nonce |
| Platform requirements | Any Linux/Windows node | TPM 2.0 chip or vTPM |
| Zero-config platforms | All | Cloud VMs (GCE Shielded, Azure Trusted Launch, Nitro) |
| Implementation complexity | Low (pure Go, no kernel drivers) | Medium (TPM2 library, PCR policy) |
| Upgrade path to hardware | Yes — same verifier interface | N/A |

Software PSI is designed to be the floor, not the ceiling. Clusters that adopt PSI today can switch to hardware attestation by changing `AttestationMode: "hardware"` and deploying a hardware verifier controller, with no changes to the API surface or enrollment workflow.

---

## Implementation Phases

The single `NodeAttestation` feature gate gates the entire framework. Phases reflect framework maturity, not per-verifier maturity — hardware verifier controllers follow their own graduation independently.

### Phase 0 (prerequisite — fits within WG Node Identity Phase 1)

- Define `attestation.kubernetes.io/v1alpha1` API types
- Extend `CertificateSigningRequestSpec` with `AttestationRef`
- Define the `AttestationVerifier` interface and `AttestationVerifierRegistry`
- Define the external verifier controller contract (`NodeAttestationDocument.Status`)
- Produce threat model (this document)

### Phase 1 — Alpha (feature gate `NodeAttestation`)

- `NodeAttestation` feature gate added to kubelet, KCM, and kubeadm; disabled by default
- Built-in software (PSI) verifier and null verifier shipped with KCM
- kubeadm keypair generation in `kubeadm join` when gate is enabled
- Kubelet measurement collection (`attestation.go`)
- `attestationcleaner` controller for challenge/enrollment GC
- External verifier controller contract documented; no in-tree hardware verifiers yet
- E2E tests using the null verifier (no hardware dependency in CI)

### Phase 2 — Beta

- `NodeAttestation` feature gate enabled by default
- `MeasurementPolicy: "require"` (default) with expected measurements populated by kubeadm from image metadata; `"tofu"` available for initial rollout
- SLSA provenance verification (optional, requires sigstore integration)
- IMA log submission and recording
- Windows support (measurement collection from PE hash, no IMA)
- At least one external hardware verifier (e.g., `cloud-gce` or `tpm`) implemented out-of-tree and validated against the interface
- Multi-distribution testing (minimum 2)

### Phase 3 — GA

- `NodeAttestation` feature gate locked on; `AttestationMode: "software"` as default; `"hardware"` available once at least one external verifier controller ships
- Conformance tests covering the framework contract for both built-in and external verifiers
- Graduation independent of any specific hardware verifier reaching GA

---

## Key File Locations (existing k8s codebase)

| Purpose | Path |
|---|---|
| CSR approval controller | `pkg/controller/certificates/approver/sarapprove.go` |
| Kubelet bootstrap | `pkg/kubelet/certificate/bootstrap/bootstrap.go` |
| Bootstrap token cleaner (model for attestation cleaner) | `pkg/controller/bootstrap/tokencleaner.go` |
| CSR types | `pkg/apis/certificates/types.go` |
| Kubelet certificate manager | `pkg/kubelet/certificate/kubelet.go` |

New files to create:

| File | Description |
|---|---|
| `pkg/controller/certificates/approver/attestation_verifier.go` | Verifier interface + software implementation |
| `pkg/kubelet/certificate/bootstrap/attestation.go` | Measurement collection + document signing |
| `pkg/controller/attestation/cleaner.go` | Challenge/enrollment GC controller |
| `staging/src/k8s.io/api/attestation/v1alpha1/types.go` | API types |
| `cmd/kube-controller-manager/app/attestation.go` | Controller registration |

---

## Certificate Rotation

Certificate rotation reuses the same node identity key and enrollment established at bootstrap — no re-enrollment is needed.

When the kubelet's client cert approaches expiry, `pkg/kubelet/certificate/kubelet.go` initiates rotation by submitting a new CSR. The flow is:

1. Kubelet requests a new `NodeAttestationChallenge` using its existing (still-valid) client cert — no bootstrap token needed at this stage
2. Kubelet signs a new `NodeAttestationDocument` with the node identity private key (same key as bootstrap)
3. New CSR is submitted with `AttestationRef` pointing to the new document
4. KCM software verifier: looks up the `Active` enrollment, verifies the JWS signature, checks the nonce, optionally re-checks binary hashes — then approves

The `NodeIdentityEnrollment` is not re-created. `BootstrapExpiry` is not re-enforced (it only applies in the `Pending` phase). The enrollment persists as long as the `Node` object exists.

**Key rotation (atomic procedure).** The node identity private key itself is long-lived by design. If an operator suspects the key is compromised, the procedure must be *atomic* — deleting the old enrollment before the new one is ready creates a window where the node cannot attest at all:

1. **Pre-stage the new enrollment:** Generate a new keypair locally. Create a new `NodeIdentityEnrollment` named `<node-name>-pending` with the new public key, `phase: Pending`, and a short `BootstrapExpiry`.
2. **Swap on the node:** Write the new private key to a temporary path. Perform an atomic rename to `/var/lib/kubelet/pki/node-identity.key` so the node is never without a usable key.
3. **Atomically replace the enrollment:** Update the existing `NodeIdentityEnrollment` for the node (using server-side apply) to replace `SoftwareIdentity.PublicKey` with the new public key, or create a new enrollment and delete the old one in a single transaction (etcd conditional delete + create). The KCM verifier will accept the new key for the next attestation round.
4. **Trigger a kubelet restart** — the kubelet detects the new key and re-attests. The cert rotation path handles this without a full node drain.
5. **Clean up** the `<node-name>-pending` enrollment if the staged approach was used.

This is analogous to rotating an SSH host key — disruptive but well-defined. The atomic replacement in step 3 ensures no bootstrap attempt during rotation is silently approved against a stale key.

---

## Upgrade Path

Existing clusters that bootstrapped with token-based CSR approval have no `NodeIdentityEnrollment` objects and no node identity keys on disk. The framework supports a **permissive migration mode** to allow gradual rollout without draining nodes.

The `EnforcementMode` field on `NodeAttestationPolicy` (defined in the [API Design section](#nodeattestationpolicy)) controls migration behaviour:

- `"permissive"` — CSRs from nodes with **no enrollment** proceed via the legacy token path with a warning. CSRs from nodes that **have** an enrollment but present no `AttestationRef` are denied. This is not a fallback for failed attestation.
- `"enforced"` — CSRs with no enrollment are denied; all nodes must attest.

**Migration procedure for an existing cluster:**

1. Enable the `NodeAttestation` feature gate on the API server and KCM (kubelet gate is not needed yet)
2. Apply a `NodeAttestationPolicy` with `enforcementMode: permissive` — existing nodes continue to renew certs via the token path without interruption
3. For each node being replaced or restarted: generate a keypair, create a `NodeIdentityEnrollment`, restart kubelet — the node re-bootstraps via the attestation path
4. Once all nodes appear in `kubectl get nodeidentityenrollments` with `phase: Active`, switch `enforcementMode` to `enforced`
5. Enable the `NodeAttestation` gate on kubeadm for future `kubeadm join` invocations

Nodes that have not yet been migrated continue working in permissive mode. The presence of the node identity key file (`NodeIdentityKeyFile` in `KubeletConfiguration`, defaulting to `/var/lib/kubelet/pki/node-identity.key`) is the sole signal that controls whether the kubelet attempts attestation — no separate mode field is needed.

---

## Open Questions

1. **Key storage on Windows.** Linux has `/proc/self/exe` and optionally the kernel keyring. Windows has DPAPI and the TPM CNG provider. Should the software path on Windows use DPAPI to protect the identity key? This makes key extraction require a valid Windows user session, not just a file copy.

2. **Measurement collection for static pods.** The control plane runs as static pods managed by kubelet. Should kubelet attest the kube-apiserver/etcd/kube-controller-manager binaries as well? This would strengthen the software measurement, but adds complexity and breaks if pods are OCI-based (binary is inside a container image layer).

3. **SLSA provenance transport.** Should the `SLSAProvenanceURI` be an OCI reference to a Rekor entry, or a direct OCI artifact attachment? OCI artifact attachments (sigstore `cosign attest`) are more standard but require registry access from the KCM. Rekor entries require Rekor API access.

4. **Enrollment creation RBAC.** In the current design, a bootstrap token creates the enrollment. Should there be a dedicated `kubeadm join controller` (running in-cluster) that creates enrollments on behalf of Machines, removing the need for the joining node to have create permissions at all? This would fully decouple provisioning from the node's own credentials.

5. **Certificate rotation.** The design covers initial bootstrap. For certificate rotation, the node already holds a valid client cert, so the signed attestation document can be signed with the current client private key rather than the node identity key. Should the attestation document be re-verified on every rotation, or only on initial bootstrap?

6. **Revocation.** If the node identity key is suspected compromised, the operator deletes the `NodeIdentityEnrollment`. The node's existing cert remains valid until expiry (standard Kubernetes certificate lifecycle). Should deletion of the enrollment trigger certificate revocation? This requires the Kubernetes CRL/OCSP work, which is a separate effort.

7. **External verifier timeout.** When the CSR approver is waiting for an external hardware verifier to stamp `NodeAttestationDocument.Status`, how long should it wait before treating the document as failed? A fixed timeout (e.g., 2 minutes) is simple but may be too short for slow TPM operations. A configurable timeout per `AttestationMode` is more flexible. Should the timeout be expressed on the `NodeAttestationChallenge` TTL, or as a separate field on `NodeIdentityEnrollment`?

8. **Evidence collection for `"hardware"` mode.** When `AttestationMode: "hardware"` is set, the kubelet does not know in advance which external verifier controller will claim its document. Should it collect all available hardware evidence (TPM quote, cloud identity document, IMA log) and let the verifier ignore what it does not need? Or should there be a discovery step — a `NodeAttestationVerifierCatalog` object listing which `Extensions` keys registered controllers consume — so the kubelet can collect only the relevant evidence and avoid unnecessary overhead?

---

## Relationship to WG Node Identity Deliverables

| WG Deliverable | This Document's Contribution |
|---|---|
| Node Attestation KEP (SIG Auth) | Defines the `attestation.kubernetes.io` API; software verifier is one implementation of the verifier interface |
| Kubelet Bootstrap Changes KEP (SIG Node) | Kubelet measurement collection and `AttestationRef` in CSR |
| Kubeadm Attestation Integration KEP (SIG Cluster Lifecycle) | Keypair generation in `kubeadm join`; enrollment lifecycle |
| Threat Model | Section above; feeds into the shared threat model document |
| Reference Attestation Verifier | Software verifier + null verifier serve as the reference implementations |
| Conformance Test Suite | Software path is the testable path on all CI environments (no TPM required) |

---

## Summary

The `NodeAttestation` feature gate enables a unified attestation framework for Kubernetes. The key design decisions:

- **One gate, many verifiers.** `NodeAttestation` controls whether the framework is active. Which verifier runs is determined by `AttestationMode` in config and which verifier controllers are deployed — not by the gate.
- **Software attestation (PSI) is the built-in default.** It requires no hardware and no external deployment. Every cluster gets a meaningful improvement over TOFU tokens the moment the gate is enabled.
- **Hardware verifiers are external controllers.** They watch `NodeAttestationDocument` objects, perform platform-specific verification, and stamp `Status.Phase`. KCM's CSR approver is agnostic to the verification mechanism — it only cares about the terminal status. This keeps hardware complexity entirely out of Kubernetes core.
- **The API surface is stable across modes.** A cluster that starts with software attestation and later adopts a TPM verifier changes `AttestationMode` in KubeletConfiguration and deploys the verifier controller. No API migration needed.
- **The provisioned keypair is the root of the software path.** Private key on the node, public key enrolled before bootstrap. This converts TOFU from "anyone with the token can join as any node" to "only the provisioned node, holding the private key generated during provisioning, can join as this node." Hardware verifiers replace the keypair with a hardware trust anchor; the enrollment and challenge/nonce machinery remains identical.
