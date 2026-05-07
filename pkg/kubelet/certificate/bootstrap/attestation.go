package bootstrap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	jose "gopkg.in/go-jose/go-jose.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	attestationv1alpha1 "k8s.io/api/attestation/v1alpha1"
	clientset "k8s.io/client-go/kubernetes"
)

const (
	defaultNodeIdentityKeyFile = "/var/lib/kubelet/pki/node-identity.key"
	defaultChallengeTTL        = 5 * time.Minute
)

// AttestationConfig holds the kubelet-side attestation configuration.
type AttestationConfig struct {
	// NodeIdentityKeyFile is the path to the ECDSA private key.
	// Defaults to /var/lib/kubelet/pki/node-identity.key.
	NodeIdentityKeyFile string
	// NodeName is the node name the kubelet will register with.
	NodeName string
	// NodeIP is the primary IP address of the node (from --node-ip or auto-detected).
	// When set, it is embedded in the JWS as a node_ip claim so the server can
	// optionally enforce that enrollment.ExpectedNodeIP matches.
	NodeIP string
}

func (c *AttestationConfig) keyFile() string {
	if c.NodeIdentityKeyFile != "" {
		return c.NodeIdentityKeyFile
	}
	return defaultNodeIdentityKeyFile
}

// AttestationResult is returned by PerformAttestation on success.
type AttestationResult struct {
	// DocumentName is the name of the NodeAttestationDocument created in the API server.
	DocumentName string
}

// PerformAttestation runs the full attestation flow for a node bootstrap or rotation:
//  1. Collect software measurements
//  2. Request a NodeAttestationChallenge
//  3. Sign the JWS payload
//  4. Submit the NodeAttestationDocument
//
// Returns the document name to embed in the CSR AttestationRef field, or an error.
// If the node identity key file does not exist, returns ("", nil) — callers should
// skip attestation and fall back to the legacy token path.
func PerformAttestation(ctx context.Context, client clientset.Interface, cfg AttestationConfig) (*AttestationResult, error) {
	keyFile := cfg.keyFile()

	// Check whether the identity key is present on disk.
	// Absence means the node was not provisioned for attestation.
	privKey, err := loadPrivateKey(keyFile)
	if err != nil {
		if os.IsNotExist(err) {
			klog.V(4).Infof("attestation: identity key %s not found; skipping attestation", keyFile)
			return nil, nil
		}
		return nil, fmt.Errorf("attestation: failed to load identity key %s: %w", keyFile, err)
	}

	// Collect software measurements.
	measurements, err := collectMeasurements()
	if err != nil {
		return nil, fmt.Errorf("attestation: failed to collect measurements: %w", err)
	}

	// Request a NodeAttestationChallenge (nonce) from the API server.
	challenge, err := requestChallenge(ctx, client, cfg.NodeName)
	if err != nil {
		return nil, fmt.Errorf("attestation: failed to request challenge: %w", err)
	}

	// Compute the measurements hash to bind into the JWS.
	measHash, err := hashMeasurements(measurements)
	if err != nil {
		return nil, fmt.Errorf("attestation: failed to hash measurements: %w", err)
	}

	// Sign the JWS payload.
	signedPayload, err := signAttestationPayload(privKey, cfg.NodeName, cfg.NodeIP, challenge.Status.Nonce, measHash)
	if err != nil {
		return nil, fmt.Errorf("attestation: failed to sign payload: %w", err)
	}

	// Submit the NodeAttestationDocument.
	docName, err := submitDocument(ctx, client, cfg.NodeName, challenge.Name, measurements, signedPayload)
	if err != nil {
		return nil, fmt.Errorf("attestation: failed to submit document: %w", err)
	}

	klog.V(2).Infof("attestation: document %s submitted for node %s", docName, cfg.NodeName)
	return &AttestationResult{DocumentName: docName}, nil
}

// GenerateAndSaveNodeIdentityKey generates a new ECDSA P-256 keypair, writes the
// private key to keyFile (mode 0600) and the public key to keyFile+".pub" (mode 0644).
// Called by kubeadm join when no existing enrollment is found for this node.
func GenerateAndSaveNodeIdentityKey(keyFile string) (string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate ECDSA key: %w", err)
	}

	// Encode private key as PKCS#8 PEM.
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("marshal private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	if err := os.WriteFile(keyFile, privPEM, 0600); err != nil {
		return "", fmt.Errorf("write private key to %s: %w", keyFile, err)
	}

	// Encode public key as PKIX PEM.
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	pubFile := keyFile + ".pub"
	if err := os.WriteFile(pubFile, []byte(pubPEM), 0644); err != nil {
		return "", fmt.Errorf("write public key to %s: %w", pubFile, err)
	}

	klog.V(2).Infof("attestation: generated node identity key pair at %s", keyFile)
	return pubPEM, nil
}

// loadPrivateKey reads and parses an ECDSA private key from a PEM file.
func loadPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key in %s is not ECDSA (got %T)", path, key)
	}
	return ecKey, nil
}

// collectMeasurements collects the software stack evidence for this node.
func collectMeasurements() (attestationv1alpha1.NodeMeasurements, error) {
	m := attestationv1alpha1.NodeMeasurements{}

	// Hash the running kubelet binary.
	if hash, err := hashSelf(); err != nil {
		klog.Warningf("attestation: failed to hash kubelet binary: %v", err)
	} else {
		m.KubeletHash = hash
	}

	// Kernel version.
	if kv, err := readKernelVersion(); err != nil {
		klog.V(4).Infof("attestation: kernel version unavailable: %v", err)
	} else {
		m.KernelVersion = kv
	}

	// OS image ID from /etc/os-release.
	if id, err := readOSImageID(); err != nil {
		klog.V(4).Infof("attestation: OS image ID unavailable: %v", err)
	} else {
		m.OSImageID = id
	}

	return m, nil
}

// hashSelf returns the SHA-256 hex digest of /proc/self/exe (the running kubelet binary).
func hashSelf() (string, error) {
	data, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		return "", fmt.Errorf("read /proc/self/exe: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// readKernelVersion reads the kernel version from /proc/version.
func readKernelVersion() (string, error) {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// readOSImageID reads the IMAGE_ID or ID field from /etc/os-release.
func readOSImageID() (string, error) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "IMAGE_ID=") {
			return strings.Trim(strings.TrimPrefix(line, "IMAGE_ID="), "\""), nil
		}
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "ID=") {
			return strings.Trim(strings.TrimPrefix(line, "ID="), "\""), nil
		}
	}
	return "", nil
}

// hashMeasurements returns the hex-encoded SHA-256 of the canonical JSON encoding.
func hashMeasurements(m attestationv1alpha1.NodeMeasurements) (string, error) {
	data, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// requestChallenge creates a NodeAttestationChallenge and returns it once the
// API server has populated the nonce in Status.
func requestChallenge(ctx context.Context, client clientset.Interface, nodeName string) (*attestationv1alpha1.NodeAttestationChallenge, error) {
	challenge := &attestationv1alpha1.NodeAttestationChallenge{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: nodeName + "-",
		},
		Spec: attestationv1alpha1.NodeAttestationChallengeSpec{
			NodeName: nodeName,
			TTL:      metav1.Duration{Duration: defaultChallengeTTL},
		},
	}
	created, err := client.AttestationV1alpha1().
		NodeAttestationChallenges().Create(ctx, challenge, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("create NodeAttestationChallenge: %w", err)
	}
	if created.Status.Nonce == "" {
		return nil, fmt.Errorf("API server returned challenge with empty nonce")
	}
	return created, nil
}

// signAttestationPayload builds and signs the compact JWS for a NodeAttestationDocument.
func signAttestationPayload(priv *ecdsa.PrivateKey, nodeName, nodeIP, nonce, measHash string) (string, error) {
	now := time.Now()
	claims := map[string]interface{}{
		"iss":               "kubernetes.io/node-identity/v1alpha1",
		"sub":               "system:node:" + nodeName,
		"iat":               now.Unix(),
		"exp":               now.Add(10 * time.Minute).Unix(),
		"nonce":             nonce,
		"measurements_hash": measHash,
	}
	if nodeIP != "" {
		claims["node_ip"] = nodeIP
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal JWS claims: %w", err)
	}

	sig, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("create JWS signer: %w", err)
	}

	jws, err := sig.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("sign JWS: %w", err)
	}
	return jws.CompactSerialize()
}

// submitDocument creates a NodeAttestationDocument in the API server.
func submitDocument(
	ctx context.Context,
	client clientset.Interface,
	nodeName, challengeName string,
	measurements attestationv1alpha1.NodeMeasurements,
	signedPayload string,
) (string, error) {
	doc := &attestationv1alpha1.NodeAttestationDocument{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: nodeName + "-",
		},
		Spec: attestationv1alpha1.NodeAttestationDocumentSpec{
			NodeName:        nodeName,
			ChallengeRef:    challengeName,
			AttestationMode: attestationv1alpha1.AttestationModeSoftware,
			Measurements:    measurements,
			SignedPayload:   signedPayload,
		},
	}
	created, err := client.AttestationV1alpha1().
		NodeAttestationDocuments().Create(ctx, doc, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("create NodeAttestationDocument: %w", err)
	}
	return created.Name, nil
}
