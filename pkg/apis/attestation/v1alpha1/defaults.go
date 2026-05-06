package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime"
	attestationv1alpha1 "k8s.io/api/attestation/v1alpha1"
)

func addDefaultingFuncs(scheme *runtime.Scheme) error {
	return RegisterDefaults(scheme)
}

// SetDefaults_NodeAttestationPolicy sets defaults on a NodeAttestationPolicy.
func SetDefaults_NodeAttestationPolicy(obj *attestationv1alpha1.NodeAttestationPolicy) {
	if obj.Spec.DefaultMode == "" {
		obj.Spec.DefaultMode = attestationv1alpha1.AttestationModeSoftware
	}
	if obj.Spec.EnforcementMode == "" {
		obj.Spec.EnforcementMode = "permissive"
	}
	if obj.Spec.SoftwarePolicy != nil {
		if obj.Spec.SoftwarePolicy.MeasurementPolicy == "" {
			obj.Spec.SoftwarePolicy.MeasurementPolicy = attestationv1alpha1.MeasurementPolicyRequire
		}
	}
}

// SetDefaults_NodeIdentityEnrollment sets defaults on a NodeIdentityEnrollment.
func SetDefaults_NodeIdentityEnrollment(obj *attestationv1alpha1.NodeIdentityEnrollment) {
	if obj.Spec.AttestationMode == "" {
		obj.Spec.AttestationMode = attestationv1alpha1.AttestationModeSoftware
	}
}

// SetDefaults_NodeAttestationChallenge sets defaults on a NodeAttestationChallenge.
func SetDefaults_NodeAttestationChallenge(obj *attestationv1alpha1.NodeAttestationChallenge) {
	if obj.Spec.TTL.Duration == 0 {
		obj.Spec.TTL.Duration = 5 * 60 * 1e9 // 5 minutes in nanoseconds
	}
}
