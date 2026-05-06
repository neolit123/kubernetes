package validation

import (
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/apis/attestation"
)

// ValidateNodeIdentityEnrollment validates a NodeIdentityEnrollment.
func ValidateNodeIdentityEnrollment(enrollment *attestation.NodeIdentityEnrollment) field.ErrorList {
	allErrs := field.ErrorList{}
	specPath := field.NewPath("spec")

	switch enrollment.Spec.AttestationMode {
	case attestation.AttestationModeSoftware:
		if enrollment.Spec.SoftwareIdentity == nil {
			allErrs = append(allErrs, field.Required(specPath.Child("softwareIdentity"),
				"required when attestationMode is software"))
		} else if enrollment.Spec.SoftwareIdentity.PublicKey == "" {
			allErrs = append(allErrs, field.Required(specPath.Child("softwareIdentity", "publicKey"), ""))
		}
	case attestation.AttestationModeHardware:
		if enrollment.Spec.HardwareIdentity == nil {
			allErrs = append(allErrs, field.Required(specPath.Child("hardwareIdentity"),
				"required when attestationMode is hardware"))
		}
	case attestation.AttestationModeNull:
		// Blocked by admission in production; allowed in test environments.
	case "":
		allErrs = append(allErrs, field.Required(specPath.Child("attestationMode"), ""))
	default:
		allErrs = append(allErrs, field.NotSupported(specPath.Child("attestationMode"),
			enrollment.Spec.AttestationMode,
			[]string{
				string(attestation.AttestationModeSoftware),
				string(attestation.AttestationModeHardware),
			}))
	}
	return allErrs
}

// ValidateNodeIdentityEnrollmentUpdate validates an update to a NodeIdentityEnrollment.
func ValidateNodeIdentityEnrollmentUpdate(new, old *attestation.NodeIdentityEnrollment) field.ErrorList {
	return ValidateNodeIdentityEnrollment(new)
}

// ValidateNodeAttestationDocument validates a NodeAttestationDocument.
func ValidateNodeAttestationDocument(doc *attestation.NodeAttestationDocument) field.ErrorList {
	allErrs := field.ErrorList{}
	specPath := field.NewPath("spec")

	if doc.Spec.NodeName == "" {
		allErrs = append(allErrs, field.Required(specPath.Child("nodeName"), ""))
	}
	if doc.Spec.ChallengeRef == "" {
		allErrs = append(allErrs, field.Required(specPath.Child("challengeRef"), ""))
	}
	if doc.Spec.SignedPayload == "" {
		allErrs = append(allErrs, field.Required(specPath.Child("signedPayload"), ""))
	}
	if doc.Spec.AttestationMode == "" {
		allErrs = append(allErrs, field.Required(specPath.Child("attestationMode"), ""))
	}
	if len(doc.Spec.Measurements.KubeletHash) == 0 && doc.Spec.AttestationMode == attestation.AttestationModeSoftware {
		allErrs = append(allErrs, field.Required(specPath.Child("measurements", "kubeletHash"),
			"required for software attestation"))
	}
	return allErrs
}

// ValidateNodeAttestationDocumentUpdate validates an update to a NodeAttestationDocument.
func ValidateNodeAttestationDocumentUpdate(new, old *attestation.NodeAttestationDocument) field.ErrorList {
	return ValidateNodeAttestationDocument(new)
}

// ValidateNodeAttestationChallenge validates a NodeAttestationChallenge.
func ValidateNodeAttestationChallenge(challenge *attestation.NodeAttestationChallenge) field.ErrorList {
	allErrs := field.ErrorList{}
	if challenge.Spec.NodeName == "" {
		allErrs = append(allErrs, field.Required(field.NewPath("spec", "nodeName"), ""))
	}
	maxTTL := 10 * time.Minute
	if challenge.Spec.TTL.Duration > maxTTL {
		allErrs = append(allErrs, field.Invalid(field.NewPath("spec", "ttl"),
			challenge.Spec.TTL.Duration,
			fmt.Sprintf("TTL must not exceed %s", maxTTL)))
	}
	return allErrs
}

// ValidateNodeAttestationChallengeUpdate validates an update to a NodeAttestationChallenge.
func ValidateNodeAttestationChallengeUpdate(new, old *attestation.NodeAttestationChallenge) field.ErrorList {
	return ValidateNodeAttestationChallenge(new)
}

// ValidateNodeAttestationPolicy validates a NodeAttestationPolicy.
func ValidateNodeAttestationPolicy(policy *attestation.NodeAttestationPolicy) field.ErrorList {
	allErrs := field.ErrorList{}
	specPath := field.NewPath("spec")

	switch policy.Spec.DefaultMode {
	case attestation.AttestationModeSoftware, attestation.AttestationModeHardware, attestation.AttestationModeNull, "":
		// valid
	default:
		allErrs = append(allErrs, field.NotSupported(specPath.Child("defaultMode"),
			policy.Spec.DefaultMode,
			[]string{
				string(attestation.AttestationModeSoftware),
				string(attestation.AttestationModeHardware),
				string(attestation.AttestationModeNull),
			}))
	}

	switch policy.Spec.EnforcementMode {
	case "permissive", "enforced", "":
		// valid
	default:
		allErrs = append(allErrs, field.NotSupported(specPath.Child("enforcementMode"),
			policy.Spec.EnforcementMode,
			[]string{"permissive", "enforced"}))
	}

	if policy.Spec.SoftwarePolicy != nil {
		switch policy.Spec.SoftwarePolicy.MeasurementPolicy {
		case attestation.MeasurementPolicyRequire, attestation.MeasurementPolicyTOFU, attestation.MeasurementPolicyIgnore, "":
			// valid
		default:
			allErrs = append(allErrs, field.NotSupported(
				specPath.Child("softwarePolicy", "measurementPolicy"),
				policy.Spec.SoftwarePolicy.MeasurementPolicy,
				[]string{
					string(attestation.MeasurementPolicyRequire),
					string(attestation.MeasurementPolicyTOFU),
					string(attestation.MeasurementPolicyIgnore),
				}))
		}
	}

	return allErrs
}

// ValidateNodeAttestationPolicyUpdate validates an update to a NodeAttestationPolicy.
func ValidateNodeAttestationPolicyUpdate(new, old *attestation.NodeAttestationPolicy) field.ErrorList {
	return ValidateNodeAttestationPolicy(new)
}
