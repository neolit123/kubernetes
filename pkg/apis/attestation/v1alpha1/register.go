package v1alpha1

import (
	attestationv1alpha1 "k8s.io/api/attestation/v1alpha1"
)

// SchemeGroupVersion is the group and version used in this package.
var SchemeGroupVersion = attestationv1alpha1.SchemeGroupVersion

var (
	localSchemeBuilder = &attestationv1alpha1.SchemeBuilder
	AddToScheme        = localSchemeBuilder.AddToScheme
)

func init() {
	// Register manually written functions here. Generated functions are registered
	// in the generated files.
	localSchemeBuilder.Register(addDefaultingFuncs)
}
