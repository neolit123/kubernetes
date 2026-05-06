// Package nodeattestationchallenge provides Registry interface and its RESTStorage
// implementation for storing NodeAttestationChallenge objects.
package nodeattestationchallenge

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/apiserver/pkg/storage/names"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	"k8s.io/kubernetes/pkg/apis/attestation"
	"k8s.io/kubernetes/pkg/apis/attestation/validation"
	"sigs.k8s.io/structured-merge-diff/v6/fieldpath"
)

// strategy implements NodeAttestationChallenge create/update business logic.
type strategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// Strategy is the default logic that applies when creating/updating NodeAttestationChallenge objects.
var Strategy = strategy{legacyscheme.Scheme, names.SimpleNameGenerator}

var _ rest.RESTCreateStrategy = Strategy
var _ rest.RESTUpdateStrategy = Strategy

func (strategy) NamespaceScoped() bool { return false }

func (strategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {
	challenge := obj.(*attestation.NodeAttestationChallenge)
	// Clear status on create; it is populated by the API server.
	challenge.Status = attestation.NodeAttestationChallengeStatus{}
}

func (strategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	return validation.ValidateNodeAttestationChallenge(obj.(*attestation.NodeAttestationChallenge))
}

func (strategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string { return nil }

func (strategy) Canonicalize(obj runtime.Object) {}

func (strategy) AllowCreateOnUpdate(ctx context.Context) bool { return false }

func (strategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {}

func (strategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return validation.ValidateNodeAttestationChallengeUpdate(
		obj.(*attestation.NodeAttestationChallenge),
		old.(*attestation.NodeAttestationChallenge),
	)
}

func (strategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string { return nil }

func (strategy) AllowUnconditionalUpdate(ctx context.Context) bool { return false }

// statusStrategy implements the status subresource strategy.
type statusStrategy struct {
	strategy
}

// StatusStrategy is the strategy for the status subresource.
var StatusStrategy = statusStrategy{Strategy}

func (statusStrategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {
	newChallenge := obj.(*attestation.NodeAttestationChallenge)
	oldChallenge := old.(*attestation.NodeAttestationChallenge)
	// Only allow status updates; preserve spec.
	newChallenge.Spec = oldChallenge.Spec
}

func (statusStrategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return field.ErrorList{}
}

// GetResetFields returns the set of fields that are reset by a status update.
func (statusStrategy) GetResetFields() map[fieldpath.APIVersion]*fieldpath.Set {
	return map[fieldpath.APIVersion]*fieldpath.Set{
		"attestation.kubernetes.io/v1alpha1": fieldpath.NewSet(
			fieldpath.MakePathOrDie("spec"),
		),
	}
}
