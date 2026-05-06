// Package nodeattestationpolicy provides Registry interface and its RESTStorage
// implementation for storing NodeAttestationPolicy objects.
package nodeattestationpolicy

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/apiserver/pkg/storage/names"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	"k8s.io/kubernetes/pkg/apis/attestation"
	"k8s.io/kubernetes/pkg/apis/attestation/validation"
)

// strategy implements NodeAttestationPolicy create/update business logic.
type strategy struct {
	runtime.ObjectTyper
	names.NameGenerator
}

// Strategy is the default logic that applies when creating/updating NodeAttestationPolicy objects.
var Strategy = strategy{legacyscheme.Scheme, names.SimpleNameGenerator}

var _ rest.RESTCreateStrategy = Strategy
var _ rest.RESTUpdateStrategy = Strategy

func (strategy) NamespaceScoped() bool { return false }

func (strategy) PrepareForCreate(ctx context.Context, obj runtime.Object) {}

func (strategy) Validate(ctx context.Context, obj runtime.Object) field.ErrorList {
	return validation.ValidateNodeAttestationPolicy(obj.(*attestation.NodeAttestationPolicy))
}

func (strategy) WarningsOnCreate(ctx context.Context, obj runtime.Object) []string { return nil }

func (strategy) Canonicalize(obj runtime.Object) {}

func (strategy) AllowCreateOnUpdate(ctx context.Context) bool { return false }

func (strategy) PrepareForUpdate(ctx context.Context, obj, old runtime.Object) {}

func (strategy) ValidateUpdate(ctx context.Context, obj, old runtime.Object) field.ErrorList {
	return validation.ValidateNodeAttestationPolicyUpdate(
		obj.(*attestation.NodeAttestationPolicy),
		old.(*attestation.NodeAttestationPolicy),
	)
}

func (strategy) WarningsOnUpdate(ctx context.Context, obj, old runtime.Object) []string { return nil }

func (strategy) AllowUnconditionalUpdate(ctx context.Context) bool { return false }
