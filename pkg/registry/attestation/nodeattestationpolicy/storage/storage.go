package storage

import (
	"fmt"

	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/registry/generic"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/registry/rest"
	"k8s.io/kubernetes/pkg/apis/attestation"
	"k8s.io/kubernetes/pkg/printers"
	printersinternal "k8s.io/kubernetes/pkg/printers/internalversion"
	printerstorage "k8s.io/kubernetes/pkg/printers/storage"
	"k8s.io/kubernetes/pkg/registry/attestation/nodeattestationpolicy"
)

// REST is a RESTStorage for NodeAttestationPolicy.
type REST struct {
	*genericregistry.Store
}

var _ rest.StandardStorage = &REST{}
var _ rest.TableConvertor = &REST{}

// NewREST returns a RESTStorage object for NodeAttestationPolicy objects.
func NewREST(optsGetter generic.RESTOptionsGetter) (*REST, error) {
	store := &genericregistry.Store{
		NewFunc:                   func() runtime.Object { return &attestation.NodeAttestationPolicy{} },
		NewListFunc:               func() runtime.Object { return &attestation.NodeAttestationPolicyList{} },
		DefaultQualifiedResource:  attestation.Resource("nodeattestationpolicies"),
		SingularQualifiedResource: attestation.Resource("nodeattestationpolicy"),

		CreateStrategy: nodeattestationpolicy.Strategy,
		UpdateStrategy: nodeattestationpolicy.Strategy,
		DeleteStrategy: nodeattestationpolicy.Strategy,

		TableConvertor: printerstorage.TableConvertor{TableGenerator: printers.NewTableGenerator().With(printersinternal.AddHandlers)},
	}
	options := &generic.StoreOptions{
		RESTOptions: optsGetter,
		AttrFunc:    getAttrs,
	}
	if err := store.CompleteWithOptions(options); err != nil {
		return nil, err
	}
	return &REST{store}, nil
}

func getAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	policy, ok := obj.(*attestation.NodeAttestationPolicy)
	if !ok {
		return nil, nil, fmt.Errorf("not a nodeattestationpolicy")
	}
	return labels.Set(policy.Labels), generic.ObjectMetaFieldsSet(&policy.ObjectMeta, false), nil
}
