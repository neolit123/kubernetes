package storage

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	"k8s.io/kubernetes/pkg/registry/attestation/nodeattestationdocument"
	"sigs.k8s.io/structured-merge-diff/v6/fieldpath"
)

// REST is a RESTStorage for NodeAttestationDocument.
type REST struct {
	*genericregistry.Store
}

// StatusREST implements the REST endpoint for changing the status of a NodeAttestationDocument.
type StatusREST struct {
	store *genericregistry.Store
}

var _ rest.StandardStorage = &REST{}
var _ rest.Patcher = &StatusREST{}

// NewREST returns a RESTStorage object for NodeAttestationDocument objects.
func NewREST(optsGetter generic.RESTOptionsGetter) (*REST, *StatusREST, error) {
	store := &genericregistry.Store{
		NewFunc:                   func() runtime.Object { return &attestation.NodeAttestationDocument{} },
		NewListFunc:               func() runtime.Object { return &attestation.NodeAttestationDocumentList{} },
		DefaultQualifiedResource:  attestation.Resource("nodeattestationdocuments"),
		SingularQualifiedResource: attestation.Resource("nodeattestationdocument"),

		CreateStrategy: nodeattestationdocument.Strategy,
		UpdateStrategy: nodeattestationdocument.Strategy,
		DeleteStrategy: nodeattestationdocument.Strategy,

		TableConvertor: printerstorage.TableConvertor{TableGenerator: printers.NewTableGenerator().With(printersinternal.AddHandlers)},
	}
	options := &generic.StoreOptions{
		RESTOptions: optsGetter,
		AttrFunc:    getAttrs,
	}
	if err := store.CompleteWithOptions(options); err != nil {
		return nil, nil, err
	}

	statusStore := *store
	statusStore.UpdateStrategy = nodeattestationdocument.StatusStrategy
	statusStore.ResetFieldsStrategy = nodeattestationdocument.StatusStrategy

	return &REST{store}, &StatusREST{store: &statusStore}, nil
}

func getAttrs(obj runtime.Object) (labels.Set, fields.Set, error) {
	doc, ok := obj.(*attestation.NodeAttestationDocument)
	if !ok {
		return nil, nil, fmt.Errorf("not a nodeattestationdocument")
	}
	return labels.Set(doc.Labels), generic.ObjectMetaFieldsSet(&doc.ObjectMeta, false), nil
}

// New creates a new NodeAttestationDocument object.
func (r *StatusREST) New() runtime.Object {
	return &attestation.NodeAttestationDocument{}
}

// Destroy cleans up resources on shutdown.
func (r *StatusREST) Destroy() {}

// Get retrieves the object from the storage. It is required to support Patch.
func (r *StatusREST) Get(ctx context.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	return r.store.Get(ctx, name, options)
}

// Update alters the status subset of an object.
func (r *StatusREST) Update(ctx context.Context, name string, objInfo rest.UpdatedObjectInfo, createValidation rest.ValidateObjectFunc, updateValidation rest.ValidateObjectUpdateFunc, forceAllowCreate bool, options *metav1.UpdateOptions) (runtime.Object, bool, error) {
	return r.store.Update(ctx, name, objInfo, createValidation, updateValidation, false, options)
}

// GetResetFields implements rest.ResetFieldsStrategy.
func (r *StatusREST) GetResetFields() map[fieldpath.APIVersion]*fieldpath.Set {
	return r.store.GetResetFields()
}

// ConvertToTable implements rest.TableConvertor.
func (r *StatusREST) ConvertToTable(ctx context.Context, object runtime.Object, tableOptions runtime.Object) (*metav1.Table, error) {
	return r.store.ConvertToTable(ctx, object, tableOptions)
}
