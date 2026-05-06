package rest

import (
	"k8s.io/apiserver/pkg/registry/generic"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
	serverstorage "k8s.io/apiserver/pkg/server/storage"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	"k8s.io/kubernetes/pkg/apis/attestation"
	attestationv1alpha1 "k8s.io/api/attestation/v1alpha1"
	challengestorage "k8s.io/kubernetes/pkg/registry/attestation/nodeattestationchallenge/storage"
	documentstorage "k8s.io/kubernetes/pkg/registry/attestation/nodeattestationdocument/storage"
	enrollmentstorage "k8s.io/kubernetes/pkg/registry/attestation/nodeidentityenrollment/storage"
	policystorage "k8s.io/kubernetes/pkg/registry/attestation/nodeattestationpolicy/storage"
)

// StorageProvider is the REST storage provider for the attestation API group.
type StorageProvider struct{}

// NewRESTStorage returns API GroupInfo for the attestation API group.
func (p StorageProvider) NewRESTStorage(apiResourceConfigSource serverstorage.APIResourceConfigSource, restOptionsGetter generic.RESTOptionsGetter) (genericapiserver.APIGroupInfo, error) {
	apiGroupInfo := genericapiserver.NewDefaultAPIGroupInfo(attestation.GroupName, legacyscheme.Scheme, legacyscheme.ParameterCodec, legacyscheme.Codecs)

	if storageMap, err := p.v1alpha1Storage(apiResourceConfigSource, restOptionsGetter); err != nil {
		return genericapiserver.APIGroupInfo{}, err
	} else if len(storageMap) > 0 {
		apiGroupInfo.VersionedResourcesStorageMap[attestationv1alpha1.SchemeGroupVersion.Version] = storageMap
	}

	return apiGroupInfo, nil
}

func (p StorageProvider) v1alpha1Storage(apiResourceConfigSource serverstorage.APIResourceConfigSource, restOptionsGetter generic.RESTOptionsGetter) (map[string]rest.Storage, error) {
	storage := map[string]rest.Storage{}

	if resource := "nodeidentityenrollments"; apiResourceConfigSource.ResourceEnabled(attestationv1alpha1.SchemeGroupVersion.WithResource(resource)) {
		enrollmentStorage, enrollmentStatusStorage, err := enrollmentstorage.NewREST(restOptionsGetter)
		if err != nil {
			return nil, err
		}
		storage[resource] = enrollmentStorage
		storage[resource+"/status"] = enrollmentStatusStorage
	}

	if resource := "nodeattestationchallenges"; apiResourceConfigSource.ResourceEnabled(attestationv1alpha1.SchemeGroupVersion.WithResource(resource)) {
		challengeStorage, challengeStatusStorage, err := challengestorage.NewREST(restOptionsGetter)
		if err != nil {
			return nil, err
		}
		storage[resource] = challengeStorage
		storage[resource+"/status"] = challengeStatusStorage
	}

	if resource := "nodeattestationdocuments"; apiResourceConfigSource.ResourceEnabled(attestationv1alpha1.SchemeGroupVersion.WithResource(resource)) {
		documentStorage, documentStatusStorage, err := documentstorage.NewREST(restOptionsGetter)
		if err != nil {
			return nil, err
		}
		storage[resource] = documentStorage
		storage[resource+"/status"] = documentStatusStorage
	}

	if resource := "nodeattestationpolicies"; apiResourceConfigSource.ResourceEnabled(attestationv1alpha1.SchemeGroupVersion.WithResource(resource)) {
		policyStorage, err := policystorage.NewREST(restOptionsGetter)
		if err != nil {
			return nil, err
		}
		storage[resource] = policyStorage
	}

	return storage, nil
}

// GroupName returns the API group name.
func (p StorageProvider) GroupName() string {
	return attestation.GroupName
}
