/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package fake

import (
	attestationv1alpha1 "k8s.io/api/attestation/v1alpha1"
	gentype "k8s.io/client-go/gentype"
	typedattestationv1alpha1 "k8s.io/client-go/kubernetes/typed/attestation/v1alpha1"
)

// fakeNodeAttestationDocuments implements NodeAttestationDocumentInterface.
type fakeNodeAttestationDocuments struct {
	*gentype.FakeClientWithList[*attestationv1alpha1.NodeAttestationDocument, *attestationv1alpha1.NodeAttestationDocumentList]
	Fake *FakeAttestationV1alpha1
}

func newFakeNodeAttestationDocuments(fake *FakeAttestationV1alpha1) typedattestationv1alpha1.NodeAttestationDocumentInterface {
	return &fakeNodeAttestationDocuments{
		gentype.NewFakeClientWithList[*attestationv1alpha1.NodeAttestationDocument, *attestationv1alpha1.NodeAttestationDocumentList](
			fake.Fake,
			"",
			attestationv1alpha1.SchemeGroupVersion.WithResource("nodeattestationdocuments"),
			attestationv1alpha1.SchemeGroupVersion.WithKind("NodeAttestationDocument"),
			func() *attestationv1alpha1.NodeAttestationDocument {
				return &attestationv1alpha1.NodeAttestationDocument{}
			},
			func() *attestationv1alpha1.NodeAttestationDocumentList {
				return &attestationv1alpha1.NodeAttestationDocumentList{}
			},
			func(dst, src *attestationv1alpha1.NodeAttestationDocumentList) { dst.ListMeta = src.ListMeta },
			func(list *attestationv1alpha1.NodeAttestationDocumentList) []*attestationv1alpha1.NodeAttestationDocument {
				return gentype.ToPointerSlice(list.Items)
			},
			func(list *attestationv1alpha1.NodeAttestationDocumentList, items []*attestationv1alpha1.NodeAttestationDocument) {
				list.Items = gentype.FromPointerSlice(items)
			},
		),
		fake,
	}
}
