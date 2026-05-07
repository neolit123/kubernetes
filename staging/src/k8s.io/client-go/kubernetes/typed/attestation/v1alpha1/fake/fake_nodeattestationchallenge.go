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

// fakeNodeAttestationChallenges implements NodeAttestationChallengeInterface.
type fakeNodeAttestationChallenges struct {
	*gentype.FakeClientWithList[*attestationv1alpha1.NodeAttestationChallenge, *attestationv1alpha1.NodeAttestationChallengeList]
	Fake *FakeAttestationV1alpha1
}

func newFakeNodeAttestationChallenges(fake *FakeAttestationV1alpha1) typedattestationv1alpha1.NodeAttestationChallengeInterface {
	return &fakeNodeAttestationChallenges{
		gentype.NewFakeClientWithList[*attestationv1alpha1.NodeAttestationChallenge, *attestationv1alpha1.NodeAttestationChallengeList](
			fake.Fake,
			"",
			attestationv1alpha1.SchemeGroupVersion.WithResource("nodeattestationchallenges"),
			attestationv1alpha1.SchemeGroupVersion.WithKind("NodeAttestationChallenge"),
			func() *attestationv1alpha1.NodeAttestationChallenge {
				return &attestationv1alpha1.NodeAttestationChallenge{}
			},
			func() *attestationv1alpha1.NodeAttestationChallengeList {
				return &attestationv1alpha1.NodeAttestationChallengeList{}
			},
			func(dst, src *attestationv1alpha1.NodeAttestationChallengeList) { dst.ListMeta = src.ListMeta },
			func(list *attestationv1alpha1.NodeAttestationChallengeList) []*attestationv1alpha1.NodeAttestationChallenge {
				return gentype.ToPointerSlice(list.Items)
			},
			func(list *attestationv1alpha1.NodeAttestationChallengeList, items []*attestationv1alpha1.NodeAttestationChallenge) {
				list.Items = gentype.FromPointerSlice(items)
			},
		),
		fake,
	}
}
