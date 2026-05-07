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

package v1alpha1

import (
	context "context"

	attestationv1alpha1 "k8s.io/api/attestation/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
	scheme "k8s.io/client-go/kubernetes/scheme"
)

// NodeIdentityEnrollmentsGetter has a method to return a NodeIdentityEnrollmentInterface.
type NodeIdentityEnrollmentsGetter interface {
	NodeIdentityEnrollments() NodeIdentityEnrollmentInterface
}

// NodeIdentityEnrollmentInterface provides methods for NodeIdentityEnrollment resources.
type NodeIdentityEnrollmentInterface interface {
	Create(ctx context.Context, obj *attestationv1alpha1.NodeIdentityEnrollment, opts v1.CreateOptions) (*attestationv1alpha1.NodeIdentityEnrollment, error)
	Update(ctx context.Context, obj *attestationv1alpha1.NodeIdentityEnrollment, opts v1.UpdateOptions) (*attestationv1alpha1.NodeIdentityEnrollment, error)
	UpdateStatus(ctx context.Context, obj *attestationv1alpha1.NodeIdentityEnrollment, opts v1.UpdateOptions) (*attestationv1alpha1.NodeIdentityEnrollment, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*attestationv1alpha1.NodeIdentityEnrollment, error)
	List(ctx context.Context, opts v1.ListOptions) (*attestationv1alpha1.NodeIdentityEnrollmentList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (*attestationv1alpha1.NodeIdentityEnrollment, error)
	NodeIdentityEnrollmentExpansion
}

// nodeIdentityEnrollments implements NodeIdentityEnrollmentInterface.
type nodeIdentityEnrollments struct {
	*gentype.ClientWithList[*attestationv1alpha1.NodeIdentityEnrollment, *attestationv1alpha1.NodeIdentityEnrollmentList]
}

func newNodeIdentityEnrollments(c *AttestationV1alpha1Client) *nodeIdentityEnrollments {
	return &nodeIdentityEnrollments{
		gentype.NewClientWithList[*attestationv1alpha1.NodeIdentityEnrollment, *attestationv1alpha1.NodeIdentityEnrollmentList](
			"nodeidentityenrollments",
			c.RESTClient(),
			scheme.ParameterCodec,
			"",
			func() *attestationv1alpha1.NodeIdentityEnrollment {
				return &attestationv1alpha1.NodeIdentityEnrollment{}
			},
			func() *attestationv1alpha1.NodeIdentityEnrollmentList {
				return &attestationv1alpha1.NodeIdentityEnrollmentList{}
			},
		),
	}
}
