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
	http "net/http"

	attestationv1alpha1 "k8s.io/api/attestation/v1alpha1"
	scheme "k8s.io/client-go/kubernetes/scheme"
	rest "k8s.io/client-go/rest"
)

// AttestationV1alpha1Interface defines methods for the attestation.kubernetes.io/v1alpha1 group.
type AttestationV1alpha1Interface interface {
	RESTClient() rest.Interface
	NodeIdentityEnrollmentsGetter
	NodeAttestationChallengesGetter
	NodeAttestationDocumentsGetter
	NodeAttestationPoliciesGetter
}

// AttestationV1alpha1Client is used to interact with the attestation.kubernetes.io/v1alpha1 group.
type AttestationV1alpha1Client struct {
	restClient rest.Interface
}

func (c *AttestationV1alpha1Client) NodeIdentityEnrollments() NodeIdentityEnrollmentInterface {
	return newNodeIdentityEnrollments(c)
}

func (c *AttestationV1alpha1Client) NodeAttestationChallenges() NodeAttestationChallengeInterface {
	return newNodeAttestationChallenges(c)
}

func (c *AttestationV1alpha1Client) NodeAttestationDocuments() NodeAttestationDocumentInterface {
	return newNodeAttestationDocuments(c)
}

func (c *AttestationV1alpha1Client) NodeAttestationPolicies() NodeAttestationPolicyInterface {
	return newNodeAttestationPolicies(c)
}

// NewForConfig creates a new AttestationV1alpha1Client for the given config.
func NewForConfig(c *rest.Config) (*AttestationV1alpha1Client, error) {
	config := *c
	setConfigDefaults(&config)
	httpClient, err := rest.HTTPClientFor(&config)
	if err != nil {
		return nil, err
	}
	return NewForConfigAndClient(&config, httpClient)
}

// NewForConfigAndClient creates a new AttestationV1alpha1Client for the given config and http client.
func NewForConfigAndClient(c *rest.Config, h *http.Client) (*AttestationV1alpha1Client, error) {
	config := *c
	setConfigDefaults(&config)
	client, err := rest.RESTClientForConfigAndClient(&config, h)
	if err != nil {
		return nil, err
	}
	return &AttestationV1alpha1Client{client}, nil
}

// NewForConfigOrDie creates a new AttestationV1alpha1Client and panics on error.
func NewForConfigOrDie(c *rest.Config) *AttestationV1alpha1Client {
	client, err := NewForConfig(c)
	if err != nil {
		panic(err)
	}
	return client
}

// New creates a new AttestationV1alpha1Client for the given RESTClient.
func New(c rest.Interface) *AttestationV1alpha1Client {
	return &AttestationV1alpha1Client{c}
}

func setConfigDefaults(config *rest.Config) {
	gv := attestationv1alpha1.SchemeGroupVersion
	config.GroupVersion = &gv
	config.APIPath = "/apis"
	config.NegotiatedSerializer = rest.CodecFactoryForGeneratedClient(scheme.Scheme, scheme.Codecs).WithoutConversion()
	if config.UserAgent == "" {
		config.UserAgent = rest.DefaultKubernetesUserAgent()
	}
}

// RESTClient returns a RESTClient used to communicate with the API server.
func (c *AttestationV1alpha1Client) RESTClient() rest.Interface {
	if c == nil {
		return nil
	}
	return c.restClient
}
