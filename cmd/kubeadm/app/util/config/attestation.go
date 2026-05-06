/*
Copyright 2025 The Kubernetes Authors.

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

package config

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	kubeadmapi "k8s.io/kubernetes/cmd/kubeadm/app/apis/kubeadm"
)

const (
	// AttestationGroup is the API group for attestation resources.
	AttestationGroup = "attestation.kubernetes.io"
)

var attestationPolicyGVK = schema.GroupVersionKind{
	Group:   AttestationGroup,
	Version: "v1alpha1",
	Kind:    "NodeAttestationPolicy",
}

// ExtractAttestationPolicyDoc scans the document map for a NodeAttestationPolicy
// document and returns its raw YAML bytes. Returns nil if no such document is present.
func ExtractAttestationPolicyDoc(gvkmap kubeadmapi.DocumentMap) []byte {
	for gvk, doc := range gvkmap {
		if gvk.Group == AttestationGroup && gvk.Kind == attestationPolicyGVK.Kind {
			return doc
		}
	}
	return nil
}
