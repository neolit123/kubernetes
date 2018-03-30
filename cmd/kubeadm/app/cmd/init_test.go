/*
Copyright 2018 The Kubernetes Authors.

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

package cmd

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	kubeadmapi "k8s.io/kubernetes/cmd/kubeadm/app/apis/kubeadm"
	kubeadmapiext "k8s.io/kubernetes/cmd/kubeadm/app/apis/kubeadm/v1alpha1"
	"k8s.io/kubernetes/cmd/kubeadm/app/apis/kubeadm/validation"
	"k8s.io/kubernetes/cmd/kubeadm/app/features"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	kubeproxyconfigv1alpha1 "k8s.io/kubernetes/pkg/proxy/apis/kubeproxyconfig/v1alpha1"
)

const (
	TestConfig = `apiVersion: v1
clusters:
- cluster:
    certificate-authority-data:
    server: localhost:8000
  name: prod
contexts:
- context:
    cluster: prod
    namespace: default
    user: default-service-account
  name: default
current-context: default
kind: Config
preferences: {}
users:
- name: kubernetes-admin
  user:
    client-certificate-data:
    client-key-data:
`
)

var (
	masterConfigValid = &kubeadmapiext.MasterConfiguration{
		API: kubeadmapiext.API{AdvertiseAddress: "1.2.3.4", BindPort: 1234},
		KubeProxy: kubeadmapiext.KubeProxy{
			Config: &kubeproxyconfigv1alpha1.KubeProxyConfiguration{
				BindAddress: "127.0.0.1",
			},
		},
		KubernetesVersion: "1.9.0",
		CloudProvider:     "some-cp",
	}

	masterConfigInvalidVersion = &kubeadmapiext.MasterConfiguration{
		API: kubeadmapiext.API{AdvertiseAddress: "1.2.3.4", BindPort: 1234},
		KubeProxy: kubeadmapiext.KubeProxy{
			Config: &kubeproxyconfigv1alpha1.KubeProxyConfiguration{
				BindAddress: "127.0.0.1",
			},
		},
		KubernetesVersion: "a.b.c.d",
		CloudProvider:     "some-cp",
	}
)

// WIP:
// https://github.com/kubernetes/kubernetes/blob/ab639118e72b6558bfe36aa6a0635f4027cf028b/cmd/kubeadm/app/apis/kubeadm/v1alpha1/types.go#L30
// https://github.com/kubernetes/kubernetes/blob/d7cadf5d180277cfed7fd57d1e1a125c538bd751/cmd/kubeadm/app/phases/kubeconfig/kubeconfig_test.go
// https://github.com/kubernetes/kubernetes/blob/master/cmd/kubeadm/app/util/config/masterconfig.go#L38
// https://github.com/kubernetes/kubernetes/blob/b32e9c45460662f2bbc64d88fe379db5bd733934/cmd/kubeadm/app/phases/certs/pkiutil/pki_helpers_test.go#L442

func TestNewInit(t *testing.T) {
	var err error
	skipPreFlight := true
	skipTokenPrint := true
	dryRun := true
	featureGatesString := ""
	ignorePreflightErrors := []string{"all"}

	tmpDir, err := ioutil.TempDir("", "kubeadm-token-test")
	if err != nil {
		t.Errorf("Unable to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	fullPath := filepath.Join(tmpDir, "test-config-file")

	f, err := os.Create(fullPath)
	if err != nil {
		t.Errorf("Unable to create test file %q: %v", fullPath, err)
	}
	defer f.Close()

	ignorePreflightErrorsSet, err := validation.ValidateIgnorePreflightErrors(ignorePreflightErrors, skipPreFlight)
	if err != nil {
		t.Fatalf("NewInit: %v", err)
	}

	testCases := []struct {
		name          string
		configToWrite string
		cfgPath       string
		masterConfig  *kubeadmapiext.MasterConfiguration
		expectedError bool
	}{

		{
			name:          "valid: successfully created Init object",
			configToWrite: TestConfig,
			cfgPath:       fullPath,
			masterConfig:  masterConfigValid,
			expectedError: false,
		},
		{
			name:          "invalid: missing config file",
			cfgPath:       tmpDir + "/missing-file",
			masterConfig:  masterConfigValid,
			expectedError: true,
		},
		{
			name:          "invalid: incorrect config format",
			configToWrite: "bad-config",
			cfgPath:       fullPath,
			masterConfig:  masterConfigValid,
			expectedError: true,
		},
		{
			name:          "invalid: incorreect format for version in master config",
			configToWrite: TestConfig,
			cfgPath:       fullPath,
			masterConfig:  masterConfigInvalidVersion,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		if tc.configToWrite != "" {
			if _, err = f.WriteString(tc.configToWrite); err != nil {
				t.Fatalf("Unable to write test file %q: %v", fullPath, err)
			}
		}
		if tc.masterConfig.FeatureGates, err = features.NewFeatureGate(&features.InitFeatureGates, featureGatesString); err != nil {
			t.Fatalf("NewInit: %v", err)
		}
		legacyscheme.Scheme.Default(tc.masterConfig)
		internalcfg := &kubeadmapi.MasterConfiguration{}
		legacyscheme.Scheme.Convert(tc.masterConfig, internalcfg, nil)

		_, err = NewInit(tc.cfgPath, internalcfg, ignorePreflightErrorsSet, skipTokenPrint, dryRun)
		if (err != nil) != tc.expectedError {
			t.Fatalf("Test case %q: NewInit expected error: %v, saw: %v", tc.name, tc.expectedError, (err != nil))
		}
	}
}
