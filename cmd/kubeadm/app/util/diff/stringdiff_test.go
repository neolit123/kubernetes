/*
Copyright 2024 The Kubernetes Authors.

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

package diff

import (
	"testing"
)

func TestDiffString(t *testing.T) {
	tests := []struct {
		name           string
		a              string
		b              string
		expectedOutput string
		contextLines   int
	}{
		{
			name: "complex diff with 2 context lines",
			a: `
line1
line2
line3
line4



line5
line6
line7
line8
`,
			b: `
line1
line2
line3
line4.1
line5
line6.1
line7
line8.1
`,
			contextLines: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := DiffString(tc.a, tc.b, "old", "new", tc.contextLines)
			if out != tc.expectedOutput {
				t.Fatalf("\nexpected output:\n%s\n\ngot:\n%s\n", tc.expectedOutput, out)
			}
		})
	}
}
