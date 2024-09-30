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

// Package diff holds some utilities for producing diffs between objects.
package diff

import (
	"fmt"
	"strings"
)

// --------------------------

// DiffString takes two strings a and b and returns a unified diff between them.
// Pass contextLines to specify how many additional context lines are produced.
// oldFile and newFile are put in the header of the diff.
func DiffString(a, b, oldFile, newFile string, contextLines int) string {
	var lines []string

	a = strings.TrimRight(a, "\n")
	b = strings.TrimRight(b, "\n")

	lines = append(lines, fmt.Sprintf("--- %s", oldFile))
	lines = append(lines, fmt.Sprintf("+++ %s", newFile))

	aLines := strings.Split(a, "\n")
	bLines := strings.Split(b, "\n")

	type hunk struct {
		startA int
		startB int
		linesA []string
		linesB []string
	}

	var hunks, merged []hunk

	min := func(a, b int) int {
		if a < b {
			return a
		}
		return b
	}

	max := func(a, b int) int {
		if a > b {
			return a
		}
		return b
	}

	addHunk := func(startA, startB int, linesA, linesB []string) {
		hunk := hunk{
			startA: startA,
			startB: startB,
			linesA: linesA,
			linesB: linesB,
		}
		hunks = append(hunks, hunk)
	}

	hunksOverlap := func(a, b hunk) bool {
		startA := min(a.startA, a.startB)
		endA := max(a.startA+len(a.linesA), a.startB+len(a.linesB))

		startB := min(b.startA, b.startB)
		endB := max(b.startA+len(b.linesA), b.startB+len(b.linesB))

		return startB <= endA || startA <= endB
	}

	for i := 0; i < max(len(aLines), len(bLines)); i++ {
		j := i + 1
		if i > len(aLines)-1 {
			addHunk(j, j, []string{}, []string{bLines[i]})
			continue
		}
		if i > len(bLines)-1 {
			addHunk(j, j, []string{}, []string{aLines[i]})
			continue
		}
		if aLines[i] != bLines[i] {
			addHunk(j, j, []string{aLines[i]}, []string{bLines[i]})
		}
	}

	current := hunks[0]
	for i := 1; i < len(hunks); i++ {
		if hunksOverlap(hunks[i-1], hunks[i]) {
			current.startA = min(current.startA, hunks[i].startA)
			current.startB = min(current.startB, hunks[i].startB)
			current.linesA = append(current.linesA, hunks[i].linesA...)
			current.linesB = append(current.linesB, hunks[i].linesB...)
		} else {
			merged = append(merged, current)
			current = hunks[i]
		}
	}
	merged = append(merged, current)

	for i := range merged {
		hunk := merged[i]
		lines = append(lines, fmt.Sprintf("@@ -%d,%d +%d,%d @@",
			hunk.startA, len(hunk.linesA),
			hunk.startB, len(hunk.linesB),
		))

		for j := range max(len(hunk.linesA), len(hunk.linesB)) {
			if j < len(hunk.linesA) {
				lines = append(lines, fmt.Sprintf("-%s", hunk.linesA[j]))
			}
			if j < len(hunk.linesB) {
				lines = append(lines, fmt.Sprintf("+%s", hunk.linesB[j]))
			}
		}
	}

	return strings.Join(lines, "\n")
}

// --------------------------------

// // DiffString takes two strings a and b and returns a unified diff between them.
// // Pass contextLines to specify how many additional context lines are produced.
// // oldFile and newFile are put in the header of the diff.
// func DiffString(inputA, inputB, oldFile, newFile string, contextLines int) string {
// 	var lines []string

// 	addLine := func(line string) {
// 		lines = append(lines, line)
// 	}

// 	inputA = strings.TrimRight(inputA, "\n")
// 	inputB = strings.TrimRight(inputB, "\n")

// 	a := strings.Split(inputA, "\n")
// 	b := strings.Split(inputB, "\n")

// 	addLine(fmt.Sprintf("--- %s", oldFile))
// 	addLine(fmt.Sprintf("+++ %s", newFile))

// 	// min := func(a, b int) int {
// 	// 	if a < b {
// 	// 		return a
// 	// 	}
// 	// 	return b
// 	// }

// 	max := func(a, b int) int {
// 		if a > b {
// 			return a
// 		}
// 		return b
// 	}

// 	// diffLen := len(a) - len(b)

// 	var hunkStartA, hunkStartB, hunkLenA, hunkLenB int
// 	var trailingContext int
// 	var startHunk bool
// 	var hunkLines []string

// 	if len(a) < len(b) {
// 		for _ = range len(b) - len(a) {
// 			a = append(a, "")
// 		}
// 	} else if len(a) > len(b) {
// 		for _ = range len(a) - len(b) {
// 			b = append(b, "")
// 		}
// 	}
// 	sharedLen := len(a)
// 	for i := 0; i < sharedLen; i++ {
// 		if a[i] != b[i] {
// 			if !startHunk {
// 				startHunk = true
// 				hunkLines = []string{}
// 				hunkStartA = max(1, i-contextLines)
// 				hunkStartB = hunkStartA
// 				hunkLenA = 0
// 				hunkLenB = 0
// 				trailingContext = contextLines
// 				for j := contextLines; j > 0; j-- {
// 					if i-j < 0 {
// 						continue
// 					}
// 					hunkLines = append(hunkLines, fmt.Sprintf(" %s", a[i-j]))
// 					hunkLenA++
// 					hunkLenB++
// 				}
// 			}
// 			hunkLines = append(hunkLines, fmt.Sprintf("-%s", a[i]))
// 			hunkLenA++
// 			hunkLines = append(hunkLines, fmt.Sprintf("+%s", b[i]))
// 			hunkLenB++
// 			if i == sharedLen-1 {
// 				trailingContext = 0
// 				goto writeHunk
// 			}
// 			continue
// 		}
// 		if trailingContext > 0 {
// 			hunkLines = append(hunkLines, fmt.Sprintf(" %s", a[i]))
// 			hunkLenA++
// 			hunkLenB++
// 			trailingContext--
// 		}
// 		if i == sharedLen-1 {
// 			trailingContext = 0
// 		}
// 	writeHunk:
// 		if trailingContext == 0 && startHunk {
// 			addLine(fmt.Sprintf("@@ -%d,%d +%d,%d @@", hunkStartA, hunkLenA, hunkStartB, hunkLenB))
// 			for _, line := range hunkLines {
// 				addLine(line)
// 			}
// 			startHunk = false
// 		}
// 	}

// 	return strings.Join(lines, "\n")
// }

// -------------------------
// func DiffString(a, b, oldFile, newFile string, contextLines int) string {
// 	var lines []string

// 	a = strings.TrimRight(a, "\n")
// 	b = strings.TrimRight(b, "\n")

// 	lines = append(lines, fmt.Sprintf("--- %s", oldFile))
// 	lines = append(lines, fmt.Sprintf("+++ %s", newFile))

// 	aLines := strings.Split(a, "\n")
// 	bLines := strings.Split(b, "\n")

// 	type hunk struct {
// 		startA int
// 		startB int
// 		linesA []string
// 		linesB []string
// 	}

// 	var hunks, merged []hunk

// 	min := func(a, b int) int {
// 		if a < b {
// 			return a
// 		}
// 		return b
// 	}

// 	max := func(a, b int) int {
// 		if a > b {
// 			return a
// 		}
// 		return b
// 	}

// 	addHunk := func(startA, startB int, linesA, linesB []string) {
// 		hunk := hunk{
// 			startA: startA,
// 			startB: startB,
// 			linesA: linesA,
// 			linesB: linesB,
// 		}
// 		hunks = append(hunks, hunk)
// 	}

// 	for i := 0; i < max(len(aLines), len(bLines)); i++ {
// 		j := i + 1
// 		if i > len(aLines)-1 {
// 			addHunk(j, j, []string{}, []string{bLines[i]})
// 			continue
// 		}
// 		if i > len(bLines)-1 {
// 			addHunk(j, j, []string{}, []string{aLines[i]})
// 			continue
// 		}
// 		if aLines[i] != bLines[i] {
// 			addHunk(j, j, []string{aLines[i]}, []string{bLines[i]})
// 		}
// 	}

// 	current := hunks[0]
// 	for i := 1; i < len(hunks); i++ {
// 		if hunks[i].startA == hunks[i-1].startA+1 {
// 			current.startA = min(current.startA, hunks[i].startA)
// 			current.startB = min(current.startB, hunks[i].startB)
// 			current.linesA = append(current.linesA, hunks[i].linesA...)
// 			current.linesB = append(current.linesB, hunks[i].linesB...)
// 		} else {
// 			merged = append(merged, current)
// 			current = hunks[i]
// 		}
// 	}
// 	merged = append(merged, current)

// 	for i := range merged {
// 		hunk := merged[i]
// 		ctxA := max(hunk.startA-contextLines, 1)
// 		ctxB := max(hunk.startB-contextLines, 1)
// 		lines = append(lines, fmt.Sprintf("@@ -%d,%d +%d,%d @@",
// 			ctxA, len(hunk.linesA)+ctxA,
// 			ctxB, len(hunk.linesB)+ctxB,
// 		))
// 		for j := contextLines; j >= 0; j-- {
// 			c := hunk.startA - j - 1
// 			if c < 0 || c > len(aLines)-1 {
// 				break
// 			}
// 			lines = append(lines, fmt.Sprintf("%s", aLines[c]))
// 		}
// 		for j := range max(len(hunk.linesA), len(hunk.linesB)) {
// 			if j < len(hunk.linesA) {
// 				lines = append(lines, fmt.Sprintf("-%s", hunk.linesA[j]))
// 			}
// 			if j < len(hunk.linesB) {
// 				lines = append(lines, fmt.Sprintf("+%s", hunk.linesB[j]))
// 			}
// 		}
// 	}

// 	return strings.Join(lines, "\n")
// }
