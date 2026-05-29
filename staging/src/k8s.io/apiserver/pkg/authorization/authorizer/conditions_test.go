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

package authorizer_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/cel-go/cel"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/admission"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
)

func TestConditionsAwareDecision(t *testing.T) {
	unexpectedErr := fmt.Errorf("unexpected things happened")
	otherErr := fmt.Errorf("other error")

	ctx := t.Context()
	sampleAttrs := authorizer.AttributesRecord{}

	tests := []struct {
		name                string
		testDecisions       []authorizer.ConditionsAwareDecision
		wantIsAllowed       bool
		wantIsNoOpinion     bool
		wantIsDeny          bool
		wantIsConditional   bool
		wantIsUnconditional bool
		wantReason          string
		wantAnyError        bool
		wantErrorIs         error
		wantString          string
	}{
		{
			name: "zero value",
			testDecisions: []authorizer.ConditionsAwareDecision{
				{},
				authorizer.ConditionsAwareDecisionFromParts(0, "", nil),
				authorizer.AuthorizerFunc(func(_ context.Context, _ authorizer.Attributes) (authorizer.Decision, string, error) {
					return 0, "", nil
				}).ConditionsAwareAuthorize(ctx, sampleAttrs),
			},
			wantIsDeny:          true,
			wantIsUnconditional: true,
			wantReason:          "",
			wantErrorIs:         nil,
			wantString:          `Deny`,
		},
		{
			name: "deny constructor",
			testDecisions: []authorizer.ConditionsAwareDecision{
				authorizer.ConditionsAwareDecisionDeny("foo", unexpectedErr),
				authorizer.ConditionsAwareDecisionFromParts(authorizer.DecisionDeny, "foo", unexpectedErr),
				authorizer.AuthorizerFunc(func(_ context.Context, _ authorizer.Attributes) (authorizer.Decision, string, error) {
					return authorizer.DecisionDeny, "foo", unexpectedErr
				}).ConditionsAwareAuthorize(ctx, sampleAttrs),
			},
			wantIsDeny:          true,
			wantIsUnconditional: true,
			wantReason:          "foo",
			wantErrorIs:         unexpectedErr,
			wantString:          `Deny(reason="foo", err="unexpected things happened")`,
		},
		{
			name: "allow constructor",
			testDecisions: []authorizer.ConditionsAwareDecision{
				authorizer.ConditionsAwareDecisionAllow("ok", nil),
				authorizer.ConditionsAwareDecisionFromParts(authorizer.DecisionAllow, "ok", nil),
				authorizer.AuthorizerFunc(func(_ context.Context, _ authorizer.Attributes) (authorizer.Decision, string, error) {
					return authorizer.DecisionAllow, "ok", nil
				}).ConditionsAwareAuthorize(ctx, sampleAttrs),
			},
			wantIsAllowed:       true,
			wantIsUnconditional: true,
			wantReason:          "ok",
			wantErrorIs:         nil,
			wantString:          `Allow(reason="ok")`,
		},
		{
			name: "noopinion constructor",
			testDecisions: []authorizer.ConditionsAwareDecision{
				authorizer.ConditionsAwareDecisionNoOpinion("", nil),
				authorizer.ConditionsAwareDecisionFromParts(authorizer.DecisionNoOpinion, "", nil),
				authorizer.AuthorizerFunc(func(_ context.Context, _ authorizer.Attributes) (authorizer.Decision, string, error) {
					return authorizer.DecisionNoOpinion, "", nil
				}).ConditionsAwareAuthorize(ctx, sampleAttrs),
			},
			wantIsNoOpinion:     true,
			wantIsUnconditional: true,
			wantReason:          "",
			wantErrorIs:         nil,
			wantString:          `NoOpinion`,
		},
		{
			name: "from parts: unsupported mode",
			testDecisions: []authorizer.ConditionsAwareDecision{
				authorizer.ConditionsAwareDecisionFromParts(42, "", nil),
				authorizer.AuthorizerFunc(func(_ context.Context, _ authorizer.Attributes) (authorizer.Decision, string, error) {
					return 42, "", nil
				}).ConditionsAwareAuthorize(ctx, sampleAttrs),
			},
			wantIsDeny:          true,
			wantIsUnconditional: true,
			wantReason:          "",
			wantAnyError:        true,
			wantString:          `Deny(err="unknown unconditional decision type: 42")`,
		},
		{
			name: "from parts: unsupported mode with other error",
			testDecisions: []authorizer.ConditionsAwareDecision{
				authorizer.ConditionsAwareDecisionFromParts(42, "foo", otherErr),
				authorizer.AuthorizerFunc(func(_ context.Context, _ authorizer.Attributes) (authorizer.Decision, string, error) {
					return 42, "foo", otherErr
				}).ConditionsAwareAuthorize(ctx, sampleAttrs),
			},
			wantIsDeny:          true,
			wantIsUnconditional: true,
			wantReason:          "foo",
			wantErrorIs:         otherErr,
			wantString:          `Deny(reason="foo", err="[other error, unknown unconditional decision type: 42]")`,
		},
		{
			name: "conditional: single allow condition",
			testDecisions: []authorizer.ConditionsAwareDecision{
				authorizer.ConditionsAwareDecisionConditional(
					"test-authz", nil, nil,
					[]authorizer.Condition{authorizer.GenericCondition{ID: "allow-cond"}},
				),
			},
			wantIsConditional:   true,
			wantIsUnconditional: false,
			wantString:          `Conditional(maps=1, fallback=NoOpinion)`,
		},
		{
			name: "conditional: with union fallback Allow",
			testDecisions: []authorizer.ConditionsAwareDecision{
				authorizer.ConditionsAwareDecisionConditionalMaps(
					[]authorizer.ConditionsMap{
						makeConditionsMap("a1", nil, nil,
							[]authorizer.Condition{authorizer.GenericCondition{ID: "c1"}}),
					},
					authorizer.ConditionsAwareDecisionAllow("ok", nil),
				),
			},
			wantIsConditional:   true,
			wantIsUnconditional: false,
			wantString:          `Conditional(maps=1, fallback=Allow(reason="ok"))`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for i, d := range tt.testDecisions {
				t.Run(fmt.Sprint(i), func(t *testing.T) {
					if got := d.IsAllow(); got != tt.wantIsAllowed {
						t.Errorf("IsAllow() = %v, want %v", got, tt.wantIsAllowed)
					}
					if got := d.IsNoOpinion(); got != tt.wantIsNoOpinion {
						t.Errorf("IsNoOpinion() = %v, want %v", got, tt.wantIsNoOpinion)
					}
					if got := d.IsDeny(); got != tt.wantIsDeny {
						t.Errorf("IsDeny() = %v, want %v", got, tt.wantIsDeny)
					}
					if got := d.IsConditional(); got != tt.wantIsConditional {
						t.Errorf("IsConditional() = %v, want %v", got, tt.wantIsConditional)
					}
					if got := d.IsUnconditional(); got != tt.wantIsUnconditional {
						t.Errorf("IsUnconditional() = %v, want %v", got, tt.wantIsUnconditional)
					}
					if got := d.Reason(); got != tt.wantReason {
						t.Errorf("Reason() = %q, want %q", got, tt.wantReason)
					}
					gotErr := d.Error()
					if tt.wantAnyError {
						if gotErr == nil {
							t.Errorf("Error() = nil, want some error")
						}
					} else if !errors.Is(gotErr, tt.wantErrorIs) {
						t.Errorf("Error() = %v, want %v", gotErr, tt.wantErrorIs)
					}
					if got := d.String(); got != tt.wantString {
						t.Errorf("String() = %q, want %q", got, tt.wantString)
					}
				})
			}
		})
	}
}

func TestConditionsAwareDecisionConditional(t *testing.T) {
	makeAllowConds := func(n int) []authorizer.Condition {
		out := make([]authorizer.Condition, n)
		for i := range n {
			out[i] = authorizer.GenericCondition{ID: fmt.Sprintf("cond-%d", i)}
		}
		return out
	}

	tests := []struct {
		name              string
		authorizerName    string
		deny              []authorizer.Condition
		noOpinion         []authorizer.Condition
		allow             []authorizer.Condition
		wantIsConditional bool
		wantIsNoOpinion   bool
		wantIsDeny        bool
		wantAnyError      bool
		wantString        string
	}{
		{
			name:              "valid single allow condition",
			authorizerName:    "a",
			allow:             []authorizer.Condition{authorizer.GenericCondition{ID: "foo"}},
			wantIsConditional: true,
			wantString:        `Conditional(maps=1, fallback=NoOpinion)`,
		},
		{
			name:              "valid max conditions",
			authorizerName:    "a",
			allow:             makeAllowConds(authorizer.MaxConditionsPerMap),
			wantIsConditional: true,
		},
		{
			name:            "too many conditions",
			authorizerName:  "a",
			allow:           makeAllowConds(authorizer.MaxConditionsPerMap + 1),
			wantIsNoOpinion: true,
			wantAnyError:    true,
			wantString:      fmt.Sprintf(`NoOpinion(reason="failed closed", err="too many conditions: %d exceeds maximum of %d")`, authorizer.MaxConditionsPerMap+1, authorizer.MaxConditionsPerMap),
		},
		{
			name:           "too many conditions with deny",
			authorizerName: "a",
			deny:           makeAllowConds(authorizer.MaxConditionsPerMap + 1),
			wantIsDeny:     true,
			wantAnyError:   true,
		},
		{
			name:            "empty conditions",
			authorizerName:  "a",
			wantIsNoOpinion: true,
			wantAnyError:    true,
			wantString:      `NoOpinion(reason="no conditions", err="at least one condition must be provided to ConditionsAwareDecisionConditional, got none")`,
		},
		{
			name:            "noopinion-only short-circuits to NoOpinion",
			authorizerName:  "a",
			noOpinion:       []authorizer.Condition{authorizer.GenericCondition{ID: "nop-1"}},
			wantIsNoOpinion: true,
			wantString:      `NoOpinion`,
		},
		{
			name:           "nil condition is a validation error (allow bucket)",
			authorizerName: "a",
			allow: []authorizer.Condition{
				authorizer.GenericCondition{ID: "foo"},
				nil,
			},
			wantIsNoOpinion: true,
			wantAnyError:    true,
			wantString:      `NoOpinion(reason="failed closed", err="encountered nil condition")`,
		},
		{
			name:           "nil condition is a validation error (deny bucket)",
			authorizerName: "a",
			deny: []authorizer.Condition{
				authorizer.GenericCondition{ID: "foo"},
				nil,
			},
			wantIsDeny:   true,
			wantAnyError: true,
			wantString:   `Deny(reason="failed closed", err="encountered nil condition")`,
		},
		{
			name:           "typed nil condition is a validation error",
			authorizerName: "a",
			allow: []authorizer.Condition{
				authorizer.GenericCondition{ID: "foo"},
				typedNilCondition(),
			},
			wantIsNoOpinion: true,
			wantAnyError:    true,
		},
		{
			name:           "duplicate IDs across buckets",
			authorizerName: "a",
			deny:           []authorizer.Condition{authorizer.GenericCondition{ID: "foo"}},
			allow:          []authorizer.Condition{authorizer.GenericCondition{ID: "foo"}},
			wantIsDeny:     true,
			wantAnyError:   true,
			wantString:     `Deny(reason="failed closed", err="duplicate condition ID \"foo\"")`,
		},
		{
			name:           "invalid condition ID",
			authorizerName: "a",
			deny:           []authorizer.Condition{authorizer.GenericCondition{ID: "not a valid label"}},
			wantIsDeny:     true,
			wantAnyError:   true,
		},
		{
			name:            "invalid condition type",
			authorizerName:  "a",
			noOpinion:       []authorizer.Condition{authorizer.GenericCondition{ID: "bar", Type: "not a valid label"}},
			allow:           []authorizer.Condition{authorizer.GenericCondition{ID: "foo"}},
			wantIsNoOpinion: true,
			wantAnyError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := authorizer.ConditionsAwareDecisionConditional(tt.authorizerName, tt.deny, tt.noOpinion, tt.allow)
			if got := d.IsConditional(); got != tt.wantIsConditional {
				t.Errorf("IsConditional() = %v, want %v (decision=%s)", got, tt.wantIsConditional, d)
			}
			if got := d.IsNoOpinion(); got != tt.wantIsNoOpinion {
				t.Errorf("IsNoOpinion() = %v, want %v (decision=%s)", got, tt.wantIsNoOpinion, d)
			}
			if got := d.IsDeny(); got != tt.wantIsDeny {
				t.Errorf("IsDeny() = %v, want %v (decision=%s)", got, tt.wantIsDeny, d)
			}
			if tt.wantAnyError && d.Error() == nil {
				t.Errorf("Error() = nil, want some error (decision=%s)", d)
			}
			if tt.wantString != "" {
				if got := d.String(); got != tt.wantString {
					t.Errorf("String() = %q, want %q", got, tt.wantString)
				}
			}
		})
	}
}

func TestConditionsAwareDecisionConditionalPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for empty authorizerName, got none")
		}
	}()
	authorizer.ConditionsAwareDecisionConditional("", nil, nil, []authorizer.Condition{authorizer.GenericCondition{ID: "x"}})
}

func TestConditionsAwareDecisionUnconditionalParts(t *testing.T) {
	tests := []struct {
		name         string
		decision     authorizer.ConditionsAwareDecision
		wantDecision authorizer.Decision
		wantReason   string
	}{
		{
			name:         "unconditional Allow",
			decision:     authorizer.ConditionsAwareDecisionAllow("ok", nil),
			wantDecision: authorizer.DecisionAllow,
			wantReason:   "ok",
		},
		{
			name:         "unconditional Deny",
			decision:     authorizer.ConditionsAwareDecisionDeny("no", nil),
			wantDecision: authorizer.DecisionDeny,
			wantReason:   "no",
		},
		{
			name:         "unconditional NoOpinion",
			decision:     authorizer.ConditionsAwareDecisionNoOpinion("skip", nil),
			wantDecision: authorizer.DecisionNoOpinion,
			wantReason:   "skip",
		},
		{
			name: "conditional allow-only: fail-closed to NoOpinion",
			decision: authorizer.ConditionsAwareDecisionConditional(
				"a", nil, nil,
				[]authorizer.Condition{authorizer.GenericCondition{ID: "c1"}},
			),
			wantDecision: authorizer.DecisionNoOpinion,
			wantReason:   "failed closed: tried to return conditional decision to conditions-unaware authorizer",
		},
		{
			name: "conditional deny: fail-closed to Deny",
			decision: authorizer.ConditionsAwareDecisionConditional(
				"a",
				[]authorizer.Condition{authorizer.GenericCondition{ID: "c1"}},
				nil, nil,
			),
			wantDecision: authorizer.DecisionDeny,
			wantReason:   "failed closed: tried to return conditional decision to conditions-unaware authorizer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, reason, _ := tt.decision.UnconditionalParts()
			if decision != tt.wantDecision {
				t.Errorf("decision = %v, want %v", decision, tt.wantDecision)
			}
			if reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

func TestConditionsMapEvaluate(t *testing.T) {
	evalErr := errors.New("eval error")

	trueResult := authorizer.ConditionEvaluationResultBoolean(true)
	falseResult := authorizer.ConditionEvaluationResultBoolean(false)
	errResult := authorizer.ConditionEvaluationResultError(evalErr)

	cond := func(id string, result authorizer.ConditionEvaluationResult) authorizer.GenericCondition {
		return authorizer.GenericCondition{
			ID: id,
			EvaluateFunc: func(context.Context, authorizer.ConditionsData) authorizer.ConditionEvaluationResult {
				return result
			},
		}
	}
	condDesc := func(id, desc string, result authorizer.ConditionEvaluationResult) authorizer.GenericCondition {
		c := cond(id, result)
		c.Description = desc
		return c
	}
	unevalCond := func(id string) authorizer.GenericCondition {
		return authorizer.GenericCondition{ID: id} // nil EvaluateFunc → unevaluatable
	}

	// fillerDenyFalse is a deny condition that always evaluates to false. Used in sub-cases
	// that need to exercise Evaluate() on otherwise noOpinion-only input (bypassing the
	// constructor's short-circuit which folds noOpinion-only maps to NoOpinion directly).
	fillerDenyFalse := []authorizer.Condition{cond("filler-deny-false", falseResult)}

	type subCase struct {
		name                string
		denyConditions      []authorizer.Condition
		noOpinionConditions []authorizer.Condition
		allowConditions     []authorizer.Condition
		evaluateFunc        func(context.Context, authorizer.ConditionsData, authorizer.Condition) authorizer.ConditionEvaluationResult
	}

	tests := []struct {
		name               string
		subCases           []subCase
		wantString         string
		wantIsConditional  bool
		wantDenyCount      int
		wantNoOpinionCount int
		wantAllowCount     int
	}{
		// Deny: at least one deny condition matched
		{
			name:       "deny: at least one deny condition matched",
			wantString: `Deny(reason="condition \"deny-1\" denied the request")`,
			subCases: []subCase{
				{
					name:           "minimal",
					denyConditions: []authorizer.Condition{cond("deny-1", trueResult)},
				},
				{
					name: "matching deny trumps any other case",
					denyConditions: []authorizer.Condition{
						cond("deny-no", falseResult),
						unevalCond("deny-uneval"),
						cond("deny-err", errResult),
						cond("deny-1", trueResult),
					},
					noOpinionConditions: []authorizer.Condition{
						cond("nop-yes", trueResult),
						cond("nop-err", errResult),
						cond("nop-no", falseResult),
						unevalCond("nop-uneval"),
					},
					allowConditions: []authorizer.Condition{
						cond("allow-yes", trueResult),
						cond("allow-no", falseResult),
						cond("allow-err", errResult),
						unevalCond("allow-uneval"),
					},
				},
				{
					name:           "with erroring deny (error ignored due to match)",
					denyConditions: []authorizer.Condition{cond("deny-1", trueResult), cond("deny-err", errResult)},
				},
				{
					name:           "with unevaluatable deny (ignored due to match)",
					denyConditions: []authorizer.Condition{cond("deny-1", trueResult), unevalCond("deny-uneval")},
				},
				{
					name:                "deny match with false nop and allow",
					denyConditions:      []authorizer.Condition{cond("deny-1", trueResult)},
					noOpinionConditions: []authorizer.Condition{cond("nop-1", falseResult)},
					allowConditions:     []authorizer.Condition{cond("allow-1", falseResult)},
				},
				{
					name:                "deny match with unevaluatable nop and allow",
					denyConditions:      []authorizer.Condition{cond("deny-1", trueResult)},
					noOpinionConditions: []authorizer.Condition{unevalCond("nop-1")},
					allowConditions:     []authorizer.Condition{unevalCond("allow-1")},
				},
				{
					name:           "via evaluateFunc fallback (condition unevaluatable, evaluateFunc returns true)",
					denyConditions: []authorizer.Condition{unevalCond("deny-1")},
					evaluateFunc: func(context.Context, authorizer.ConditionsData, authorizer.Condition) authorizer.ConditionEvaluationResult {
						return authorizer.ConditionEvaluationResultBoolean(true)
					},
				},
				{
					name:                "deny match takes precedence; evaluateFunc never called",
					denyConditions:      []authorizer.Condition{cond("deny-1", trueResult)},
					noOpinionConditions: []authorizer.Condition{cond("nop-1", trueResult)},
					allowConditions:     []authorizer.Condition{cond("allow-1", trueResult)},
					evaluateFunc: func(context.Context, authorizer.ConditionsData, authorizer.Condition) authorizer.ConditionEvaluationResult {
						panic("evaluateFunc should never be called when all conditions self-evaluate")
					},
				},
			},
		},
		{
			name:       "deny: at least one deny condition matched with description",
			wantString: `Deny(reason="condition \"deny-1\" denied the request with description \"access denied\"")`,
			subCases: []subCase{
				{
					name:           "minimal",
					denyConditions: []authorizer.Condition{condDesc("deny-1", "access denied", trueResult)},
				},
			},
		},

		// Deny: error, fail closed
		{
			name:       "deny: error fail closed",
			wantString: `Deny(reason="one or more conditional evaluation errors occurred", err="condition \"deny-1\" with effect=Deny produced error: eval error")`,
			subCases: []subCase{
				{
					name:           "minimal",
					denyConditions: []authorizer.Condition{cond("deny-1", errResult)},
				},
				{
					name:           "error takes precedence over unevaluatable",
					denyConditions: []authorizer.Condition{cond("deny-1", errResult), unevalCond("deny-uneval")},
				},
				{
					name: "deny error trumps noopinion and allow of any form",
					denyConditions: []authorizer.Condition{
						cond("deny-no", falseResult),
						unevalCond("deny-uneval"),
						cond("deny-1", errResult),
					},
					noOpinionConditions: []authorizer.Condition{
						cond("nop-yes", trueResult),
						cond("nop-no", falseResult),
						unevalCond("nop-uneval"),
					},
					allowConditions: []authorizer.Condition{
						cond("allow-yes", trueResult),
						cond("allow-no", falseResult),
						unevalCond("allow-uneval"),
					},
				},
			},
		},

		// NoOpinion: at least one noopinion condition matched
		{
			name:       "noopinion: at least one noopinion condition matched",
			wantString: `NoOpinion(reason="condition \"nop-1\" evaluated to NoOpinion")`,
			subCases: []subCase{
				{
					name:                "minimal",
					denyConditions:      fillerDenyFalse,
					noOpinionConditions: []authorizer.Condition{cond("nop-1", trueResult)},
				},
				{
					name:                "nop match trumps allow",
					denyConditions:      fillerDenyFalse,
					noOpinionConditions: []authorizer.Condition{cond("nop-1", trueResult)},
					allowConditions:     []authorizer.Condition{cond("allow-1", trueResult)},
				},
				{
					name:                "with erroring nop (error ignored due to match)",
					denyConditions:      fillerDenyFalse,
					noOpinionConditions: []authorizer.Condition{cond("nop-1", trueResult), cond("nop-err", errResult)},
				},
				{
					name:                "with unevaluatable nop (ignored due to match)",
					denyConditions:      fillerDenyFalse,
					noOpinionConditions: []authorizer.Condition{cond("nop-1", trueResult), unevalCond("nop-uneval")},
				},
			},
		},
		{
			name:       "noopinion: at least one noopinion condition matched with description",
			wantString: `NoOpinion(reason="condition \"nop-1\" evaluated to NoOpinion with description \"not relevant\"")`,
			subCases: []subCase{
				{
					name:                "minimal",
					denyConditions:      fillerDenyFalse,
					noOpinionConditions: []authorizer.Condition{condDesc("nop-1", "not relevant", trueResult)},
				},
			},
		},

		// NoOpinion: error, fail closed (from nop)
		{
			name:       "noopinion: nop error fail closed",
			wantString: `NoOpinion(reason="one or more conditional evaluation errors occurred", err="condition \"nop-1\" with effect=NoOpinion produced error: eval error")`,
			subCases: []subCase{
				{
					name:                "minimal",
					denyConditions:      fillerDenyFalse,
					noOpinionConditions: []authorizer.Condition{cond("nop-1", errResult)},
				},
				{
					name:                "nop error trumps matching allow",
					denyConditions:      fillerDenyFalse,
					noOpinionConditions: []authorizer.Condition{cond("nop-1", errResult)},
					allowConditions:     []authorizer.Condition{cond("allow-1", trueResult)},
				},
			},
		},

		// NoOpinion: error, fail closed (from allow)
		{
			name:       "noopinion: single allow error fail closed",
			wantString: `NoOpinion(reason="one or more conditional evaluation errors occurred", err="condition \"allow-1\" with effect=Allow produced error: eval error")`,
			subCases: []subCase{
				{
					name:            "minimal",
					allowConditions: []authorizer.Condition{cond("allow-1", errResult)},
				},
				{
					name:            "via evaluateFunc fallback (condition unevaluatable, evaluateFunc errors)",
					allowConditions: []authorizer.Condition{unevalCond("allow-1")},
					evaluateFunc: func(context.Context, authorizer.ConditionsData, authorizer.Condition) authorizer.ConditionEvaluationResult {
						return authorizer.ConditionEvaluationResultError(evalErr)
					},
				},
				{
					name:            "condition errors, evaluateFunc not called",
					allowConditions: []authorizer.Condition{cond("allow-1", errResult)},
					evaluateFunc: func(context.Context, authorizer.ConditionsData, authorizer.Condition) authorizer.ConditionEvaluationResult {
						panic("should not be called when condition self-evaluates to error")
					},
				},
			},
		},
		{
			name:       "noopinion: multiple allow errors fail closed",
			wantString: `NoOpinion(reason="one or more conditional evaluation errors occurred", err="[condition \"allow-1\" with effect=Allow produced error: eval error, condition \"allow-2\" with effect=Allow produced error: eval error]")`,
			subCases: []subCase{
				{
					name: "minimal",
					allowConditions: []authorizer.Condition{
						cond("allow-1", errResult),
						cond("allow-2", errResult),
					},
				},
			},
		},

		// NoOpinion: no conditions matched
		{
			name:       "noopinion: no conditions matched",
			wantString: `NoOpinion(reason="no conditions matched")`,
			subCases: []subCase{
				{
					name:           "single deny false",
					denyConditions: []authorizer.Condition{cond("deny-1", falseResult)},
				},
				{
					name:            "single allow false",
					allowConditions: []authorizer.Condition{cond("allow-1", falseResult)},
				},
				{
					name:            "all effects false",
					denyConditions:  []authorizer.Condition{cond("deny-1", falseResult)},
					allowConditions: []authorizer.Condition{cond("allow-1", falseResult)},
				},
				{
					name:            "via evaluateFunc fallback (unevaluatable, evaluateFunc false)",
					allowConditions: []authorizer.Condition{unevalCond("allow-1")},
					evaluateFunc: func(context.Context, authorizer.ConditionsData, authorizer.Condition) authorizer.ConditionEvaluationResult {
						return authorizer.ConditionEvaluationResultBoolean(false)
					},
				},
			},
		},

		// NoOpinion: unevaluatable nop with no allow conditions
		{
			name:       "noopinion: unevaluatable nop, no allow -> NoOpinion",
			wantString: `NoOpinion(reason="at least one NoOpinion condition matched, or no conditions matched")`,
			subCases: []subCase{
				{
					name:                "minimal",
					denyConditions:      fillerDenyFalse,
					noOpinionConditions: []authorizer.Condition{unevalCond("nop-1")},
				},
			},
		},

		// Allow: at least one allow condition matched
		{
			name:       "allow: at least one allow condition matched",
			wantString: `Allow(reason="condition \"allow-1\" allowed the request")`,
			subCases: []subCase{
				{
					name:            "minimal",
					allowConditions: []authorizer.Condition{cond("allow-1", trueResult)},
				},
				{
					name:                "with false deny and nop",
					denyConditions:      []authorizer.Condition{cond("deny-1", falseResult)},
					noOpinionConditions: []authorizer.Condition{cond("nop-1", falseResult)},
					allowConditions:     []authorizer.Condition{cond("allow-1", trueResult)},
				},
				{
					name:            "evaluateFunc not called (condition self-evaluates)",
					allowConditions: []authorizer.Condition{cond("allow-1", trueResult)},
					evaluateFunc: func(context.Context, authorizer.ConditionsData, authorizer.Condition) authorizer.ConditionEvaluationResult {
						panic("should not be called")
					},
				},
				{
					name:            "via evaluateFunc fallback (condition unevaluatable, evaluateFunc returns true)",
					allowConditions: []authorizer.Condition{unevalCond("allow-1")},
					evaluateFunc: func(context.Context, authorizer.ConditionsData, authorizer.Condition) authorizer.ConditionEvaluationResult {
						return authorizer.ConditionEvaluationResultBoolean(true)
					},
				},
			},
		},
		{
			name:       "allow: condition matched with description",
			wantString: `Allow(reason="condition \"allow-1\" allowed the request with description \"access granted\"")`,
			subCases: []subCase{
				{
					name:            "minimal",
					allowConditions: []authorizer.Condition{condDesc("allow-1", "access granted", trueResult)},
				},
			},
		},
		{
			name:       "allow: condition matched with error warning from sibling allow",
			wantString: `Allow(reason="condition \"allow-1\" allowed the request", err="condition \"allow-err\" with effect=Allow produced error: eval error")`,
			subCases: []subCase{
				{
					name: "minimal",
					allowConditions: []authorizer.Condition{
						cond("allow-err", errResult),
						cond("allow-1", trueResult),
					},
				},
			},
		},

		// Conditional: refined map returned for unevaluatable conditions
		{
			name:               "conditionsmap: deny unevaluatable, nop and allow present",
			wantIsConditional:  true,
			wantDenyCount:      1,
			wantNoOpinionCount: 1,
			wantAllowCount:     1,
			subCases: []subCase{
				{
					name:                "minimal",
					denyConditions:      []authorizer.Condition{unevalCond("deny-1")},
					noOpinionConditions: []authorizer.Condition{cond("nop-1", trueResult)},
					allowConditions:     []authorizer.Condition{cond("allow-1", trueResult)},
				},
				{
					name:                "one deny false, one deny unevaluatable",
					denyConditions:      []authorizer.Condition{cond("deny-false", falseResult), unevalCond("deny-1")},
					noOpinionConditions: []authorizer.Condition{cond("nop-1", trueResult)},
					allowConditions:     []authorizer.Condition{cond("allow-1", trueResult)},
				},
			},
		},
		{
			name:               "conditionsmap: nop unevaluatable, allow present",
			wantIsConditional:  true,
			wantNoOpinionCount: 1,
			wantAllowCount:     1,
			subCases: []subCase{
				{
					name:                "minimal",
					denyConditions:      fillerDenyFalse,
					noOpinionConditions: []authorizer.Condition{unevalCond("nop-1")},
					allowConditions:     []authorizer.Condition{cond("allow-1", trueResult)},
				},
			},
		},
		{
			name:              "conditionsmap: allow unevaluatable",
			wantIsConditional: true,
			wantAllowCount:    1,
			subCases: []subCase{
				{
					name:            "nil evaluateFunc",
					allowConditions: []authorizer.Condition{unevalCond("allow-1")},
				},
				{
					name:            "evaluateFunc also returns unevaluatable",
					allowConditions: []authorizer.Condition{unevalCond("allow-1")},
					evaluateFunc: func(context.Context, authorizer.ConditionsData, authorizer.Condition) authorizer.ConditionEvaluationResult {
						return authorizer.ConditionsEvaluationResultUnevaluatable()
					},
				},
				{
					name:                "with false deny and nop",
					denyConditions:      []authorizer.Condition{cond("deny-1", falseResult)},
					noOpinionConditions: []authorizer.Condition{cond("nop-1", falseResult)},
					allowConditions:     []authorizer.Condition{unevalCond("allow-1")},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, sc := range tt.subCases {
				t.Run(sc.name, func(t *testing.T) {
					d := buildAndEvaluate(t, "test-authz", sc.denyConditions, sc.noOpinionConditions, sc.allowConditions, sc.evaluateFunc)

					if tt.wantString != "" {
						if got := d.String(); got != tt.wantString {
							t.Errorf("String() = %q, want %q", got, tt.wantString)
						}
					}
					if got := d.IsConditional(); got != tt.wantIsConditional {
						t.Errorf("IsConditional() = %v, want %v", got, tt.wantIsConditional)
					}
					if tt.wantIsConditional {
						maps := d.ConditionsMaps()
						if len(maps) != 1 {
							t.Fatalf("expected 1 ConditionsMap, got %d", len(maps))
						}
						gotDeny, gotNop, gotAllow := countConditions(maps[0])
						if gotDeny != tt.wantDenyCount {
							t.Errorf("deny count = %d, want %d", gotDeny, tt.wantDenyCount)
						}
						if gotNop != tt.wantNoOpinionCount {
							t.Errorf("noopinion count = %d, want %d", gotNop, tt.wantNoOpinionCount)
						}
						if gotAllow != tt.wantAllowCount {
							t.Errorf("allow count = %d, want %d", gotAllow, tt.wantAllowCount)
						}
					}
				})
			}
		})
	}
}

// buildAndEvaluate constructs a ConditionsMap via the constructor, extracts it, and
// calls Evaluate. Fails the test if the constructor returns a non-conditional decision.
func buildAndEvaluate(
	t *testing.T,
	authorizerName string,
	deny, noOpinion, allow []authorizer.Condition,
	evaluateFunc func(context.Context, authorizer.ConditionsData, authorizer.Condition) authorizer.ConditionEvaluationResult,
) authorizer.ConditionsAwareDecision {
	t.Helper()
	d := authorizer.ConditionsAwareDecisionConditional(authorizerName, deny, noOpinion, allow)
	if !d.IsConditional() {
		t.Fatalf("expected conditional from constructor, got %s", d)
	}
	maps := d.ConditionsMaps()
	if len(maps) != 1 {
		t.Fatalf("expected 1 ConditionsMap, got %d", len(maps))
	}
	return maps[0].Evaluate(t.Context(), authorizer.ConditionsData{}, evaluateFunc)
}

func countConditions(cm authorizer.ConditionsMap) (deny, noOpinion, allow int) {
	for range cm.DenyConditions() {
		deny++
	}
	for range cm.NoOpinionConditions() {
		noOpinion++
	}
	for range cm.AllowConditions() {
		allow++
	}
	return
}

func TestConditionEvaluationResultIsFalse(t *testing.T) {
	if authorizer.ConditionEvaluationResultBoolean(false).IsFalse() != true {
		t.Error("IsFalse() = false, want true for a false result")
	}
	if authorizer.ConditionEvaluationResultBoolean(true).IsFalse() != false {
		t.Error("IsFalse() = true, want false for a true result")
	}
	if authorizer.ConditionEvaluationResultError(errors.New("e")).IsFalse() != false {
		t.Error("IsFalse() = true, want false for an error result")
	}
	if authorizer.ConditionsEvaluationResultUnevaluatable().IsFalse() != false {
		t.Error("IsFalse() = true, want false for an unevaluatable result")
	}
}

func TestConditionsAwareDecisionConditionalMapsEmpty(t *testing.T) {
	fallback := authorizer.ConditionsAwareDecisionAllow("fallback", nil)
	d := authorizer.ConditionsAwareDecisionConditionalMaps(nil, fallback)
	if !d.IsAllow() {
		t.Errorf("empty conditionsMaps should return fallback, got %s", d)
	}
}

func TestConditionsMapIteratorEarlyBreak(t *testing.T) {
	falseResult := authorizer.ConditionEvaluationResultBoolean(false)
	cond := func(id string) authorizer.Condition {
		return authorizer.GenericCondition{
			ID: id,
			EvaluateFunc: func(context.Context, authorizer.ConditionsData) authorizer.ConditionEvaluationResult {
				return falseResult
			},
		}
	}

	d := authorizer.ConditionsAwareDecisionConditional(
		"a",
		[]authorizer.Condition{cond("d1"), cond("d2")},
		[]authorizer.Condition{cond("n1"), cond("n2")},
		[]authorizer.Condition{cond("a1"), cond("a2")},
	)
	cm := d.ConditionsMaps()[0]

	for _, iter := range []struct {
		name string
		seq  func(func(authorizer.Condition) bool)
	}{
		{"DenyConditions", cm.DenyConditions()},
		{"NoOpinionConditions", cm.NoOpinionConditions()},
		{"AllowConditions", cm.AllowConditions()},
	} {
		t.Run(iter.name, func(t *testing.T) {
			count := 0
			for range iter.seq {
				count++
				break
			}
			if count != 1 {
				t.Errorf("expected 1 iteration after early break, got %d", count)
			}
		})
	}
}

func TestConditionsMapEvaluateDeepCopyEmptyBuckets(t *testing.T) {
	// deny-only unevaluatable triggers deepCopyConditions(nil) for nop and allow.
	d := authorizer.ConditionsAwareDecisionConditional(
		"a",
		[]authorizer.Condition{authorizer.GenericCondition{ID: "deny-uneval"}},
		nil, nil,
	)
	cm := d.ConditionsMaps()[0]
	result := cm.Evaluate(t.Context(), authorizer.ConditionsData{}, nil)
	if !result.IsConditional() {
		t.Fatalf("expected refined conditional, got %s", result)
	}
	refined := result.ConditionsMaps()[0]
	deny, nop, allow := countConditions(refined)
	if deny != 1 || nop != 0 || allow != 0 {
		t.Errorf("deny=%d nop=%d allow=%d, want 1/0/0", deny, nop, allow)
	}
}

func TestConditionsAwareDecisionConditionalExpressionLimits(t *testing.T) {
	bigExpr := string(make([]byte, authorizer.MaxConditionExpressionBytes+1))
	bigDesc := string(make([]byte, authorizer.MaxConditionDescriptionBytes+1))

	t.Run("expression too long", func(t *testing.T) {
		d := authorizer.ConditionsAwareDecisionConditional(
			"a", nil, nil,
			[]authorizer.Condition{authorizer.GenericCondition{ID: "c", Condition: bigExpr}},
		)
		if !d.IsNoOpinion() {
			t.Errorf("expected NoOpinion for oversized expression, got %s", d)
		}
		if d.Error() == nil {
			t.Error("expected validation error, got nil")
		}
	})

	t.Run("description too long", func(t *testing.T) {
		d := authorizer.ConditionsAwareDecisionConditional(
			"a", nil, nil,
			[]authorizer.Condition{authorizer.GenericCondition{ID: "c", Description: bigDesc}},
		)
		if !d.IsNoOpinion() {
			t.Errorf("expected NoOpinion for oversized description, got %s", d)
		}
		if d.Error() == nil {
			t.Error("expected validation error, got nil")
		}
	})
}

func TestConditionsAwareDecisionConditionalNoOpinionOnlyInvalidID(t *testing.T) {
	// noOpinion-only short-circuit still validates condition IDs.
	d := authorizer.ConditionsAwareDecisionConditional(
		"a", nil,
		[]authorizer.Condition{authorizer.GenericCondition{ID: "not a valid label"}},
		nil,
	)
	if !d.IsNoOpinion() {
		t.Errorf("expected NoOpinion, got %s", d)
	}
	if d.Error() == nil {
		t.Error("expected validation error, got nil")
	}
}

func TestConditionsMapEvaluateDeepCopy(t *testing.T) {
	marker := "original"

	// Unevaluatable deny → refined map should deep-copy nop and allow.
	d := authorizer.ConditionsAwareDecisionConditional(
		"test-authz",
		[]authorizer.Condition{authorizer.GenericCondition{ID: "deny-uneval"}},
		[]authorizer.Condition{&deepCopyTracker{id: "nop-1", marker: &marker}},
		[]authorizer.Condition{&deepCopyTracker{id: "allow-1", marker: &marker}},
	)
	if !d.IsConditional() {
		t.Fatalf("expected conditional, got %s", d)
	}
	cm := d.ConditionsMaps()[0]

	result := cm.Evaluate(t.Context(), authorizer.ConditionsData{}, nil)
	if !result.IsConditional() {
		t.Fatalf("expected refined Conditional, got %s", result)
	}

	refined := result.ConditionsMaps()[0]
	if refined.Length() != 3 {
		t.Fatalf("expected 3 conditions, got %d", refined.Length())
	}

	// Mutate the original.
	marker = "mutated"

	for c := range refined.NoOpinionConditions() {
		if tracker, ok := c.(*deepCopyTracker); ok && *tracker.marker != "original" {
			t.Errorf("deep copy failed for noOpinion: got %q, want \"original\"", *tracker.marker)
		}
	}
	for c := range refined.AllowConditions() {
		if tracker, ok := c.(*deepCopyTracker); ok && *tracker.marker != "original" {
			t.Errorf("deep copy failed for allow: got %q, want \"original\"", *tracker.marker)
		}
	}
}
// sampleAuthorizer is a Named, conditions-aware authorizer used in integration tests.
//   - alice: unconditional Allow for all verbs.
//   - bob: unconditional Deny for all verbs.
//   - carol: Allow lists; conditional Allow for writes (object.labels.owner == "carol").
//   - dave: Allow lists; conditional Deny for writes that touch the "supersecret" label.
//   - anyone else: NoOpinion.
type sampleAuthorizer struct{}

var _ authorizer.Authorizer = sampleAuthorizer{}

var _ authorizer.Named = sampleAuthorizer{}

func (sampleAuthorizer) AuthorizerName() string { return "sample" }

func (a sampleAuthorizer) Authorize(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
	decision, reason, err := a.ConditionsAwareAuthorize(ctx, attrs).UnconditionalParts()
	return decision, reason, err
}

func (a sampleAuthorizer) ConditionsAwareAuthorize(_ context.Context, attrs authorizer.Attributes) authorizer.ConditionsAwareDecision {
	name := attrs.GetUser().GetName()
	verb := attrs.GetVerb()

	switch name {
	case "alice":
		return authorizer.ConditionsAwareDecisionAllow("", nil)
	case "bob":
		return authorizer.ConditionsAwareDecisionDeny("", nil)
	case "carol":
		switch verb {
		case "list":
			return authorizer.ConditionsAwareDecisionAllow("", nil)
		case "update":
			return authorizer.ConditionsAwareDecisionConditional(
				"sample", nil, nil,
				[]authorizer.Condition{
					authorizer.GenericCondition{
						ID:   "owner-label-is-carol",
						Type: "test-cel-conditions-type",
						Condition: `
							(oldObject != null ? (has(oldObject.metadata) && has(oldObject.metadata.labels) && has(oldObject.metadata.labels.owner) && oldObject.metadata.labels.owner == "carol") : true) &&
							(object != null ? (has(object.metadata) && has(object.metadata.labels) && has(object.metadata.labels.owner) && object.metadata.labels.owner == "carol") : true)
						`,
					},
				},
			)
		default:
			return authorizer.ConditionsAwareDecisionNoOpinion("", nil)
		}
	case "dave":
		switch verb {
		case "list":
			return authorizer.ConditionsAwareDecisionAllow("", nil)
		case "create", "update", "delete":
			return authorizer.ConditionsAwareDecisionConditional(
				"sample",
				[]authorizer.Condition{
					authorizer.GenericCondition{
						ID:        "deny-supersecret-on-oldObject",
						Type:      "test-cel-conditions-type",
						Condition: `oldObject != null && has(oldObject.metadata) && has(oldObject.metadata.labels) && has(oldObject.metadata.labels.supersecret)`,
					},
					authorizer.GenericCondition{
						ID:        "deny-supersecret-on-object",
						Type:      "test-cel-conditions-type",
						Condition: `object != null && has(object.metadata) && has(object.metadata.labels) && has(object.metadata.labels.supersecret)`,
					},
				},
				nil, nil,
			)
		default:
			return authorizer.ConditionsAwareDecisionNoOpinion("", nil)
		}
	default:
		return authorizer.ConditionsAwareDecisionNoOpinion("", nil)
	}
}

func (a sampleAuthorizer) EvaluateConditions(ctx context.Context, unevaluated authorizer.ConditionsAwareDecision, data authorizer.ConditionsData) (authorizer.Decision, string, error) {
	if unevaluated.IsUnconditional() {
		return unevaluated.UnconditionalParts()
	}
	maps := unevaluated.ConditionsMaps()
	if len(maps) != 1 || maps[0].AuthorizerName() != "sample" {
		return authorizer.DecisionDeny, "failed closed", fmt.Errorf("sampleAuthorizer.EvaluateConditions: unexpected decision shape %s", unevaluated)
	}
	return celEvaluateConditionsMap(ctx, maps[0], data)
}

func TestSampleAuthorizer(t *testing.T) {
	type evalCase struct {
		name      string
		object    *unstructured.Unstructured
		oldObject *unstructured.Unstructured
		// [0] = conditions-unaware path, [1] = conditions-aware path
		wantAuthorizeStr [2]string
		wantFinalStr     [2]string
	}

	tests := []struct {
		name  string
		attrs authorizer.AttributesRecord
		cases []evalCase
	}{
		// alice: unconditional Allow for all verbs.
		{
			name:  "alice list",
			attrs: authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "alice"}, Verb: "list"},
			cases: []evalCase{{name: "allow", wantAuthorizeStr: [2]string{"Allow", "Allow"}}},
		},
		{
			name:  "alice create",
			attrs: authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "alice"}, Verb: "create"},
			cases: []evalCase{{name: "allow", wantAuthorizeStr: [2]string{"Allow", "Allow"}}},
		},
		// bob: unconditional Deny for all verbs.
		{
			name:  "bob list",
			attrs: authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "bob"}, Verb: "list"},
			cases: []evalCase{{name: "deny", wantAuthorizeStr: [2]string{"Deny", "Deny"}}},
		},
		// carol: conditional writes.
		{
			name:  "carol list",
			attrs: authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "carol"}, Verb: "list"},
			cases: []evalCase{{name: "allow", wantAuthorizeStr: [2]string{"Allow", "Allow"}}},
		},
		{
			name:  "carol update",
			attrs: authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "carol"}, Verb: "update"},
			cases: []evalCase{
				{
					name:      "both owner=carol",
					object:    objWithLabels(map[string]string{"owner": "carol"}),
					oldObject: objWithLabels(map[string]string{"owner": "carol"}),
					// carol has only Allow conditions → fail-closed is NoOpinion (no Deny conditions).
					wantAuthorizeStr: [2]string{`NoOpinion(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `Conditional(maps=1, fallback=NoOpinion)`},
					wantFinalStr:     [2]string{`NoOpinion(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `Allow(reason="condition \"owner-label-is-carol\" allowed the request")`},
				},
				{
					name:             "old owner=carol, new owner missing",
					object:           objWithLabels(nil),
					oldObject:        objWithLabels(map[string]string{"owner": "carol"}),
					wantAuthorizeStr: [2]string{`NoOpinion(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `Conditional(maps=1, fallback=NoOpinion)`},
					wantFinalStr:     [2]string{`NoOpinion(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `NoOpinion(reason="no conditions matched")`},
				},
			},
		},
		{
			name:  "carol unsupported verb",
			attrs: authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "carol"}, Verb: "patch"},
			cases: []evalCase{{name: "no opinion", wantAuthorizeStr: [2]string{"NoOpinion", "NoOpinion"}}},
		},
		// dave: conditional deny on supersecret.
		{
			name:  "dave list",
			attrs: authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "dave"}, Verb: "list"},
			cases: []evalCase{{name: "allow", wantAuthorizeStr: [2]string{"Allow", "Allow"}}},
		},
		{
			name:  "dave update",
			attrs: authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "dave"}, Verb: "update"},
			cases: []evalCase{
				{
					name:             "both objects with supersecret",
					object:           objWithLabels(map[string]string{"supersecret": "yes"}),
					oldObject:        objWithLabels(map[string]string{"supersecret": "yes"}),
					wantAuthorizeStr: [2]string{`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `Conditional(maps=1, fallback=NoOpinion)`},
					wantFinalStr:     [2]string{`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `Deny(reason="condition \"deny-supersecret-on-oldObject\" denied the request, condition \"deny-supersecret-on-object\" denied the request")`},
				},
				{
					name:             "new with supersecret only",
					object:           objWithLabels(map[string]string{"supersecret": "yes"}),
					oldObject:        objWithLabels(nil),
					wantAuthorizeStr: [2]string{`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `Conditional(maps=1, fallback=NoOpinion)`},
					wantFinalStr:     [2]string{`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `Deny(reason="condition \"deny-supersecret-on-object\" denied the request")`},
				},
				{
					name:             "neither with supersecret",
					object:           objWithLabels(map[string]string{"safe": "yes"}),
					oldObject:        objWithLabels(map[string]string{"safe": "yes"}),
					wantAuthorizeStr: [2]string{`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `Conditional(maps=1, fallback=NoOpinion)`},
					wantFinalStr:     [2]string{`Deny(reason="failed closed: tried to return conditional decision to conditions-unaware authorizer")`, `NoOpinion(reason="no conditions matched")`},
				},
			},
		},
		// unknown user: NoOpinion.
		{
			name:  "unknown user get",
			attrs: authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "unknown"}, Verb: "list"},
			cases: []evalCase{{name: "no opinion", wantAuthorizeStr: [2]string{"NoOpinion", "NoOpinion"}}},
		},
	}

	authz := sampleAuthorizer{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, tc := range tt.cases {
				// If wantFinalStr not set, use wantAuthorizeStr.
				if tc.wantFinalStr[0] == "" {
					tc.wantFinalStr = tc.wantAuthorizeStr
				}

				for i, condAware := range [2]bool{false, true} {
					t.Run(fmt.Sprintf("%s/conditionsAware=%v", tc.name, condAware), func(t *testing.T) {
						var decision authorizer.ConditionsAwareDecision
						if condAware {
							decision = authz.ConditionsAwareAuthorize(t.Context(), tt.attrs)
						} else {
							decision = authorizer.ConditionsAwareDecisionFromParts(authz.Authorize(t.Context(), tt.attrs))
						}

						if got := decision.String(); got != tc.wantAuthorizeStr[i] {
							t.Errorf("ConditionsAwareAuthorize() = %q, want %q", got, tc.wantAuthorizeStr[i])
						}

						data := authorizer.ConditionsData{
							AdmissionControl: admission.NewAttributesRecord(
								tc.object, tc.oldObject,
								schema.GroupVersionKind{}, "", "",
								schema.GroupVersionResource{}, "", "", nil, false, nil),
						}

						final := authorizer.ConditionsAwareDecisionFromParts(authz.EvaluateConditions(t.Context(), decision, data))
						if got := final.String(); got != tc.wantFinalStr[i] {
							t.Errorf("EvaluateConditions() = %q, want %q", got, tc.wantFinalStr[i])
						}
					})
				}
			}
		})
	}
}

func typedNilCondition() authorizer.Condition {
	var c *authorizer.GenericCondition
	return c
}

func makeConditionsMap(authorizerName string, deny, noOpinion, allow []authorizer.Condition) authorizer.ConditionsMap {
	d := authorizer.ConditionsAwareDecisionConditional(authorizerName, deny, noOpinion, allow)
	if !d.IsConditional() {
		panic(fmt.Sprintf("makeConditionsMap: constructor returned non-conditional %s", d))
	}
	return d.ConditionsMaps()[0]
}

func objWithLabels(lbls map[string]string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]any{}}
	if len(lbls) > 0 {
		obj.SetLabels(lbls)
	}
	return obj
}

// deepCopyTracker is a Condition whose DeepCopy copies its marker pointer.
type deepCopyTracker struct {
	id     string
	marker *string
}

func (c *deepCopyTracker) GetID() string          { return c.id }

func (c *deepCopyTracker) GetType() string        { return "" }

func (c *deepCopyTracker) GetCondition() string   { return "" }

func (c *deepCopyTracker) GetDescription() string { return "" }

func (c *deepCopyTracker) Evaluate(_ context.Context, _ authorizer.ConditionsData) authorizer.ConditionEvaluationResult {
	return authorizer.ConditionsEvaluationResultUnevaluatable()
}

func (c *deepCopyTracker) DeepCopy() authorizer.Condition {
	cp := *c
	if c.marker != nil {
		m := *c.marker
		cp.marker = &m
	}
	return &cp
}

// celEvaluateConditionsMap evaluates a ConditionsMap using CEL expressions.
func celEvaluateConditionsMap(ctx context.Context, cm authorizer.ConditionsMap, data authorizer.ConditionsData) (authorizer.Decision, string, error) {
	env, err := cel.NewEnv(
		cel.Variable("object", cel.DynType),
		cel.Variable("oldObject", cel.DynType),
	)
	if err != nil {
		return cm.FailClosedDecision(), "failed closed", fmt.Errorf("cel.NewEnv: %w", err)
	}

	if data.AdmissionControl == nil {
		return cm.FailClosedDecision(), "failed closed", errors.New("AdmissionControl is nil")
	}

	obj, err := runtimeObjectToMap(data.AdmissionControl.GetObject())
	if err != nil {
		return cm.FailClosedDecision(), "failed closed", err
	}
	oldObj, err := runtimeObjectToMap(data.AdmissionControl.GetOldObject())
	if err != nil {
		return cm.FailClosedDecision(), "failed closed", err
	}

	vars := map[string]any{"object": obj, "oldObject": oldObj}

	evalFn := func(_ context.Context, _ authorizer.ConditionsData, c authorizer.Condition) authorizer.ConditionEvaluationResult {
		return evalCELExpr(env, c.GetCondition(), vars)
	}

	result := cm.Evaluate(ctx, data, evalFn)
	if result.IsConditional() {
		// All conditions were unevaluatable; fail closed.
		return result.ConditionsMaps()[0].FailClosedDecision(), "failed closed: unevaluatable conditions remain", nil
	}
	return result.UnconditionalParts()
}

func evalCELExpr(env *cel.Env, expr string, vars map[string]any) authorizer.ConditionEvaluationResult {
	ast, issues := env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return authorizer.ConditionEvaluationResultError(fmt.Errorf("CEL compile %q: %w", expr, issues.Err()))
	}
	prg, err := env.Program(ast)
	if err != nil {
		return authorizer.ConditionEvaluationResultError(fmt.Errorf("CEL program %q: %w", expr, err))
	}
	out, _, err := prg.Eval(vars)
	if err != nil {
		return authorizer.ConditionEvaluationResultError(fmt.Errorf("CEL eval %q: %w", expr, err))
	}
	b, ok := out.Value().(bool)
	if !ok {
		return authorizer.ConditionEvaluationResultError(fmt.Errorf("CEL %q: expected bool, got %T", expr, out.Value()))
	}
	return authorizer.ConditionEvaluationResultBoolean(b)
}

func runtimeObjectToMap(r runtime.Object) (interface{}, error) {
	if r == nil || reflect.ValueOf(r).IsNil() {
		return nil, nil
	}
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(r)
	if err != nil {
		return nil, fmt.Errorf("ToUnstructured: %w", err)
	}
	return m, nil
}
