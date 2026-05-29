/*
Copyright 2014 The Kubernetes Authors.

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

package union

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	genericapirequest "k8s.io/apiserver/pkg/endpoints/request"
)

type mockAuthzHandler struct {
	decision authorizer.Decision
	reason   string
	err      error
}

func (mock *mockAuthzHandler) Authorize(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
	return mock.decision, mock.reason, mock.err
}

// ConditionsAwareAuthorize is not conditions-aware, converts the Authorize decision.
func (mock *mockAuthzHandler) ConditionsAwareAuthorize(ctx context.Context, a authorizer.Attributes) authorizer.ConditionsAwareDecision {
	return authorizer.ConditionsAwareDecisionFromParts(mock.Authorize(ctx, a))
}

// EvaluateConditions is not supported by this authorizer.
func (*mockAuthzHandler) EvaluateConditions(_ context.Context, _ authorizer.ConditionsAwareDecision, _ authorizer.ConditionsData) (authorizer.Decision, string, error) {
	return authorizer.DecisionDeny, "", authorizer.ErrorConditionEvaluationNotSupported
}

func TestAuthorizationSecondPasses(t *testing.T) {
	handler1 := &mockAuthzHandler{decision: authorizer.DecisionNoOpinion}
	handler2 := &mockAuthzHandler{decision: authorizer.DecisionAllow}
	authzHandler := New(handler1, handler2)

	authorized, _, _ := authzHandler.Authorize(context.Background(), nil)
	if authorized != authorizer.DecisionAllow {
		t.Errorf("Unexpected authorization failure")
	}
}

func TestAuthorizationFirstPasses(t *testing.T) {
	handler1 := &mockAuthzHandler{decision: authorizer.DecisionAllow}
	handler2 := &mockAuthzHandler{decision: authorizer.DecisionNoOpinion}
	authzHandler := New(handler1, handler2)

	authorized, _, _ := authzHandler.Authorize(context.Background(), nil)
	if authorized != authorizer.DecisionAllow {
		t.Errorf("Unexpected authorization failure")
	}
}

func TestAuthorizationNonePasses(t *testing.T) {
	handler1 := &mockAuthzHandler{decision: authorizer.DecisionNoOpinion}
	handler2 := &mockAuthzHandler{decision: authorizer.DecisionNoOpinion}
	authzHandler := New(handler1, handler2)

	authorized, _, _ := authzHandler.Authorize(context.Background(), nil)
	if authorized == authorizer.DecisionAllow {
		t.Errorf("Expected failed authorization")
	}
}

func TestAuthorizationError(t *testing.T) {
	handler1 := &mockAuthzHandler{err: fmt.Errorf("foo")}
	handler2 := &mockAuthzHandler{err: fmt.Errorf("foo")}
	authzHandler := New(handler1, handler2)

	_, _, err := authzHandler.Authorize(context.Background(), nil)
	if err == nil {
		t.Errorf("Expected error: %v", err)
	}
}

type mockAuthzRuleHandler struct {
	resourceRules    []authorizer.ResourceRuleInfo
	nonResourceRules []authorizer.NonResourceRuleInfo
	err              error
}

func (mock *mockAuthzRuleHandler) RulesFor(ctx context.Context, user user.Info, namespace string) ([]authorizer.ResourceRuleInfo, []authorizer.NonResourceRuleInfo, bool, error) {
	if mock.err != nil {
		return []authorizer.ResourceRuleInfo{}, []authorizer.NonResourceRuleInfo{}, false, mock.err
	}
	return mock.resourceRules, mock.nonResourceRules, false, nil
}

func TestAuthorizationResourceRules(t *testing.T) {
	handler1 := &mockAuthzRuleHandler{
		resourceRules: []authorizer.ResourceRuleInfo{
			&authorizer.DefaultResourceRuleInfo{
				Verbs:     []string{"*"},
				APIGroups: []string{"*"},
				Resources: []string{"bindings"},
			},
			&authorizer.DefaultResourceRuleInfo{
				Verbs:     []string{"get", "list", "watch"},
				APIGroups: []string{"*"},
				Resources: []string{"*"},
			},
		},
	}
	handler2 := &mockAuthzRuleHandler{
		resourceRules: []authorizer.ResourceRuleInfo{
			&authorizer.DefaultResourceRuleInfo{
				Verbs:     []string{"*"},
				APIGroups: []string{"*"},
				Resources: []string{"events"},
			},
			&authorizer.DefaultResourceRuleInfo{
				Verbs:         []string{"get"},
				APIGroups:     []string{"*"},
				Resources:     []string{"*"},
				ResourceNames: []string{"foo"},
			},
		},
	}

	expected := []authorizer.DefaultResourceRuleInfo{
		{
			Verbs:     []string{"*"},
			APIGroups: []string{"*"},
			Resources: []string{"bindings"},
		},
		{
			Verbs:     []string{"get", "list", "watch"},
			APIGroups: []string{"*"},
			Resources: []string{"*"},
		},
		{
			Verbs:     []string{"*"},
			APIGroups: []string{"*"},
			Resources: []string{"events"},
		},
		{
			Verbs:         []string{"get"},
			APIGroups:     []string{"*"},
			Resources:     []string{"*"},
			ResourceNames: []string{"foo"},
		},
	}

	authzRulesHandler := NewRuleResolvers(handler1, handler2)

	rules, _, _, _ := authzRulesHandler.RulesFor(genericapirequest.NewContext(), nil, "")
	actual := getResourceRules(rules)
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Expected: \n%#v\n but actual: \n%#v\n", expected, actual)
	}
}

func TestAuthorizationNonResourceRules(t *testing.T) {
	handler1 := &mockAuthzRuleHandler{
		nonResourceRules: []authorizer.NonResourceRuleInfo{
			&authorizer.DefaultNonResourceRuleInfo{
				Verbs:           []string{"get"},
				NonResourceURLs: []string{"/api"},
			},
		},
	}

	handler2 := &mockAuthzRuleHandler{
		nonResourceRules: []authorizer.NonResourceRuleInfo{
			&authorizer.DefaultNonResourceRuleInfo{
				Verbs:           []string{"get"},
				NonResourceURLs: []string{"/api/*"},
			},
		},
	}

	expected := []authorizer.DefaultNonResourceRuleInfo{
		{
			Verbs:           []string{"get"},
			NonResourceURLs: []string{"/api"},
		},
		{
			Verbs:           []string{"get"},
			NonResourceURLs: []string{"/api/*"},
		},
	}

	authzRulesHandler := NewRuleResolvers(handler1, handler2)

	_, rules, _, _ := authzRulesHandler.RulesFor(genericapirequest.NewContext(), nil, "")
	actual := getNonResourceRules(rules)
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Expected: \n%#v\n but actual: \n%#v\n", expected, actual)
	}
}

func getResourceRules(infos []authorizer.ResourceRuleInfo) []authorizer.DefaultResourceRuleInfo {
	rules := make([]authorizer.DefaultResourceRuleInfo, len(infos))
	for i, info := range infos {
		rules[i] = authorizer.DefaultResourceRuleInfo{
			Verbs:         info.GetVerbs(),
			APIGroups:     info.GetAPIGroups(),
			Resources:     info.GetResources(),
			ResourceNames: info.GetResourceNames(),
		}
	}
	return rules
}

func getNonResourceRules(infos []authorizer.NonResourceRuleInfo) []authorizer.DefaultNonResourceRuleInfo {
	rules := make([]authorizer.DefaultNonResourceRuleInfo, len(infos))
	for i, info := range infos {
		rules[i] = authorizer.DefaultNonResourceRuleInfo{
			Verbs:           info.GetVerbs(),
			NonResourceURLs: info.GetNonResourceURLs(),
		}
	}
	return rules
}
// evalTestEffect drives what kind of conditional decision evalTestAuthz returns.
type evalTestEffect string

const (
	effectNone      evalTestEffect = ""          // return unconditional decision
	effectAllow     evalTestEffect = "Allow"     // return conditional with allow condition
	effectDeny      evalTestEffect = "Deny"      // return conditional with deny condition
	effectNoOpinion evalTestEffect = "NoOpinion" // return conditional with noOpinion condition (short-circuits to NoOpinion at construction)
)

// evalTestAuthz is a Named conditions-aware authorizer whose behavior is fully controlled
// by struct fields, making it easy to construct table-driven union tests.
type evalTestAuthz struct {
	name            string         // AuthorizerName; must be unique in the chain
	conditionEffect evalTestEffect // if non-empty, ConditionsAwareAuthorize returns a conditional decision
	decision        authorizer.Decision
	authorizeErr    error

	evalDecision authorizer.Decision
	evalReason   string
	evalErr      error
}

func (a *evalTestAuthz) AuthorizerName() string { return a.name }

func (a *evalTestAuthz) Authorize(ctx context.Context, attrs authorizer.Attributes) (authorizer.Decision, string, error) {
	d, r, err := a.ConditionsAwareAuthorize(ctx, attrs).UnconditionalParts()
	return d, r, err
}

func (a *evalTestAuthz) ConditionsAwareAuthorize(_ context.Context, _ authorizer.Attributes) authorizer.ConditionsAwareDecision {
	if a.conditionEffect == effectNone {
		return authorizer.ConditionsAwareDecisionFromParts(a.decision, "", a.authorizeErr)
	}
	cond := []authorizer.Condition{authorizer.GenericCondition{ID: "test-cond", Condition: "test"}}
	var deny, noOpinion, allow []authorizer.Condition
	switch a.conditionEffect {
	case effectAllow:
		allow = cond
	case effectDeny:
		deny = cond
	case effectNoOpinion:
		// noOpinion-only short-circuits to NoOpinion at construction time, so we add a
		// filler deny=false condition to force a real ConditionsMap to be returned.
		deny = []authorizer.Condition{authorizer.GenericCondition{
			ID: "filler-deny-false",
			EvaluateFunc: func(context.Context, authorizer.ConditionsData) authorizer.ConditionEvaluationResult {
				return authorizer.ConditionEvaluationResultBoolean(false)
			},
		}}
		noOpinion = cond
	}
	return authorizer.ConditionsAwareDecisionConditional(a.name, deny, noOpinion, allow)
}

func (a *evalTestAuthz) EvaluateConditions(_ context.Context, decision authorizer.ConditionsAwareDecision, _ authorizer.ConditionsData) (authorizer.Decision, string, error) {
	if decision.IsUnconditional() {
		return decision.UnconditionalParts()
	}
	return a.evalDecision, a.evalReason, a.evalErr
}

func noOpinionAuthz(name string) *evalTestAuthz {
	return &evalTestAuthz{name: name, decision: authorizer.DecisionNoOpinion}
}

func TestUnionConditionsAwareAuthorize(t *testing.T) {
	attrs := authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "test"}, Verb: "get"}

	tests := []struct {
		name       string
		buildUnion func() authorizer.Authorizer
		wantString string
	}{
		{
			name:       "all NoOpinion",
			buildUnion: func() authorizer.Authorizer { return New(noOpinionAuthz("a"), noOpinionAuthz("b")) },
			wantString: `NoOpinion`,
		},
		{
			name: "first Allow short-circuits",
			buildUnion: func() authorizer.Authorizer {
				return New(&evalTestAuthz{name: "a", decision: authorizer.DecisionAllow}, noOpinionAuthz("b"))
			},
			wantString: `Allow`,
		},
		{
			name: "first Deny short-circuits",
			buildUnion: func() authorizer.Authorizer {
				return New(&evalTestAuthz{name: "a", decision: authorizer.DecisionDeny}, noOpinionAuthz("b"))
			},
			wantString: `Deny`,
		},
		{
			name: "conditional then NoOpinion",
			buildUnion: func() authorizer.Authorizer {
				return New(&evalTestAuthz{name: "a", conditionEffect: effectAllow}, noOpinionAuthz("b"))
			},
			wantString: `Conditional(maps=1, fallback=NoOpinion)`,
		},
		{
			name: "conditional then Allow (Allow becomes fallback)",
			buildUnion: func() authorizer.Authorizer {
				return New(
					&evalTestAuthz{name: "a", conditionEffect: effectAllow},
					&evalTestAuthz{name: "b", decision: authorizer.DecisionAllow},
				)
			},
			wantString: `Conditional(maps=1, fallback=Allow)`,
		},
		{
			name: "two conditionals then Deny (Deny becomes fallback)",
			buildUnion: func() authorizer.Authorizer {
				return New(
					&evalTestAuthz{name: "a", conditionEffect: effectAllow},
					&evalTestAuthz{name: "b", conditionEffect: effectDeny},
					&evalTestAuthz{name: "c", decision: authorizer.DecisionDeny},
				)
			},
			wantString: `Conditional(maps=2, fallback=Deny)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := tt.buildUnion().ConditionsAwareAuthorize(context.Background(), attrs)
			if got := d.String(); got != tt.wantString {
				t.Errorf("ConditionsAwareAuthorize() = %q, want %q", got, tt.wantString)
			}
		})
	}
}
// The nested topology used for nesting tests:
//
//	union0 = New(union1, union3, authz5)
//	union1 = New(union2, authz3)
//	union2 = New(authz1, authz2)
//	union3 = New(authz4)

func TestUnionEvaluateConditions(t *testing.T) {
	attrs := authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "test"}, Verb: "get"}
	ctx := context.Background()

	type testCase struct {
		name                                   string
		authz1, authz2, authz3, authz4, authz5 authorizer.Authorizer
		wantAuthorizeString                    string
		wantFinalString                        string
		wantAuthorizeErr                       bool
		wantFinalErr                           bool
	}

	tests := []testCase{
		{
			name:                "all noopinion",
			authz1:              noOpinionAuthz("authz1"),
			authz2:              noOpinionAuthz("authz2"),
			authz3:              noOpinionAuthz("authz3"),
			authz4:              noOpinionAuthz("authz4"),
			authz5:              noOpinionAuthz("authz5"),
			wantAuthorizeString: `NoOpinion`,
			wantFinalString:     `NoOpinion`,
		},
		{
			name:                "authz1 Allow short-circuits everything",
			authz1:              &evalTestAuthz{name: "authz1", decision: authorizer.DecisionAllow},
			authz2:              noOpinionAuthz("authz2"),
			authz3:              noOpinionAuthz("authz3"),
			authz4:              noOpinionAuthz("authz4"),
			authz5:              noOpinionAuthz("authz5"),
			wantAuthorizeString: `Allow`,
			wantFinalString:     `Allow`,
		},
		{
			name:                "authz1 Deny short-circuits everything",
			authz1:              &evalTestAuthz{name: "authz1", decision: authorizer.DecisionDeny},
			authz2:              noOpinionAuthz("authz2"),
			authz3:              noOpinionAuthz("authz3"),
			authz4:              noOpinionAuthz("authz4"),
			authz5:              noOpinionAuthz("authz5"),
			wantAuthorizeString: `Deny`,
			wantFinalString:     `Deny`,
		},
		{
			name:                "authz3 Allow (inside union1)",
			authz1:              noOpinionAuthz("authz1"),
			authz2:              noOpinionAuthz("authz2"),
			authz3:              &evalTestAuthz{name: "authz3", decision: authorizer.DecisionAllow},
			authz4:              noOpinionAuthz("authz4"),
			authz5:              noOpinionAuthz("authz5"),
			wantAuthorizeString: `Allow`,
			wantFinalString:     `Allow`,
		},
		{
			name:                "authz5 Allow (top-level)",
			authz1:              noOpinionAuthz("authz1"),
			authz2:              noOpinionAuthz("authz2"),
			authz3:              noOpinionAuthz("authz3"),
			authz4:              noOpinionAuthz("authz4"),
			authz5:              &evalTestAuthz{name: "authz5", decision: authorizer.DecisionAllow},
			wantAuthorizeString: `Allow`,
			wantFinalString:     `Allow`,
		},
		{
			name: "authz1 conditional → Allow",
			authz1: &evalTestAuthz{name: "authz1", conditionEffect: effectAllow,
				evalDecision: authorizer.DecisionAllow},
			authz2:              noOpinionAuthz("authz2"),
			authz3:              noOpinionAuthz("authz3"),
			authz4:              noOpinionAuthz("authz4"),
			authz5:              noOpinionAuthz("authz5"),
			wantAuthorizeString: `Conditional(maps=1, fallback=NoOpinion)`,
			wantFinalString:     `Allow`,
		},
		{
			name: "authz1 conditional → NoOpinion",
			authz1: &evalTestAuthz{name: "authz1", conditionEffect: effectAllow,
				evalDecision: authorizer.DecisionNoOpinion},
			authz2:              noOpinionAuthz("authz2"),
			authz3:              noOpinionAuthz("authz3"),
			authz4:              noOpinionAuthz("authz4"),
			authz5:              noOpinionAuthz("authz5"),
			wantAuthorizeString: `Conditional(maps=1, fallback=NoOpinion)`,
			wantFinalString:     `NoOpinion`,
		},
		{
			name:   "authz3 conditional → Deny (inside union1)",
			authz1: noOpinionAuthz("authz1"),
			authz2: noOpinionAuthz("authz2"),
			authz3: &evalTestAuthz{name: "authz3", conditionEffect: effectDeny,
				evalDecision: authorizer.DecisionDeny},
			authz4:              noOpinionAuthz("authz4"),
			authz5:              noOpinionAuthz("authz5"),
			wantAuthorizeString: `Conditional(maps=1, fallback=NoOpinion)`,
			wantFinalString:     `Deny`,
		},
		{
			name:   "authz5 conditional → Allow (top-level)",
			authz1: noOpinionAuthz("authz1"),
			authz2: noOpinionAuthz("authz2"),
			authz3: noOpinionAuthz("authz3"),
			authz4: noOpinionAuthz("authz4"),
			authz5: &evalTestAuthz{name: "authz5", conditionEffect: effectAllow,
				evalDecision: authorizer.DecisionAllow},
			wantAuthorizeString: `Conditional(maps=1, fallback=NoOpinion)`,
			wantFinalString:     `Allow`,
		},
		{
			name: "authz1 conditional → NoOpinion, authz2 Allow (Allow is fallback)",
			authz1: &evalTestAuthz{name: "authz1", conditionEffect: effectAllow,
				evalDecision: authorizer.DecisionNoOpinion},
			authz2:              &evalTestAuthz{name: "authz2", decision: authorizer.DecisionAllow},
			authz3:              noOpinionAuthz("authz3"),
			authz4:              noOpinionAuthz("authz4"),
			authz5:              noOpinionAuthz("authz5"),
			wantAuthorizeString: `Conditional(maps=1, fallback=Allow)`,
			wantFinalString:     `Allow`,
		},
		{
			name:   "authz3 conditional → NoOpinion, authz5 Deny (Deny is fallback)",
			authz1: noOpinionAuthz("authz1"),
			authz2: noOpinionAuthz("authz2"),
			authz3: &evalTestAuthz{name: "authz3", conditionEffect: effectAllow,
				evalDecision: authorizer.DecisionNoOpinion},
			authz4:              noOpinionAuthz("authz4"),
			authz5:              &evalTestAuthz{name: "authz5", decision: authorizer.DecisionDeny},
			wantAuthorizeString: `Conditional(maps=1, fallback=Deny)`,
			wantFinalString:     `Deny`,
		},
		{
			name: "authz1 conditional → Allow, authz5 Deny (conditional wins over fallback)",
			authz1: &evalTestAuthz{name: "authz1", conditionEffect: effectAllow,
				evalDecision: authorizer.DecisionAllow},
			authz2:              noOpinionAuthz("authz2"),
			authz3:              noOpinionAuthz("authz3"),
			authz4:              noOpinionAuthz("authz4"),
			authz5:              &evalTestAuthz{name: "authz5", decision: authorizer.DecisionDeny},
			wantAuthorizeString: `Conditional(maps=1, fallback=Deny)`,
			wantFinalString:     `Allow`,
		},
		{
			name: "authz1 conditional → Allow, authz3 conditional → NoOpinion; first wins",
			authz1: &evalTestAuthz{name: "authz1", conditionEffect: effectAllow,
				evalDecision: authorizer.DecisionAllow},
			authz2: noOpinionAuthz("authz2"),
			authz3: &evalTestAuthz{name: "authz3", conditionEffect: effectDeny,
				evalDecision: authorizer.DecisionDeny},
			authz4:              noOpinionAuthz("authz4"),
			authz5:              noOpinionAuthz("authz5"),
			wantAuthorizeString: `Conditional(maps=2, fallback=NoOpinion)`,
			wantFinalString:     `Allow`,
		},
		{
			name: "authz1 conditional → NoOpinion, authz3 conditional → Deny",
			authz1: &evalTestAuthz{name: "authz1", conditionEffect: effectAllow,
				evalDecision: authorizer.DecisionNoOpinion},
			authz2: noOpinionAuthz("authz2"),
			authz3: &evalTestAuthz{name: "authz3", conditionEffect: effectDeny,
				evalDecision: authorizer.DecisionDeny},
			authz4:              noOpinionAuthz("authz4"),
			authz5:              noOpinionAuthz("authz5"),
			wantAuthorizeString: `Conditional(maps=2, fallback=NoOpinion)`,
			wantFinalString:     `Deny`,
		},
		{
			name: "all conditionals → NoOpinion",
			authz1: &evalTestAuthz{name: "authz1", conditionEffect: effectAllow,
				evalDecision: authorizer.DecisionNoOpinion},
			authz2: &evalTestAuthz{name: "authz2", conditionEffect: effectDeny,
				evalDecision: authorizer.DecisionNoOpinion},
			authz3: &evalTestAuthz{name: "authz3", conditionEffect: effectAllow,
				evalDecision: authorizer.DecisionNoOpinion},
			authz4: noOpinionAuthz("authz4"),
			authz5: &evalTestAuthz{name: "authz5", conditionEffect: effectDeny,
				evalDecision: authorizer.DecisionNoOpinion},
			wantAuthorizeString: `Conditional(maps=4, fallback=NoOpinion)`,
			wantFinalString:     `NoOpinion`,
		},
		{
			name: "authz1 conditional → Deny, authz5 conditional → Allow; first Deny wins",
			authz1: &evalTestAuthz{name: "authz1", conditionEffect: effectDeny,
				evalDecision: authorizer.DecisionDeny},
			authz2: noOpinionAuthz("authz2"),
			authz3: &evalTestAuthz{name: "authz3", conditionEffect: effectAllow,
				evalDecision: authorizer.DecisionNoOpinion},
			authz4: noOpinionAuthz("authz4"),
			authz5: &evalTestAuthz{name: "authz5", conditionEffect: effectAllow,
				evalDecision: authorizer.DecisionAllow},
			wantAuthorizeString: `Conditional(maps=3, fallback=NoOpinion)`,
			wantFinalString:     `Deny`,
		},
		{
			name: "authorize error propagated",
			authz1: &evalTestAuthz{name: "authz1", decision: authorizer.DecisionAllow,
				authorizeErr: errors.New("authz error")},
			authz2:              noOpinionAuthz("authz2"),
			authz3:              noOpinionAuthz("authz3"),
			authz4:              noOpinionAuthz("authz4"),
			authz5:              noOpinionAuthz("authz5"),
			wantAuthorizeString: `Allow(err="authz error")`,
			wantAuthorizeErr:    true,
			wantFinalString:     `Allow(err="authz error")`,
			wantFinalErr:        true,
		},
		{
			name: "evaluate error propagated",
			authz1: &evalTestAuthz{name: "authz1", conditionEffect: effectAllow,
				evalDecision: authorizer.DecisionAllow,
				evalErr:      errors.New("eval error")},
			authz2:              noOpinionAuthz("authz2"),
			authz3:              noOpinionAuthz("authz3"),
			authz4:              noOpinionAuthz("authz4"),
			authz5:              noOpinionAuthz("authz5"),
			wantAuthorizeString: `Conditional(maps=1, fallback=NoOpinion)`,
			wantFinalString:     `Allow(err="eval error")`,
			wantFinalErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			union3 := New(tt.authz4)
			union2 := New(tt.authz1, tt.authz2)
			union1 := New(union2, tt.authz3)
			union0 := New(union1, union3, tt.authz5)

			authzDecision := union0.ConditionsAwareAuthorize(ctx, attrs)

			if gotErr := authzDecision.Error(); (gotErr != nil) != tt.wantAuthorizeErr {
				t.Fatalf("ConditionsAwareAuthorize() error = %v, wantErr %v", gotErr, tt.wantAuthorizeErr)
			}
			if got := authzDecision.String(); got != tt.wantAuthorizeString {
				t.Errorf("ConditionsAwareAuthorize() = %q, want %q", got, tt.wantAuthorizeString)
			}

			finalDecision := authorizer.ConditionsAwareDecisionFromParts(union0.EvaluateConditions(ctx, authzDecision, authorizer.ConditionsData{}))
			if gotErr := finalDecision.Error(); (gotErr != nil) != tt.wantFinalErr {
				t.Fatalf("EvaluateConditions() error = %v, wantErr %v", gotErr, tt.wantFinalErr)
			}
			if got := finalDecision.String(); got != tt.wantFinalString {
				t.Errorf("EvaluateConditions() = %q, want %q", got, tt.wantFinalString)
			}
		})
	}
}

// TestUnionConditionsAwareAuthorizeNoOpinionErrorAccumulation verifies that errors
// and reasons from intermediate NoOpinion decisions are surfaced in the final fallback,
// matching Authorize()'s error-aggregation behaviour and preserving the 500 vs 403
// distinction for callers.
func TestUnionConditionsAwareAuthorizeNoOpinionErrorAccumulation(t *testing.T) {
	ctx := context.Background()
	attrs := authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "test"}, Verb: "get"}
	timeoutErr := errors.New("webhook timeout")

	tests := []struct {
		name           string
		authorizers    []authorizer.Authorizer
		wantDecision   authorizer.Decision
		wantReason     string
		wantErrContain error
	}{
		{
			name: "noOpinion error surfaces in fallback when all conditional",
			authorizers: []authorizer.Authorizer{
				&evalTestAuthz{name: "a1", conditionEffect: effectAllow, evalDecision: authorizer.DecisionNoOpinion},
				&mockAuthzHandler{decision: authorizer.DecisionNoOpinion, err: timeoutErr},
			},
			wantDecision:   authorizer.DecisionNoOpinion,
			wantErrContain: timeoutErr,
		},
		{
			name: "noOpinion reason surfaces in fallback",
			authorizers: []authorizer.Authorizer{
				&mockAuthzHandler{decision: authorizer.DecisionNoOpinion},
				&mockAuthzHandler{decision: authorizer.DecisionNoOpinion, reason: "authz skipped"},
				&evalTestAuthz{name: "a1", conditionEffect: effectAllow, evalDecision: authorizer.DecisionNoOpinion},
			},
			wantDecision: authorizer.DecisionNoOpinion,
			wantReason:   "authz skipped",
		},
		{
			name: "noOpinion errors dropped when decisive Allow found",
			authorizers: []authorizer.Authorizer{
				&mockAuthzHandler{decision: authorizer.DecisionNoOpinion, err: timeoutErr},
				&evalTestAuthz{name: "a1", conditionEffect: effectAllow, evalDecision: authorizer.DecisionNoOpinion},
				&mockAuthzHandler{decision: authorizer.DecisionAllow},
			},
			wantDecision:   authorizer.DecisionNoOpinion,
			wantErrContain: nil,
		},
		{
			name: "noOpinion errors dropped when decisive Deny found",
			authorizers: []authorizer.Authorizer{
				&mockAuthzHandler{decision: authorizer.DecisionNoOpinion, err: timeoutErr},
				&evalTestAuthz{name: "a1", conditionEffect: effectAllow, evalDecision: authorizer.DecisionNoOpinion},
				&mockAuthzHandler{decision: authorizer.DecisionDeny},
			},
			wantDecision:   authorizer.DecisionNoOpinion,
			wantErrContain: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := New(tt.authorizers...)
			authzDecision := u.ConditionsAwareAuthorize(ctx, attrs)
			fallback := authzDecision.Fallback()

			if fallback.IsUnconditional() && !fallback.IsNoOpinion() {
				// decisive fallback — errors are intentionally dropped, skip err check
				return
			}

			if tt.wantErrContain != nil {
				if !errors.Is(fallback.Error(), tt.wantErrContain) {
					t.Errorf("fallback error = %v, want to contain %v", fallback.Error(), tt.wantErrContain)
				}
			} else {
				if fallback.Error() != nil {
					t.Errorf("fallback error = %v, want nil", fallback.Error())
				}
			}

			if tt.wantReason != "" && fallback.Reason() != tt.wantReason {
				t.Errorf("fallback reason = %q, want %q", fallback.Reason(), tt.wantReason)
			}

			finalDecision, _, _ := u.EvaluateConditions(ctx, authzDecision, authorizer.ConditionsData{})
			if finalDecision != tt.wantDecision {
				t.Errorf("EvaluateConditions decision = %v, want %v", finalDecision, tt.wantDecision)
			}
		})
	}
}

func TestUnionEvaluateConditionsFallbackInheritsEvalErrorAndReason(t *testing.T) {
	ctx := context.Background()
	attrs := authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "test"}, Verb: "get"}
	evalErr := errors.New("eval error from cond")

	// authz1 returns a conditional that evaluates to NoOpinion with an error and reason.
	// All other authorizers return plain NoOpinion.
	// The fallback is NoOpinion (no reason, no error), so the accumulated values should
	// propagate into the final result.
	authz1 := &evalTestAuthz{
		name:            "authz1",
		conditionEffect: effectAllow,
		evalDecision:    authorizer.DecisionNoOpinion,
		evalReason:      "condition did not match",
		evalErr:         evalErr,
	}
	union := New(authz1, noOpinionAuthz("authz2"))

	authzDecision := union.ConditionsAwareAuthorize(ctx, attrs)
	finalDecision, finalReason, finalErr := union.EvaluateConditions(ctx, authzDecision, authorizer.ConditionsData{})

	if finalDecision != authorizer.DecisionNoOpinion {
		t.Errorf("decision = %v, want NoOpinion", finalDecision)
	}
	if finalReason != "condition did not match" {
		t.Errorf("reason = %q, want %q", finalReason, "condition did not match")
	}
	if !errors.Is(finalErr, evalErr) {
		t.Errorf("err = %v, want to contain %v", finalErr, evalErr)
	}
}

func TestUnionEvaluateConditionsMissingAuthorizer(t *testing.T) {
	ctx := context.Background()
	attrs := authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "test"}, Verb: "get"}

	// authz1 returns conditions but is NOT in the union.
	ghostAuthz := &evalTestAuthz{name: "ghost", conditionEffect: effectDeny, evalDecision: authorizer.DecisionDeny}
	union := New(noOpinionAuthz("a"), noOpinionAuthz("b"))

	// Build a conditional decision that references "ghost" directly.
	fakeDecision := authorizer.ConditionsAwareDecisionConditionalMaps(
		[]authorizer.ConditionsMap{ghostAuthz.ConditionsAwareAuthorize(ctx, attrs).ConditionsMaps()[0]},
		authorizer.ConditionsAwareDecisionNoOpinion("", nil),
	)

	decision, reason, err := union.EvaluateConditions(ctx, fakeDecision, authorizer.ConditionsData{})
	if err == nil {
		t.Fatalf("expected error for missing authorizer, got nil")
	}
	if reason != "failed closed" {
		t.Errorf("reason = %q, want \"failed closed\"", reason)
	}
	// Should fail closed to Deny because the missing ConditionsMap has deny conditions.
	if decision != authorizer.DecisionDeny {
		t.Errorf("decision = %v, want Deny", decision)
	}
}

func TestUnionEvaluateConditionsPanicOnMissingName(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for empty AuthorizerName, got none")
		}
	}()

	ctx := context.Background()
	attrs := authorizer.AttributesRecord{User: &user.DefaultInfo{Name: "test"}, Verb: "get"}

	// mockBadAuthz returns a conditional decision but doesn't set AuthorizerName
	// (bypasses ConditionsAwareDecisionConditional's panic by using ConditionalMaps directly).
	badAuthz := &mockBadAuthz{}
	union := New(badAuthz)
	union.ConditionsAwareAuthorize(ctx, attrs)
}

// mockBadAuthz returns a conditional decision with an empty AuthorizerName.
type mockBadAuthz struct{}

func (m *mockBadAuthz) Authorize(ctx context.Context, a authorizer.Attributes) (authorizer.Decision, string, error) {
	return authorizer.DecisionNoOpinion, "", nil
}

func (m *mockBadAuthz) ConditionsAwareAuthorize(_ context.Context, _ authorizer.Attributes) authorizer.ConditionsAwareDecision {
	// Inject a ConditionsMap with an empty AuthorizerName to trigger the union's panic.
	return authorizer.ConditionsAwareDecisionConditionalMaps(
		[]authorizer.ConditionsMap{{}},
		authorizer.ConditionsAwareDecisionNoOpinion("", nil),
	)
}

func (m *mockBadAuthz) EvaluateConditions(_ context.Context, _ authorizer.ConditionsAwareDecision, _ authorizer.ConditionsData) (authorizer.Decision, string, error) {
	return authorizer.DecisionDeny, "", authorizer.ErrorConditionEvaluationNotSupported
}

func TestAuthorizationUnequivocalDeny(t *testing.T) {
	cs := []struct {
		authorizers []authorizer.Authorizer
		decision    authorizer.Decision
	}{
		{
			authorizers: []authorizer.Authorizer{},
			decision:    authorizer.DecisionNoOpinion,
		},
		{
			authorizers: []authorizer.Authorizer{
				&mockAuthzHandler{decision: authorizer.DecisionNoOpinion},
				&mockAuthzHandler{decision: authorizer.DecisionAllow},
				&mockAuthzHandler{decision: authorizer.DecisionDeny},
			},
			decision: authorizer.DecisionAllow,
		},
		{
			authorizers: []authorizer.Authorizer{
				&mockAuthzHandler{decision: authorizer.DecisionNoOpinion},
				&mockAuthzHandler{decision: authorizer.DecisionDeny},
				&mockAuthzHandler{decision: authorizer.DecisionAllow},
			},
			decision: authorizer.DecisionDeny,
		},
		{
			authorizers: []authorizer.Authorizer{
				&mockAuthzHandler{decision: authorizer.DecisionNoOpinion},
				&mockAuthzHandler{decision: authorizer.DecisionDeny, err: errors.New("webhook failed closed")},
				&mockAuthzHandler{decision: authorizer.DecisionAllow},
			},
			decision: authorizer.DecisionDeny,
		},
	}
	for i, c := range cs {
		t.Run(fmt.Sprintf("case %v", i), func(t *testing.T) {
			authzHandler := New(c.authorizers...)

			decision, _, _ := authzHandler.Authorize(context.Background(), nil)
			if decision != c.decision {
				t.Errorf("Unexpected authorization failure: %v, expected: %v", decision, c.decision)
			}
		})
	}
}
