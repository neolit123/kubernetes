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

package authorizer

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"reflect"
	"strings"

	"k8s.io/apimachinery/pkg/api/validate/content"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/authentication/user"
)

// ErrorConditionEvaluationNotSupported is returned by authorizer implementations
// that do not support condition evaluation.
var ErrorConditionEvaluationNotSupported = errors.New("condition evaluation not supported")

// Named is implemented by authorizers that return conditional decisions.
// The name must be unique within the authorizer chain. The union authorizer
// uses this name to route EvaluateConditions calls to the correct authorizer.
// Panics at evaluation time if an authorizer returns a conditional decision but
// does not implement Named.
type Named interface {
	AuthorizerName() string
}

// conditionsAwareDecisionType is a small enum for the decision variant.
// These values must not be exposed outside this package.
type conditionsAwareDecisionType int

const (
	// conditionsAwareDecisionTypeDeny is zero so that ConditionsAwareDecision{} == Deny.
	conditionsAwareDecisionTypeDeny      conditionsAwareDecisionType = 0
	conditionsAwareDecisionTypeAllow     conditionsAwareDecisionType = 11
	conditionsAwareDecisionTypeNoOpinion conditionsAwareDecisionType = 12
)

// ConditionsAwareDecision is an authorization decision that may carry conditions.
// It has three unconditional variants (Allow, Deny, NoOpinion) and a conditional
// variant represented by a non-empty conditionsMaps slice.
//
// The zero value is equivalent to ConditionsAwareDecisionDeny().
// A ConditionsAwareDecision is passed by value.
type ConditionsAwareDecision struct {
	decisionType conditionsAwareDecisionType

	// conditionsMaps is non-empty iff IsConditional() is true.
	// Each entry was produced by a distinct Named authorizer.
	conditionsMaps []ConditionsMap

	// fallback is set by the union authorizer to the first unconditional Allow or
	// Deny encountered after the conditional entries. It is nil for decisions
	// returned directly by leaf authorizers.
	fallback *ConditionsAwareDecision

	reason string
	err    error
}

// ConditionsAwareDecisionDeny constructs a Deny decision.
func ConditionsAwareDecisionDeny(reason string, err error) ConditionsAwareDecision {
	return ConditionsAwareDecision{
		// conditionsAwareDecisionTypeDeny == 0 == zero value
		decisionType: conditionsAwareDecisionTypeDeny,
		reason:       reason,
		err:          err,
	}
}

// ConditionsAwareDecisionAllow constructs an Allow decision.
func ConditionsAwareDecisionAllow(reason string, err error) ConditionsAwareDecision {
	return ConditionsAwareDecision{
		decisionType: conditionsAwareDecisionTypeAllow,
		reason:       reason,
		err:          err,
	}
}

// ConditionsAwareDecisionNoOpinion constructs a NoOpinion decision.
func ConditionsAwareDecisionNoOpinion(reason string, err error) ConditionsAwareDecision {
	return ConditionsAwareDecision{
		decisionType: conditionsAwareDecisionTypeNoOpinion,
		reason:       reason,
		err:          err,
	}
}

// ConditionsAwareDecisionFromParts converts a classic (Decision, string, error) triple.
// Intended for conditions-unaware authorizers implementing ConditionsAwareAuthorize as
// "return ConditionsAwareDecisionFromParts(self.Authorize(ctx, a))".
func ConditionsAwareDecisionFromParts(unconditional Decision, reason string, err error) ConditionsAwareDecision {
	switch unconditional {
	case DecisionAllow:
		return ConditionsAwareDecisionAllow(reason, err)
	case DecisionNoOpinion:
		return ConditionsAwareDecisionNoOpinion(reason, err)
	case DecisionDeny:
		return ConditionsAwareDecisionDeny(reason, err)
	default:
		return ConditionsAwareDecisionDeny(reason, utilerrors.NewAggregate(
			[]error{err, fmt.Errorf("unknown unconditional decision type: %d", unconditional)},
		))
	}
}

// ConditionsAwareDecisionConditional is used by individual leaf authorizers to return
// a conditional decision. authorizerName must be non-empty and must equal the value
// returned by the authorizer's Named.AuthorizerName() method.
//
// If all condition slices are empty, the call is a programming error and returns
// NoOpinion with an error.
//
// If only noOpinion conditions are provided (no deny or allow), the result collapses
// to NoOpinion immediately because evaluation can never yield Deny or Allow regardless
// of the data.
//
// Validation fails-closed: nil conditions or duplicate/invalid IDs produce a
// Deny (if any deny conditions were present) or NoOpinion result with an error.
func ConditionsAwareDecisionConditional(authorizerName string, deny, noOpinion, allow []Condition) ConditionsAwareDecision {
	if authorizerName == "" {
		panic("ConditionsAwareDecisionConditional: authorizerName must not be empty; implement Named on your authorizer")
	}

	total := len(deny) + len(noOpinion) + len(allow)
	if total == 0 {
		return ConditionsAwareDecisionNoOpinion("no conditions", fmt.Errorf(
			"at least one condition must be provided to ConditionsAwareDecisionConditional, got none"))
	}
	if total > MaxConditionsPerMap {
		hasDeny := len(deny) > 0
		err := fmt.Errorf("too many conditions: %d exceeds maximum of %d", total, MaxConditionsPerMap)
		if hasDeny {
			return ConditionsAwareDecisionDeny("failed closed", err)
		}
		return ConditionsAwareDecisionNoOpinion("failed closed", err)
	}

	// Short-circuit: noOpinion-only conditions always evaluate to NoOpinion.
	if len(deny) == 0 && len(allow) == 0 {
		// Validate the noOpinion conditions before collapsing, to surface errors early.
		seenIDs := sets.New[string]()
		if err := validateConditions(seenIDs, noOpinion); err != nil {
			return ConditionsAwareDecisionNoOpinion("failed closed", err)
		}
		return ConditionsAwareDecisionNoOpinion("", nil)
	}

	hasDeny := len(deny) > 0
	makeFailClosedError := func(err error) ConditionsAwareDecision {
		if hasDeny {
			return ConditionsAwareDecisionDeny("failed closed", err)
		}
		return ConditionsAwareDecisionNoOpinion("failed closed", err)
	}

	seenIDs := sets.New[string]()
	if err := validateConditions(seenIDs, deny); err != nil {
		return makeFailClosedError(err)
	}
	if err := validateConditions(seenIDs, noOpinion); err != nil {
		return makeFailClosedError(err)
	}
	if err := validateConditions(seenIDs, allow); err != nil {
		return makeFailClosedError(err)
	}

	return ConditionsAwareDecision{
		decisionType: conditionsAwareDecisionTypeNoOpinion,
		conditionsMaps: []ConditionsMap{
			{
				authorizerName:      authorizerName,
				denyConditions:      deny,
				noOpinionConditions: noOpinion,
				allowConditions:     allow,
			},
		},
	}
}

// ConditionsAwareDecisionConditionalMaps is used by the union authorizer to assemble a
// conditional decision from previously-collected ConditionsMaps and a fallback decision.
// If conditionsMaps is empty, the fallback is returned directly.
func ConditionsAwareDecisionConditionalMaps(conditionsMaps []ConditionsMap, fallback ConditionsAwareDecision) ConditionsAwareDecision {
	if len(conditionsMaps) == 0 {
		return fallback
	}
	fallbackCopy := fallback
	return ConditionsAwareDecision{
		decisionType:   conditionsAwareDecisionTypeNoOpinion,
		conditionsMaps: conditionsMaps,
		fallback:       &fallbackCopy,
	}
}

// IsAllow returns true if the decision is an unconditional Allow.
func (d ConditionsAwareDecision) IsAllow() bool {
	return !d.IsConditional() && d.decisionType == conditionsAwareDecisionTypeAllow
}

// IsDeny returns true if the decision is an unconditional Deny.
func (d ConditionsAwareDecision) IsDeny() bool {
	return !d.IsConditional() && d.decisionType == conditionsAwareDecisionTypeDeny
}

// IsNoOpinion returns true if the decision is an unconditional NoOpinion.
func (d ConditionsAwareDecision) IsNoOpinion() bool {
	return !d.IsConditional() && d.decisionType == conditionsAwareDecisionTypeNoOpinion
}

// IsConditional returns true if the decision carries conditions that must be evaluated
// against request/object data before a final Allow/Deny/NoOpinion can be determined.
func (d ConditionsAwareDecision) IsConditional() bool {
	return len(d.conditionsMaps) != 0
}

// IsUnconditional returns true if the decision is a plain Allow, Deny, or NoOpinion.
func (d ConditionsAwareDecision) IsUnconditional() bool {
	return !d.IsConditional()
}

// ConditionsMaps returns the slice of ConditionsMaps carried by a conditional decision.
// Returns nil for unconditional decisions.
func (d ConditionsAwareDecision) ConditionsMaps() []ConditionsMap {
	return d.conditionsMaps
}

// Fallback returns the unconditional decision that the union authorizer should use when
// all ConditionsMaps evaluate to NoOpinion. Returns NoOpinion if no fallback was set
// (i.e. for decisions returned directly by leaf authorizers).
func (d ConditionsAwareDecision) Fallback() ConditionsAwareDecision {
	if d.fallback == nil {
		return ConditionsAwareDecisionNoOpinion("", nil)
	}
	return *d.fallback
}

// UnconditionalParts converts the decision into the (Decision, string, error) triple
// that Authorizer.Authorize uses. For conditions-unaware callers, conditional decisions
// are failed-closed: Deny if any ConditionsMap contains deny conditions, else NoOpinion.
func (d ConditionsAwareDecision) UnconditionalParts() (Decision, string, error) {
	switch {
	case d.IsAllow():
		return DecisionAllow, d.reason, d.err
	case d.IsDeny():
		return DecisionDeny, d.reason, d.err
	case d.IsNoOpinion():
		return DecisionNoOpinion, d.reason, d.err
	default:
		// Conditional: fail closed without exposing an error (to avoid HTTP 500).
		// Only fail closed to Deny if at least one ConditionsMap contains deny conditions,
		// because the authorizer was trying to block something and we cannot verify that
		// the block does not apply. If all conditions are Allow/NoOpinion, the authorizer
		// was trying to grant conditionally, not deny — return NoOpinion so the next
		// authorizer in the chain can still decide.
		for _, cm := range d.conditionsMaps {
			if cm.FailClosedDecision() == DecisionDeny {
				return DecisionDeny, "failed closed: tried to return conditional decision to conditions-unaware authorizer", nil
			}
		}
		return DecisionNoOpinion, "failed closed: tried to return conditional decision to conditions-unaware authorizer", nil
	}
}

// Reason returns the reason string of the decision. Empty for conditional decisions.
func (d ConditionsAwareDecision) Reason() string {
	return d.reason
}

// Error returns the error of the decision. Nil for conditional decisions.
func (d ConditionsAwareDecision) Error() error {
	return d.err
}

// String returns a human-readable representation.
func (d ConditionsAwareDecision) String() string {
	if d.IsConditional() {
		return fmt.Sprintf("Conditional(maps=%d, fallback=%s)", len(d.conditionsMaps), d.Fallback().String())
	}
	params := []string{}
	if len(d.reason) != 0 {
		params = append(params, fmt.Sprintf("reason=%q", d.reason))
	}
	if d.err != nil {
		params = append(params, fmt.Sprintf("err=%q", d.err.Error()))
	}
	paramsStr := func() string {
		if len(params) == 0 {
			return ""
		}
		return fmt.Sprintf("(%s)", strings.Join(params, ", "))
	}
	if d.IsAllow() {
		return fmt.Sprintf("Allow%s", paramsStr())
	}
	if d.IsNoOpinion() {
		return fmt.Sprintf("NoOpinion%s", paramsStr())
	}
	return fmt.Sprintf("Deny%s", paramsStr())
}

const (
	// MaxConditionsPerMap is the maximum number of conditions allowed in a single ConditionsMap.
	MaxConditionsPerMap = 128

	// MaxConditionExpressionBytes is the maximum byte length of a condition expression
	// returned by Condition.GetCondition().
	MaxConditionExpressionBytes = 10 * 1024

	// MaxConditionDescriptionBytes is the maximum byte length of a condition description
	// returned by Condition.GetDescription().
	MaxConditionDescriptionBytes = 1 * 1024
)

// ConditionsMap holds the conditions returned by a single Named authorizer.
// Conditions are partitioned into three effect buckets:
//   - denyConditions: if any evaluate to true, the overall decision is Deny.
//   - noOpinionConditions: if any evaluate to true (and no deny matched), the decision is NoOpinion.
//   - allowConditions: if any evaluate to true (and no deny/noOpinion matched), the decision is Allow.
//
// The authorizerName field identifies the authorizer that produced this map; the union
// authorizer uses it to route EvaluateConditions calls.
type ConditionsMap struct {
	authorizerName      string
	denyConditions      []Condition
	noOpinionConditions []Condition
	allowConditions     []Condition
}

// AuthorizerName returns the name of the authorizer that produced this map.
// It must match Named.AuthorizerName() on the corresponding authorizer.
func (c ConditionsMap) AuthorizerName() string { return c.authorizerName }

// Length returns the total number of conditions in the map.
func (c ConditionsMap) Length() int {
	return len(c.denyConditions) + len(c.noOpinionConditions) + len(c.allowConditions)
}

// DenyConditions returns an iterator over the deny conditions.
func (c ConditionsMap) DenyConditions() iter.Seq[Condition] {
	return func(yield func(Condition) bool) {
		for _, cond := range c.denyConditions {
			if !yield(cond) {
				return
			}
		}
	}
}

// NoOpinionConditions returns an iterator over the noOpinion conditions.
func (c ConditionsMap) NoOpinionConditions() iter.Seq[Condition] {
	return func(yield func(Condition) bool) {
		for _, cond := range c.noOpinionConditions {
			if !yield(cond) {
				return
			}
		}
	}
}

// AllowConditions returns an iterator over the allow conditions.
func (c ConditionsMap) AllowConditions() iter.Seq[Condition] {
	return func(yield func(Condition) bool) {
		for _, cond := range c.allowConditions {
			if !yield(cond) {
				return
			}
		}
	}
}

// FailClosedDecision returns the conservative decision to use when condition evaluation
// fails unexpectedly. Returns Deny if any deny conditions exist, else NoOpinion.
func (c ConditionsMap) FailClosedDecision() Decision {
	if len(c.denyConditions) > 0 {
		return DecisionDeny
	}
	return DecisionNoOpinion
}

// conditionEvaluationResultType is an enum for ConditionEvaluationResult.
type conditionEvaluationResultType int

const (
	conditionEvaluationResultTypeUnevaluatable conditionEvaluationResultType = iota
	conditionEvaluationResultTypeTrue
	conditionEvaluationResultTypeFalse
	conditionEvaluationResultTypeError
)

// ConditionEvaluationResult is the result of evaluating a single Condition.
// It has four variants: true, false, error, and unevaluatable (the zero value).
type ConditionEvaluationResult struct {
	resultType conditionEvaluationResultType
	err        error
}

// ConditionEvaluationResultBoolean constructs a true or false result.
func ConditionEvaluationResultBoolean(evalResult bool) ConditionEvaluationResult {
	if evalResult {
		return ConditionEvaluationResult{resultType: conditionEvaluationResultTypeTrue}
	}
	return ConditionEvaluationResult{resultType: conditionEvaluationResultTypeFalse}
}

// ConditionEvaluationResultError constructs an error result.
func ConditionEvaluationResultError(err error) ConditionEvaluationResult {
	return ConditionEvaluationResult{resultType: conditionEvaluationResultTypeError, err: err}
}

// ConditionsEvaluationResultUnevaluatable constructs an unevaluatable result (the zero value).
func ConditionsEvaluationResultUnevaluatable() ConditionEvaluationResult {
	return ConditionEvaluationResult{resultType: conditionEvaluationResultTypeUnevaluatable}
}

// IsTrue reports whether evaluation succeeded and the condition is true.
func (r ConditionEvaluationResult) IsTrue() bool {
	return r.resultType == conditionEvaluationResultTypeTrue
}

// IsFalse reports whether evaluation succeeded and the condition is false.
func (r ConditionEvaluationResult) IsFalse() bool {
	return r.resultType == conditionEvaluationResultTypeFalse
}

// IsError reports whether evaluation produced an error.
func (r ConditionEvaluationResult) IsError() bool {
	return r.resultType == conditionEvaluationResultTypeError
}

// Error returns the evaluation error, if any.
func (r ConditionEvaluationResult) Error() error { return r.err }

// IsUnevaluatable reports whether the condition cannot be evaluated in-process.
func (r ConditionEvaluationResult) IsUnevaluatable() bool {
	return r.resultType == conditionEvaluationResultTypeUnevaluatable
}

// Condition is a single predicate within a ConditionsMap. The effect of the condition
// (Deny, NoOpinion, or Allow) is determined by which slice of ConditionsMap it lives in.
type Condition interface {
	// GetID uniquely identifies this condition within the owning authorizer's scope.
	// Validated as a Kubernetes label key. Any domain of the form *.k8s.io or
	// *.kubernetes.io is reserved for Kubernetes use.
	GetID() string

	// GetType describes the type of the condition for cross-process evaluation.
	// Formatted as a Kubernetes label key. Optional.
	GetType() string

	// GetCondition returns a serialized encoding of the condition expression.
	// Used when the condition must be evaluated by a remote endpoint.
	// Optional if the ID alone suffices for in-process evaluation.
	GetCondition() string

	// GetDescription is a human-readable description for error messages. Optional.
	GetDescription() string

	// DeepCopy returns a deep copy of the Condition.
	DeepCopy() Condition

	// Evaluate evaluates the condition in-process. Returns Unevaluatable if the
	// authorizer needs an external evaluator (e.g. after a serialize/deserialize round-trip).
	Evaluate(ctx context.Context, data ConditionsData) ConditionEvaluationResult
}

// GenericCondition is a convenience implementation of Condition. EvaluateFunc may be nil,
// in which case Evaluate returns Unevaluatable.
type GenericCondition struct {
	ID           string
	Condition    string
	Type         string
	Description  string
	EvaluateFunc func(ctx context.Context, data ConditionsData) ConditionEvaluationResult
}

var _ Condition = GenericCondition{}

func (c GenericCondition) GetID() string          { return c.ID }
func (c GenericCondition) GetType() string        { return c.Type }
func (c GenericCondition) GetCondition() string   { return c.Condition }
func (c GenericCondition) GetDescription() string { return c.Description }

func (c GenericCondition) Evaluate(ctx context.Context, data ConditionsData) ConditionEvaluationResult {
	if c.EvaluateFunc == nil {
		return ConditionsEvaluationResultUnevaluatable()
	}
	return c.EvaluateFunc(ctx, data)
}

func (c GenericCondition) DeepCopy() Condition {
	return c // no pointer fields
}

// Evaluate evaluates the ConditionsMap. It calls each condition's own Evaluate first; if
// that returns Unevaluatable and evaluateFunc is non-nil, evaluateFunc is tried as a
// fallback. Conditions that remain unevaluatable after both passes are kept in a refined
// ConditionsMap that is returned as a conditional decision for a subsequent evaluation round.
//
// Priority order: Deny > NoOpinion > Allow.
// An error in a higher-priority bucket shadows results in lower-priority buckets.
func (c ConditionsMap) Evaluate(ctx context.Context, data ConditionsData, evaluateFunc func(context.Context, ConditionsData, Condition) ConditionEvaluationResult) ConditionsAwareDecision {
	evalCond := func(cond Condition) ConditionEvaluationResult {
		return cond.Evaluate(ctx, data)
	}
	if evaluateFunc != nil {
		evalCond = func(cond Condition) ConditionEvaluationResult {
			if r := cond.Evaluate(ctx, data); !r.IsUnevaluatable() {
				return r
			}
			return evaluateFunc(ctx, data, cond)
		}
	}

	// Deny pass
	if len(c.denyConditions) != 0 {
		var denyErrors []error
		var appliedDenyReasons []string
		var unevaluatedDeny []Condition

		for cond := range c.DenyConditions() {
			id := cond.GetID()
			switch r := evalCond(cond); {
			case r.IsUnevaluatable():
				unevaluatedDeny = append(unevaluatedDeny, cond)
			case r.IsError():
				denyErrors = append(denyErrors, fmt.Errorf("condition %q with effect=Deny produced error: %w", id, r.Error()))
			case r.IsTrue():
				reason := fmt.Sprintf("condition %q denied the request", id)
				if desc := cond.GetDescription(); len(desc) != 0 {
					reason += fmt.Sprintf(" with description %q", desc)
				}
				appliedDenyReasons = append(appliedDenyReasons, reason)
				// r.IsFalse(): skip
			}
		}

		if len(appliedDenyReasons) != 0 {
			// Applied deny conditions take precedence over errors.
			return ConditionsAwareDecisionDeny(strings.Join(appliedDenyReasons, ", "), nil)
		}
		if len(denyErrors) != 0 {
			return ConditionsAwareDecisionDeny("one or more conditional evaluation errors occurred", utilerrors.NewAggregate(denyErrors))
		}
		if len(unevaluatedDeny) != 0 {
			// Return a refined map: keep unevaluated deny conditions plus all nop/allow.
			return ConditionsAwareDecisionConditional(
				c.AuthorizerName(),
				unevaluatedDeny,
				deepCopyConditions(c.noOpinionConditions),
				deepCopyConditions(c.allowConditions),
			)
		}
	}

	// NoOpinion pass (all deny evaluated to false)
	if len(c.noOpinionConditions) != 0 {
		var nopErrors []error
		var appliedNopReasons []string
		var unevaluatedNop []Condition

		for cond := range c.NoOpinionConditions() {
			id := cond.GetID()
			switch r := evalCond(cond); {
			case r.IsUnevaluatable():
				unevaluatedNop = append(unevaluatedNop, cond)
			case r.IsError():
				nopErrors = append(nopErrors, fmt.Errorf("condition %q with effect=NoOpinion produced error: %w", id, r.Error()))
			case r.IsTrue():
				reason := fmt.Sprintf("condition %q evaluated to NoOpinion", id)
				if desc := cond.GetDescription(); len(desc) != 0 {
					reason += fmt.Sprintf(" with description %q", desc)
				}
				appliedNopReasons = append(appliedNopReasons, reason)
				// r.IsFalse(): skip
			}
		}

		if len(appliedNopReasons) != 0 {
			return ConditionsAwareDecisionNoOpinion(strings.Join(appliedNopReasons, ", "), nil)
		}
		if len(nopErrors) != 0 {
			return ConditionsAwareDecisionNoOpinion("one or more conditional evaluation errors occurred", utilerrors.NewAggregate(nopErrors))
		}
		if len(unevaluatedNop) != 0 {
			if len(c.allowConditions) == 0 {
				// No allow conditions: outcome is always NoOpinion regardless.
				return ConditionsAwareDecisionNoOpinion("at least one NoOpinion condition matched, or no conditions matched", nil)
			}
			return ConditionsAwareDecisionConditional(
				c.AuthorizerName(),
				nil,
				unevaluatedNop,
				deepCopyConditions(c.allowConditions),
			)
		}
	}

	// Allow pass (all deny and noOpinion evaluated to false)
	if len(c.allowConditions) != 0 {
		var allowErrors []error
		var appliedAllowReasons []string
		var unevaluatedAllow []Condition

		for cond := range c.AllowConditions() {
			id := cond.GetID()
			switch r := evalCond(cond); {
			case r.IsUnevaluatable():
				unevaluatedAllow = append(unevaluatedAllow, cond)
			case r.IsError():
				allowErrors = append(allowErrors, fmt.Errorf("condition %q with effect=Allow produced error: %w", id, r.Error()))
			case r.IsTrue():
				reason := fmt.Sprintf("condition %q allowed the request", id)
				if desc := cond.GetDescription(); len(desc) != 0 {
					reason += fmt.Sprintf(" with description %q", desc)
				}
				appliedAllowReasons = append(appliedAllowReasons, reason)
				// r.IsFalse(): skip
			}
		}

		if len(appliedAllowReasons) != 0 {
			// An error in a sibling allow condition is demoted to a warning.
			return ConditionsAwareDecisionAllow(strings.Join(appliedAllowReasons, ", "), utilerrors.NewAggregate(allowErrors))
		}
		if len(allowErrors) != 0 {
			return ConditionsAwareDecisionNoOpinion("one or more conditional evaluation errors occurred", utilerrors.NewAggregate(allowErrors))
		}
		if len(unevaluatedAllow) != 0 {
			return ConditionsAwareDecisionConditional(c.AuthorizerName(), nil, nil, unevaluatedAllow)
		}
	}

	return ConditionsAwareDecisionNoOpinion("no conditions matched", nil)
}

// validateConditions validates a slice of conditions, writing seen IDs into seenIDs.
// Returns the first validation error encountered.
func validateConditions(seenIDs sets.Set[string], conditions []Condition) error {
	for _, condition := range conditions {
		if isNilValue(condition) {
			return fmt.Errorf("encountered nil condition")
		}
		id := condition.GetID()
		if seenIDs.Has(id) {
			return fmt.Errorf("duplicate condition ID %q", id)
		}
		seenIDs.Insert(id)
		if errs := content.IsLabelKey(id); len(errs) > 0 {
			return fmt.Errorf("invalid condition ID %q: %s", id, strings.Join(errs, "; "))
		}
		if condType := condition.GetType(); len(condType) != 0 {
			if errs := content.IsLabelKey(condType); len(errs) > 0 {
				return fmt.Errorf("invalid condition type %q: %s", condType, strings.Join(errs, "; "))
			}
		}
		if expr := condition.GetCondition(); len(expr) > MaxConditionExpressionBytes {
			return fmt.Errorf("condition %q expression exceeds maximum length of %d bytes (got %d)", id, MaxConditionExpressionBytes, len(expr))
		}
		if desc := condition.GetDescription(); len(desc) > MaxConditionDescriptionBytes {
			return fmt.Errorf("condition %q description exceeds maximum length of %d bytes (got %d)", id, MaxConditionDescriptionBytes, len(desc))
		}
	}
	return nil
}

func isNilValue(i interface{}) bool {
	if i == nil {
		return true
	}
	v := reflect.ValueOf(i)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Map,
		reflect.Pointer, reflect.UnsafePointer,
		reflect.Interface, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func deepCopyConditions(originals []Condition) []Condition {
	if len(originals) == 0 {
		return nil
	}
	copied := make([]Condition, len(originals))
	for i, c := range originals {
		copied[i] = c.DeepCopy()
	}
	return copied
}

// AdmissionOperation represents the operation type during admission control
// (e.g. CREATE, UPDATE, DELETE). The constants are defined in k8s.io/apiserver/pkg/admission,
// but the type is defined here to avoid import cycles.
type AdmissionOperation string

// ConditionsData holds data available during admission that conditions can evaluate against.
type ConditionsData struct {
	// AdmissionControl holds the data available during the admission phase.
	// Callers must check that this is non-nil before use.
	AdmissionControl ConditionsDataAdmissionControl
}

// ConditionsDataAdmissionControl is a subset of admission.Attributes that conditions
// may evaluate. It mirrors the admission.Attributes interface but is defined here to
// avoid an import cycle with the admission package.
type ConditionsDataAdmissionControl interface {
	GetName() string
	GetNamespace() string
	GetResource() schema.GroupVersionResource
	GetSubresource() string
	GetOperation() AdmissionOperation
	GetOperationOptions() runtime.Object
	IsDryRun() bool
	GetObject() runtime.Object
	GetOldObject() runtime.Object
	GetKind() schema.GroupVersionKind
	GetUserInfo() user.Info
}
