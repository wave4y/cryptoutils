package rsactf

import "errors"

var (
	// ErrInvalidInput indicates missing parameters or violated input conditions.
	ErrInvalidInput = errors.New("cryptoutils/rsactf: invalid input")
	// ErrNoResult indicates no result under the method's conditions or search budget.
	// Use errors.Is to match it and errors.As to inspect a *NoResultError.
	// It does not prove that a modulus is secure or a problem has no solution.
	ErrNoResult = errors.New("cryptoutils/rsactf: no result")
)

// NoResultReason identifies why a valid operation produced no result.
type NoResultReason string

const (
	// ReasonBudgetExhausted means a caller-supplied search limit stopped the
	// operation. Increasing the budget may help, but does not guarantee success.
	ReasonBudgetExhausted NoResultReason = "budget_exhausted"
	// ReasonSearchExhausted means this method finished its candidate sequence.
	// Increasing its iteration budget alone cannot add candidates. This says
	// nothing about other methods or, for Pollard p-1, a different smoothness bound.
	ReasonSearchExhausted NoResultReason = "search_exhausted"
	// ReasonConditionsNotMet means the method's mathematical recovery conditions
	// were not met, or its recovered candidate failed verification. This does
	// not assert that the underlying problem has no solution.
	ReasonConditionsNotMet NoResultReason = "conditions_not_met"
	// ReasonNotInvertible means a required modular inverse does not exist.
	ReasonNotInvertible NoResultReason = "not_invertible"
)

// NoResultError reports a valid operation that produced no result. All public
// operations returning an error matching ErrNoResult return this type.
// Invalid inputs and context cancellation retain their separate error contracts.
// Use errors.As to inspect it; use errors.Is(err, ErrNoResult), not ==, to match
// the category. Root-package aliases expose the same type and sentinel.
type NoResultError struct {
	// Op is the subpackage function name, without the Context suffix, even
	// when the operation was called through the root-package wrapper.
	Op     string
	Reason NoResultReason
}

func (e *NoResultError) Error() string {
	return ErrNoResult.Error() + ": " + e.Op + ": " + string(e.Reason)
}

// Unwrap preserves errors.Is compatibility with ErrNoResult.
func (e *NoResultError) Unwrap() error { return ErrNoResult }

func noResult(op string, reason NoResultReason) error {
	return &NoResultError{Op: op, Reason: reason}
}
