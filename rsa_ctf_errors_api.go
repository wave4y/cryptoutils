package cryptoutils

import "github.com/wave4y/cryptoutils/rsactf"

// RSACTFNoResultError reports the operation and reason for a result matching
// ErrRSACTFNoResult. Use errors.As to inspect it. Op uses the rsactf function
// name without Context, including when called through the root package.
type RSACTFNoResultError = rsactf.NoResultError

// RSACTFNoResultReason identifies why a valid RSA math/CTF operation had no result.
type RSACTFNoResultReason = rsactf.NoResultReason

const (
	// RSACTFReasonBudgetExhausted indicates a caller-supplied search limit.
	RSACTFReasonBudgetExhausted = rsactf.ReasonBudgetExhausted
	// RSACTFReasonSearchExhausted indicates the method finished its candidate sequence.
	RSACTFReasonSearchExhausted = rsactf.ReasonSearchExhausted
	// RSACTFReasonConditionsNotMet indicates unmet mathematical recovery conditions
	// or a candidate that failed verification.
	RSACTFReasonConditionsNotMet = rsactf.ReasonConditionsNotMet
	// RSACTFReasonNotInvertible indicates a required modular inverse does not exist.
	RSACTFReasonNotInvertible = rsactf.ReasonNotInvertible
)
