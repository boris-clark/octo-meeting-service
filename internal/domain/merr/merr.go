// Package merr defines the meeting service's stable error taxonomy in Go. The
// codes, HTTP statuses, and envelope here are the runtime counterpart of the
// authoritative snapshot at contracts/snapshots/r4-go-f0f482c0/errors.yaml.
//
// Implementations MUST NOT add, rename, or abbreviate codes: the catalog is
// reconciled against the snapshot by a contract test so the two never drift.
package merr

import (
	"fmt"
	"net/http"
)

// Code is a stable machine-readable error code from the frozen taxonomy.
type Code string

// The frozen MEETING_* error codes (architecture §7.3 / backend appendix §5.2).
const (
	AuthRequired          Code = "MEETING_AUTH_REQUIRED"
	CredentialInvalid     Code = "MEETING_CREDENTIAL_INVALID"
	Ended                 Code = "MEETING_ENDED"
	Cancelled             Code = "MEETING_CANCELLED"
	TooEarly              Code = "MEETING_TOO_EARLY"
	Locked                Code = "MEETING_LOCKED"
	Full                  Code = "MEETING_FULL"
	Removed               Code = "MEETING_REMOVED"
	NotSameSpace          Code = "MEETING_NOT_SAME_SPACE"
	PasswordRequired      Code = "MEETING_PASSWORD_REQUIRED"
	PasswordFormatInvalid Code = "MEETING_PASSWORD_FORMAT_INVALID"
	PasswordInvalid       Code = "MEETING_PASSWORD_INVALID"
	PasswordCooldown      Code = "MEETING_PASSWORD_COOLDOWN"
	PasswordPassExpired   Code = "MEETING_PASSWORD_PASS_EXPIRED"
	PasswordImmutable     Code = "MEETING_PASSWORD_IMMUTABLE"
	Forbidden             Code = "MEETING_FORBIDDEN"
	VersionConflict       Code = "MEETING_VERSION_CONFLICT"
	IdempotencyConflict   Code = "MEETING_IDEMPOTENCY_CONFLICT"
	ShareConflict         Code = "MEETING_SHARE_CONFLICT"
	LiveKitUnavailable    Code = "MEETING_LIVEKIT_UNAVAILABLE"
	NotificationDeferred  Code = "MEETING_NOTIFICATION_DEFERRED"
	TimeInvalid           Code = "MEETING_TIME_INVALID"
	RateLimited           Code = "MEETING_RATE_LIMITED"
	Internal              Code = "MEETING_INTERNAL"
)

// catalog maps every code to its HTTP status. It is the single Go source; the
// contract test asserts parity with errors.yaml in both directions.
var catalog = map[Code]int{
	AuthRequired:          http.StatusUnauthorized,         // 401
	CredentialInvalid:     http.StatusNotFound,             // 404
	Ended:                 http.StatusGone,                 // 410
	Cancelled:             http.StatusGone,                 // 410
	TooEarly:              http.StatusConflict,             // 409
	Locked:                http.StatusLocked,               // 423
	Full:                  http.StatusConflict,             // 409
	Removed:               http.StatusForbidden,            // 403
	NotSameSpace:          http.StatusForbidden,            // 403
	PasswordRequired:      http.StatusPreconditionRequired, // 428
	PasswordFormatInvalid: http.StatusUnprocessableEntity,  // 422
	PasswordInvalid:       http.StatusUnauthorized,         // 401
	PasswordCooldown:      http.StatusTooManyRequests,      // 429
	PasswordPassExpired:   http.StatusUnauthorized,         // 401
	PasswordImmutable:     http.StatusConflict,             // 409
	Forbidden:             http.StatusForbidden,            // 403
	VersionConflict:       http.StatusConflict,             // 409
	IdempotencyConflict:   http.StatusConflict,             // 409
	ShareConflict:         http.StatusConflict,             // 409
	LiveKitUnavailable:    http.StatusServiceUnavailable,   // 503
	NotificationDeferred:  http.StatusAccepted,             // 202
	TimeInvalid:           http.StatusUnprocessableEntity,  // 422
	RateLimited:           http.StatusTooManyRequests,      // 429
	Internal:              http.StatusInternalServerError,  // 500
}

// HTTPStatus returns the HTTP status for a code, or 500 for an unknown code.
func HTTPStatus(c Code) int {
	if s, ok := catalog[c]; ok {
		return s
	}
	return http.StatusInternalServerError
}

// Known reports whether the code is part of the frozen taxonomy.
func Known(c Code) bool {
	_, ok := catalog[c]
	return ok
}

// Codes returns every code in the catalog (unordered).
func Codes() []Code {
	out := make([]Code, 0, len(catalog))
	for c := range catalog {
		out = append(out, c)
	}
	return out
}

// Error is the wire error. It serializes to the frozen snake_case envelope
// { code, message, details, request_id }. Details must only ever carry the safe
// keys documented per code in errors.yaml — never a secret.
type Error struct {
	Code      Code           `json:"code"`
	Message   string         `json:"message"`
	Details   map[string]any `json:"details,omitempty"`
	RequestID string         `json:"request_id,omitempty"`
}

// Error implements the error interface.
func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// HTTPStatus returns the HTTP status mapped to this error's code.
func (e *Error) HTTPStatus() int { return HTTPStatus(e.Code) }

// New builds an Error with a code and message.
func New(code Code, message string) *Error {
	return &Error{Code: code, Message: message}
}

// WithDetail returns a copy of the error with a single safe detail key set.
func (e *Error) WithDetail(key string, value any) *Error {
	details := make(map[string]any, len(e.Details)+1)
	for k, v := range e.Details {
		details[k] = v
	}
	details[key] = value
	return &Error{Code: e.Code, Message: e.Message, Details: details, RequestID: e.RequestID}
}
