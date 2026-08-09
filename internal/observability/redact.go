package observability

import (
	"strings"

	"go.uber.org/zap/zapcore"
)

// sensitiveKeys are field keys whose values must never be emitted verbatim.
// The list matches the bootstrap redaction baseline: credentials, tokens, and
// meeting secrets. Domain code must reuse this core rather than logging raw
// values.
var sensitiveKeys = map[string]struct{}{
	"password":         {},
	"meeting_password": {},
	"authorization":    {},
	"token":            {},
	"access_token":     {},
	"refresh_token":    {},
	"livekit_token":    {},
	"link_token":       {},
	"pass_token":       {},
	"secret":           {},
	"dsn":              {},
}

const redacted = "[REDACTED]"

// RedactingCore wraps a zapcore.Core and masks the values of sensitive fields
// before they are written. It is defensive by design: the value is replaced,
// never truncated, so no prefix of a secret leaks.
type RedactingCore struct {
	zapcore.Core
}

// NewRedactingCore wraps the given core with redaction.
func NewRedactingCore(c zapcore.Core) *RedactingCore { return &RedactingCore{Core: c} }

// With redacts fields attached to the logger via With().
func (c *RedactingCore) With(fields []zapcore.Field) zapcore.Core {
	return &RedactingCore{Core: c.Core.With(redactFields(fields))}
}

// Check preserves the wrapper in the log entry chain.
func (c *RedactingCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}
	return ce
}

// Write redacts per-entry fields before delegating to the wrapped core.
func (c *RedactingCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	return c.Core.Write(ent, redactFields(fields))
}

// IsSensitiveKey reports whether a field key is treated as sensitive. Exported
// so domain code and tests can assert on the baseline.
func IsSensitiveKey(key string) bool {
	_, ok := sensitiveKeys[strings.ToLower(key)]
	return ok
}

func redactFields(fields []zapcore.Field) []zapcore.Field {
	out := make([]zapcore.Field, len(fields))
	for i, f := range fields {
		if IsSensitiveKey(f.Key) {
			out[i] = zapcore.Field{Key: f.Key, Type: zapcore.StringType, String: redacted}
			continue
		}
		out[i] = f
	}
	return out
}
